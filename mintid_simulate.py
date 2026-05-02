#!/usr/bin/env python3
"""
mintid_simulate.py — bytecode-faithful reproduction of MintID's first-scan flow,
with local SQLite oracle that logs every chip read and every server interaction.

Verified BYTE-FOR-BYTE against the actual Java code (ProductRequestBody from
the APK + Jackson 2.14 ObjectMapper) via the Java harness. Both the Python
simulator and the Java harness produce identical 208-byte request bodies
(or 206 bytes when TagCrypto is the lowercase variant).

Reads the coin via the ACR1552U using the FF B0 storage-card command path,
parses the NDEF Text record exactly the way the app does, builds the same
JSON body and headers the app builds, and POSTs to the MintID API. By default
emits two POSTs in succession to mirror the observed app behavior on a first
scan (one from MainActivity1.onNewIntent, one from the result activity's
onNewIntent that fires because the tag is still in the field when the result
screen launches).

Every scan -- chip dump, request bytes, response bytes, parsed product info
-- is logged to a local SQLite oracle DB (mintid_oracle.db by default). The
oracle reports BEFORE each server query whether we've seen this UID before
and whether the chip content matches our prior reads, and AFTER each query
whether the server's response has changed since we last saw this coin.

  com.droisys.mintid.util.HelperTagReader.startMainActivityAndPassTag
  com.droisys.mintid.util.HelperTagReader.startMainActivityAndPassTagGenuin
  com.droisys.mintid.util.HelperTagReader.buildNFCTag
  com.droisys.mintid.util.HelperTagReader.buildNFCTagGenuin
  com.droisys.mintid.util.HelperTagReader.getProductInfo
  com.droisys.mintid.util.HelperTagReader.getProductInfoGenuin
  com.droisys.mintid.util.HelperTagReader$1.intercept    (Genuin guest path)
  com.droisys.mintid.util.HelperTagReader$4.intercept    (regular guest path)
  com.droisys.mintid.MainActivity1.parse(NdefMessage)
  com.droisys.mintid.MainActivity1.parse(NdefRecord)
  com.droisys.mintid.MainActivity1.getRecords(NdefRecord[])
  com.droisys.mintid.MainActivity1.isText(NdefRecord)
  com.droisys.mintid.ResponseBody.ProductRequestBody.<init>
  com.droisys.mintid.Constants                          (BaseUrl literal)
  com.droisys.mintid.util.WebApis.getProductDetailWithCrypto

Endpoint resolved:
  POST http://mintidapi.droisys.info/api/ProductAuthentication/SecuredScanProduct

Hardware: ACS ACR1552U on macOS or Linux PC/SC.
Python: stdlib only (sqlite3 included).
"""
import argparse
import ctypes
import ctypes.util
import json
import os
import sys
import urllib.error
import urllib.request
from collections import OrderedDict
from ctypes import (
    POINTER,
    Structure,
    byref,
    c_char_p,
    c_uint32,
    c_void_p,
    create_string_buffer,
)

# Local oracle module. Expects mintid_oracle.py in the same directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mintid_oracle import (
    Oracle,
    format_pre_scan_report,
    format_post_scan_report,
)
from mintid_chip_summary import (
    build_chip_summary,
    format_chip_summary,
)


# ---------------------------------------------------------------------------
# PC/SC binding via ctypes (no pyscard, no pcscd config required on macOS)
# ---------------------------------------------------------------------------

if sys.platform == "darwin":
    PCSC_LIBRARY_PATH = "/System/Library/Frameworks/PCSC.framework/PCSC"
else:
    PCSC_LIBRARY_PATH = (
        ctypes.util.find_library("pcsclite") or "libpcsclite.so.1"
    )

pcsc = ctypes.CDLL(PCSC_LIBRARY_PATH)


class SCardIoRequest(Structure):
    _fields_ = [
        ("dwProtocol", c_uint32),
        ("cbPciLength", c_uint32),
    ]


pcsc.SCardEstablishContext.argtypes = [
    c_uint32,
    c_void_p,
    c_void_p,
    POINTER(c_void_p),
]
pcsc.SCardListReaders.argtypes = [
    c_void_p,
    c_char_p,
    c_char_p,
    POINTER(c_uint32),
]
pcsc.SCardConnect.argtypes = [
    c_void_p,
    c_char_p,
    c_uint32,
    c_uint32,
    POINTER(c_void_p),
    POINTER(c_uint32),
]
pcsc.SCardTransmit.argtypes = [
    c_void_p,
    POINTER(SCardIoRequest),
    c_char_p,
    c_uint32,
    POINTER(SCardIoRequest),
    c_char_p,
    POINTER(c_uint32),
]
pcsc.SCardDisconnect.argtypes = [c_void_p, c_uint32]
pcsc.SCardReleaseContext.argtypes = [c_void_p]


SCARD_S_SUCCESS = 0x00000000
SCARD_SCOPE_USER = 0x0000
SCARD_SHARE_SHARED = 0x0002
SCARD_PROTOCOL_T0 = 0x0001
SCARD_PROTOCOL_T1 = 0x0002
SCARD_PROTOCOL_ANY = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1
SCARD_LEAVE_CARD = 0x0000


# ---------------------------------------------------------------------------
# Reader interaction
# ---------------------------------------------------------------------------


def list_readers(ctx):
    """Return the list of currently visible PC/SC reader names."""
    needed = c_uint32(0)
    rv = pcsc.SCardListReaders(ctx, None, None, byref(needed))
    if rv != SCARD_S_SUCCESS:
        raise RuntimeError(
            "SCardListReaders(size) failed: 0x%08X" % (rv & 0xFFFFFFFF)
        )
    buf = create_string_buffer(needed.value)
    rv = pcsc.SCardListReaders(ctx, None, buf, byref(needed))
    if rv != SCARD_S_SUCCESS:
        raise RuntimeError(
            "SCardListReaders failed: 0x%08X" % (rv & 0xFFFFFFFF)
        )
    return [
        s.decode("utf-8")
        for s in buf.raw[: needed.value].split(b"\x00")
        if s
    ]


def pick_reader(reader_names):
    """Prefer the ACR1552U's PICC slot, fall back to the first available."""
    for name in reader_names:
        if "PICC" in name and "1552" in name:
            return name
    if not reader_names:
        raise RuntimeError(
            "No PC/SC readers visible. Plug in the ACR1552U."
        )
    return reader_names[0]


def transmit(handle, io_request, apdu_bytes):
    """Send a single APDU and return (data_bytes, sw1, sw2)."""
    send_buffer = bytes(apdu_bytes)
    recv_buffer = create_string_buffer(2048)
    recv_length = c_uint32(2048)
    rv = pcsc.SCardTransmit(
        handle,
        byref(io_request),
        send_buffer,
        len(send_buffer),
        None,
        recv_buffer,
        byref(recv_length),
    )
    if rv != SCARD_S_SUCCESS:
        return None, 0, 0
    data = recv_buffer.raw[: recv_length.value]
    if len(data) < 2:
        return data, 0, 0
    return data[:-2], data[-2], data[-1]


def read_chip(active_chip_summary=False, deeper_probes=False,
              run_writability=False):
    """
    Read the chip in the field via PC/SC storage-card pseudo-APDUs.

    Returns:
        (uid_bytes, pages_bytes, active_summary_dict_or_None,
         deeper_probes_dict_or_None)

    If active_chip_summary is True, also attempts NXP-specific commands
    (GET_VERSION, READ_SIG, READ_CNT) while the card is still in the
    field. These commands often fail on macOS because the framework
    treats these chips as 'storage cards' but we record the attempts
    regardless.

    If deeper_probes is True, ALSO runs the read-only chip-interrogation
    probes (FAST_READ, PWD_AUTH, hidden pages, magic-clone fingerprints)
    while the chip is still in the field. The connection is held open
    across all probes so we don't have to ask the user to re-tap.

    If run_writability is True (and deeper_probes is True), also runs the
    non-destructive writability test (writes the chip's existing bytes
    back to itself, observes ACK/NAK). Each invocation consumes an EEPROM
    write cycle on writable chips, so it's opt-in.
    """
    ctx = c_void_p()
    rv = pcsc.SCardEstablishContext(
        SCARD_SCOPE_USER, None, None, byref(ctx)
    )
    if rv != SCARD_S_SUCCESS:
        raise RuntimeError(
            "SCardEstablishContext failed: 0x%08X" % (rv & 0xFFFFFFFF)
        )

    try:
        readers = list_readers(ctx)
        target = pick_reader(readers)
        print("[reader] " + target)

        handle = c_void_p()
        protocol = c_uint32(0)
        rv = pcsc.SCardConnect(
            ctx,
            target.encode("utf-8"),
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_ANY,
            byref(handle),
            byref(protocol),
        )
        if rv != SCARD_S_SUCCESS:
            raise RuntimeError(
                "SCardConnect failed: 0x%08X (is a tag in the field?)"
                % (rv & 0xFFFFFFFF)
            )

        io_request = SCardIoRequest(
            protocol.value, ctypes.sizeof(SCardIoRequest)
        )

        try:
            uid_data, sw1, sw2 = transmit(
                handle, io_request, [0xFF, 0xCA, 0x00, 0x00, 0x00]
            )
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError(
                    "UID query failed: SW=%02X%02X" % (sw1, sw2)
                )
            uid_bytes = bytes(uid_data)
            print(
                "[chip ] UID = %s (%d bytes)"
                % (uid_bytes.hex().upper(), len(uid_bytes))
            )

            # Read pages 0..63 in 16-byte (4-page) chunks via the
            # storage-card READ pseudo-APDU. We attempt up to page 63
            # because:
            #   * NTAG 213 physically has pages 0..44 (180 bytes total)
            #   * NTAG 215 has pages 0..134
            #   * Some clones expose 256 bytes (pages 0..63)
            # The CC byte 2 only describes the NDEF-advertised area. The
            # chip's PHYSICAL storage often extends beyond it (config
            # pages, dynamic lock bytes, factory residue). We read past
            # the advertised limit and let the chip NAK when it runs out
            # of physical storage. This gives us:
            #   * For NTAG 213: ~45 successful page reads (180 bytes)
            #   * For NTAG 215: 64 successful (256 bytes - we cap there)
            #   * For 256-byte clones: 64 successful (256 bytes)
            pages = bytearray()
            last_ok_page = -1
            for page_index in range(0, 64, 4):
                data, sw1, sw2 = transmit(
                    handle,
                    io_request,
                    [0xFF, 0xB0, 0x00, page_index, 0x10],
                )
                if (sw1, sw2) != (0x90, 0x00) or not data:
                    break
                pages.extend(data)
                last_ok_page = page_index + 3
            print(
                "[chip ] read %d bytes across pages 0..%d"
                % (len(pages), last_ok_page)
            )

            def transmit_via_handle(apdu_bytes):
                return transmit(handle, io_request, apdu_bytes)

            active_summary = None
            if active_chip_summary:
                from mintid_chip_summary import attempt_active_commands
                active_summary = attempt_active_commands(transmit_via_handle)

            deeper_results = None
            if deeper_probes:
                try:
                    from mintid_chip_interrogate import run_field_probes
                except ImportError:
                    print("")
                    print("[note] --deeper-probes requested but "
                          "mintid_chip_interrogate not on PYTHONPATH.")
                    print("       Add archive/ to PYTHONPATH if you need it:")
                    print("       PYTHONPATH=archive python3 "
                          "mintid_simulate.py ...")
                    run_field_probes = None
                if run_field_probes:
                    print("")
                    print("=== Running deeper field probes ===")
                    deeper_results = run_field_probes(
                        transmit_via_handle,
                        uid_bytes,
                        bytes(pages),
                        run_writability=run_writability,
                        verbose=True,
                    )

            return uid_bytes, bytes(pages), active_summary, deeper_results
        finally:
            pcsc.SCardDisconnect(handle, SCARD_LEAVE_CARD)
    finally:
        pcsc.SCardReleaseContext(ctx)


# ---------------------------------------------------------------------------
# NDEF parsing — exactly mirroring com.droisys.mintid.MainActivity1.parse
# ---------------------------------------------------------------------------


def is_well_known_text_record(tnf, type_field):
    """
    com.droisys.mintid.MainActivity1.isText(NdefRecord) returns true when
    TNF is WELL_KNOWN (1) and TYPE is the 'T' RTD.
    """
    return tnf == 0x01 and type_field == b"T"


def parse_ndef_text_like_app(pages_bytes):
    """
    Reproduce com.droisys.mintid.MainActivity1.parse(NdefMessage) ->
    getRecords(NdefRecord[]) -> parse(NdefRecord) for the case of a single
    Text record on a Type 2 NFC Forum tag.

    Scans the first 32 bytes of the pages buffer for the NDEF Message TLV
    (tag byte 0x03), then parses the message and returns the trimmed text
    payload (language code stripped, decoded as UTF-8 or UTF-16 per the
    status byte high bit). Returns None if no Text record is present.
    """
    if len(pages_bytes) < 16:
        return None

    tlv_start_index = -1
    search_window = pages_bytes[: min(32, len(pages_bytes))]
    for i in range(len(search_window) - 1):
        if search_window[i] == 0x03:
            tlv_start_index = i
            break
    if tlv_start_index < 0:
        return None

    body = pages_bytes[tlv_start_index:]
    if len(body) < 2:
        return None

    msg_length_field = body[1]
    if msg_length_field == 0xFF:
        if len(body) < 4:
            return None
        msg_length = (body[2] << 8) | body[3]
        ndef_message = body[4 : 4 + msg_length]
    else:
        msg_length = msg_length_field
        ndef_message = body[2 : 2 + msg_length]

    if len(ndef_message) < 4:
        return None

    record_header = ndef_message[0]
    record_tnf = record_header & 0x07
    record_type_length = ndef_message[1]
    record_payload_length = ndef_message[2]

    type_start = 3
    type_end = type_start + record_type_length
    payload_start = type_end
    payload_end = payload_start + record_payload_length

    record_type = ndef_message[type_start:type_end]
    record_payload = ndef_message[payload_start:payload_end]

    if not is_well_known_text_record(record_tnf, record_type):
        return None

    if not record_payload:
        return None

    status_byte = record_payload[0]
    is_utf16 = bool(status_byte & 0x80)
    language_code_length = status_byte & 0x3F

    text_bytes = record_payload[1 + language_code_length :]
    encoding = "utf-16" if is_utf16 else "utf-8"
    decoded_text = text_bytes.decode(encoding, errors="replace")

    # buildNFCTag calls .trim() on the parsed text before passing it on.
    return decoded_text.strip()


# ---------------------------------------------------------------------------
# Request body and headers — exactly matching the bytecode + Jackson output
# ---------------------------------------------------------------------------


def build_request_body(
    uid_bytes, msg_payload, device_id, latitude, longitude
):
    """
    Build the Python equivalent of what Jackson produces when serializing
    com.droisys.mintid.ResponseBody.ProductRequestBody.

    KEY POINT: the JSON field order is the FIELD DECLARATION order in the
    .class file:
        DeviceID, DeviceType, Lat, Lon, TagCrypto, TagProvider, TagType,
        TagUID, TagValue
    NOT the constructor parameter order. Jackson reads field declaration
    order via reflection because each field has a @JsonProperty annotation.

    Constants set in the call site of getProductInfo:
        DeviceType  = "Android"
        TagProvider = "Identiv"
        TagType     = "NFC Tags"
        TagValue    = "1234567812345678"
    DeviceID is read from UtilPrefrences.getKeyDeviceId() (empty string by
    default on a fresh install).
    Lat/Lon come from GPSTracker (0.0 when location is denied/unknown).
    TagUID is the chip UID rendered as Android NdefRecord.toString() does
    -- which uses "%02X" (UPPERCASE hex, no separators) per AOSP source.
    TagCrypto is the trimmed Text-record content from the chip.
    """
    tag_uid_string = uid_bytes.hex().upper()  # AOSP NdefRecord.toString uses %02X

    body = OrderedDict()
    body["DeviceID"] = device_id
    body["DeviceType"] = "Android"
    body["Lat"] = latitude
    body["Lon"] = longitude
    body["TagCrypto"] = msg_payload
    body["TagProvider"] = "Identiv"
    body["TagType"] = "NFC Tags"
    body["TagUID"] = tag_uid_string
    body["TagValue"] = "1234567812345678"
    return body


def serialize_body_jackson_compatible(body):
    """
    Serialize like Jackson's default ObjectMapper: compact, no whitespace.
    Python's json.dumps default uses (", ", ": ") separators which add
    spaces. Jackson uses (",", ":") with no spaces. Match Jackson.
    """
    return json.dumps(body, separators=(",", ":"))


def build_request_headers():
    """
    Mirror com.droisys.mintid.util.HelperTagReader$4.intercept (guest path).

    The interceptor sets exactly three headers in this order:
        OrgAccessID
        AuthorizationKey
        Content-Type
    Content-Type is plain "application/json" with no charset suffix.
    User-Agent is added by OkHttp itself; we include a reasonable default.
    """
    headers = OrderedDict()
    headers["OrgAccessID"] = "000000000000000000000000"
    headers["AuthorizationKey"] = "2I0mGELp"
    headers["Content-Type"] = "application/json"
    headers["User-Agent"] = "okhttp/3.14.9"
    return headers


# ---------------------------------------------------------------------------
# HTTP send + oracle integration
# ---------------------------------------------------------------------------


def send_request(
    endpoint_base,
    body,
    headers,
    dry_run,
    label,
    oracle,
    chip_uid_bytes,
    chip_pages_bytes,
    chip_ndef_text,
):
    """
    POST the body to SecuredScanProduct, log everything to the oracle,
    and report what's changed since the last time we saw this coin.
    """
    base = endpoint_base.rstrip("/")
    if not base.endswith("/api"):
        base = base + "/api"
    url = base + "/ProductAuthentication/SecuredScanProduct"

    body_string = serialize_body_jackson_compatible(body)
    body_bytes = body_string.encode("utf-8")

    chip_uid_uppercase = chip_uid_bytes.hex().upper()

    # Pre-scan oracle report (what do we already know about this UID?).
    if oracle is not None:
        lookup = oracle.lookup_chip(chip_uid_uppercase, chip_ndef_text)
        print("")
        print(format_pre_scan_report(
            chip_uid_uppercase, chip_ndef_text, lookup
        ))

        # Open the scan record now so the chip-side data is preserved
        # even if the request fails.
        scan_id = oracle.begin_scan(
            chip_uid_bytes, chip_pages_bytes, chip_ndef_text
        )
        oracle.record_request(scan_id, url, headers, body_string)
    else:
        scan_id = None

    print("")
    print("========== " + label + " ==========")
    print("POST " + url)
    for header_name, header_value in headers.items():
        print("  " + header_name + ": " + header_value)
    print("  Content-Length: " + str(len(body_bytes)))
    print("")
    print(body_string)
    print("=" * (len(label) + 22))

    if dry_run:
        print("")
        print("[dry-run; not sending]")
        if oracle is not None and scan_id is not None:
            oracle.annotate(scan_id, "dry-run; request not sent")
        return

    request = urllib.request.Request(
        url, data=body_bytes, headers=dict(headers), method="POST"
    )
    response_status = None
    response_headers = None
    response_body_string = None
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response_status = response.status
            response_headers = OrderedDict(response.headers.items())
            response_bytes = response.read()
            response_body_string = response_bytes.decode(
                "utf-8", errors="replace"
            )

            print("")
            print("---------- Response ----------")
            print("HTTP " + str(response_status))
            for header_name, header_value in response_headers.items():
                print("  " + header_name + ": " + header_value)
            print("")
            try:
                parsed = json.loads(response_body_string)
                print(json.dumps(parsed, indent=2))
            except Exception:
                print(repr(response_body_string))
            print("------------------------------")
    except urllib.error.HTTPError as http_error:
        response_status = http_error.code
        response_headers = OrderedDict(http_error.headers.items())
        error_bytes = http_error.read()
        response_body_string = error_bytes.decode("utf-8", errors="replace")

        print("")
        print("---------- HTTP " + str(http_error.code) + " ----------")
        for header_name, header_value in response_headers.items():
            print("  " + header_name + ": " + header_value)
        try:
            parsed = json.loads(response_body_string)
            print(json.dumps(parsed, indent=2))
        except Exception:
            print(repr(response_body_string))

    # Record the response and produce the post-scan diff report.
    if oracle is not None and scan_id is not None and response_body_string is not None:
        diff_summary = oracle.record_response(
            scan_id,
            chip_uid_uppercase,
            response_status,
            response_headers,
            response_body_string,
        )
        catalog_summary = oracle.get_catalog_summary()
        print("")
        print(format_post_scan_report(
            diff_summary, catalog_summary=catalog_summary
        ))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Bytecode-faithful MintID first-scan simulator with "
                    "local SQLite oracle."
    )
    parser.add_argument(
        "--endpoint",
        default="http://mintidapi.droisys.info",
        help=(
            "Base URL for the MintID API. Default is the production endpoint "
            "from Constants.BaseUrl."
        ),
    )
    parser.add_argument(
        "--device-id",
        default="",
        help=(
            "Mirrors UtilPrefrences.getKeyDeviceId(). The default empty "
            "string matches a fresh install before any login that would "
            "have written this preference."
        ),
    )
    parser.add_argument(
        "--lat",
        type=float,
        default=0.0,
        help="GPS latitude. Default 0.0 mirrors GPSTracker without permission.",
    )
    parser.add_argument(
        "--lon",
        type=float,
        default=0.0,
        help="GPS longitude. Default 0.0 mirrors GPSTracker without permission.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the request(s) but do not actually send.",
    )
    parser.add_argument(
        "--single-scan",
        action="store_true",
        help=(
            "Send only POST #1 (MainActivity1 path). By default, also send "
            "POST #2 (result-activity path) to mirror the observed app "
            "behavior of two POSTs on a first scan."
        ),
    )
    parser.add_argument(
        "--db",
        default="mintid_oracle.db",
        help="Path to the SQLite oracle database. Created if missing.",
    )
    parser.add_argument(
        "--no-oracle",
        action="store_true",
        help="Skip oracle logging entirely (useful for one-off sends).",
    )
    parser.add_argument(
        "--no-chip-summary",
        action="store_true",
        help="Don't print the chip summary to stdout (still saves to DB).",
    )
    parser.add_argument(
        "--skip-active-commands",
        action="store_true",
        help="Skip the NXP-specific commands (GET_VERSION, READ_SIG, "
             "READ_CNT) that the simulator otherwise attempts on every "
             "scan. The active commands are cheap and recorded even when "
             "they fail, so there's rarely a reason to skip them.",
    )
    parser.add_argument(
        "--chip-active-commands",
        action="store_true",
        help=argparse.SUPPRESS,  # deprecated, now the default; kept for "
                                 # back-compat with old scripts.
    )
    parser.add_argument(
        "--skip-deeper-probes",
        action="store_true",
        help="Skip the read-only chip-interrogation probes (FAST_READ, "
             "PWD_AUTH, hidden pages, magic-clone fingerprints). They run "
             "while the chip is still on the reader by default.",
    )
    parser.add_argument(
        "--run-writability-test",
        action="store_true",
        help="Also run the non-destructive writability test (writes the "
             "chip's existing bytes back to itself, observes ACK/NAK). "
             "Off by default because each invocation consumes an EEPROM "
             "write cycle on writable chips.",
    )
    arguments = parser.parse_args()

    oracle = None
    if not arguments.no_oracle:
        oracle = Oracle(arguments.db)
        print("[oracle] using " + os.path.abspath(arguments.db))

    try:
        uid_bytes, pages_bytes, active_summary, deeper_results = read_chip(
            active_chip_summary=not arguments.skip_active_commands,
            deeper_probes=not arguments.skip_deeper_probes,
            run_writability=arguments.run_writability_test,
        )
        msg_payload = parse_ndef_text_like_app(pages_bytes)
        if msg_payload is None:
            print("[err ] no Text NDEF record found on this chip")
            sys.exit(1)
        print("[ndef] msgPayload (after .trim()) = " + repr(msg_payload))

        # Build the chip summary from the dump (passive) plus any active
        # NXP commands that may have succeeded. Persist to oracle if enabled.
        chip_summary = build_chip_summary(
            uid_bytes, pages_bytes, transmit_fn=None,
        )
        if active_summary is not None:
            chip_summary["active_commands"] = active_summary
            # Re-derive the conclusions with the new active data.
            gv = active_summary.get("get_version", {})
            if gv.get("succeeded") and gv.get("decoded"):
                d = gv["decoded"]
                chip_summary["conclusions"]["appears_to_be_real_nxp_silicon"] = (
                    d.get("vendor_id_byte") == 0x04
                )
                chip_summary["conclusions"]["chip_family_identified"] = (
                    d.get("family_name")
                )
            chip_summary["conclusions"]["originality_signature_obtained"] = (
                active_summary.get("read_sig", {}).get("succeeded", False)
            )

        if deeper_results is not None:
            chip_summary["interrogation"] = deeper_results

        if not arguments.no_chip_summary:
            print("")
            print(format_chip_summary(chip_summary))

        if oracle is not None:
            oracle.record_chip_summary(uid_bytes.hex().upper(), chip_summary)
            print("[oracle] chip summary + interrogation results saved "
                  "to DB BEFORE server query.")

        body = build_request_body(
            uid_bytes,
            msg_payload,
            arguments.device_id,
            arguments.lat,
            arguments.lon,
        )
        headers = build_request_headers()

        send_request(
            arguments.endpoint,
            body,
            headers,
            arguments.dry_run,
            "POST #1 -- MainActivity1.onNewIntent -> "
            "startMainActivityAndPassTag -> getProductInfo",
            oracle,
            uid_bytes,
            pages_bytes,
            msg_payload,
        )

        if not arguments.single_scan:
            send_request(
                arguments.endpoint,
                body,
                headers,
                arguments.dry_run,
                "POST #2 -- ResultActivity.onNewIntent -> "
                "startMainActivityAndPassTagGenuin -> getProductInfoGenuin",
                oracle,
                uid_bytes,
                pages_bytes,
                msg_payload,
            )
    finally:
        if oracle is not None:
            oracle.close()


if __name__ == "__main__":
    main()
