"""
mintid_chip_summary.py — analyse a Type 2 NFC tag's chip-side data.

Two layers:

  1. PASSIVE: parses things from a memory dump we already have (the FF B0 read
     pages 0..N from the oracle's chip_pages_bytes column). This always works:
        * UID structure (cascade tag, manufacturer code, BCC bytes)
        * Lock bytes (static + dynamic)
        * Capability Container (CC) parse: NDEF version, storage size, R/W
          access, magic byte
        * Page-by-page zero/non-zero map
        * SHA-256 of the full dump (baseline for future tamper detection)
        * Manufacturer-code lookup (NXP, Infineon, STMicro, clones, etc.)

  2. ACTIVE: tries a few NXP-specific commands by sending them through the
     PC/SC reader. These often fail on macOS because the framework treats
     these chips as 'storage cards' and synthesizes responses, but we record
     whether each command was attempted, the raw bytes if returned, and
     whether the result decodes to something sensible:
        * GET_VERSION (0x60)         -> 8 bytes identifying chip family
        * READ_SIG    (0x3C 0x00)    -> 32 bytes ECDSA originality signature
        * READ_CNT    (0x39 0x02)    -> 3 bytes NFC counter

This module has NO hard dependency on PC/SC; the active layer is invoked
only when a transmit callback is provided. Passive analysis works on any
dump bytes.
"""
import hashlib
from collections import OrderedDict


# Known NXP/competitor manufacturer codes (ISO/IEC 7816-6 / 14443-3).
# Byte 0 of a 7-byte UID is the manufacturer code.
MANUFACTURER_CODES = {
    0x02: "STMicroelectronics",
    0x04: "NXP Semiconductors",
    0x05: "Infineon Technologies",
    0x07: "Texas Instruments",
    0x16: "EM Microelectronic-Marin",
    0x21: "EM Microelectronic-Marin (alt)",
    0x28: "ST Microelectronics (alt)",
    0x33: "AMIC Technology",
    0x44: "Generic / unregistered",
    0x47: "ZMDI",
}


# GET_VERSION decoder for NXP NTAG family. Format from NXP datasheet
# NTAG213/215/216 product short data sheet, section 9.5.
NTAG_VERSIONS = {
    # (storage_size, product_subtype) -> human name
    (0x0F, 0x01): "NTAG 213",
    (0x11, 0x01): "NTAG 215",
    (0x13, 0x01): "NTAG 216",
    (0x0F, 0x02): "NTAG 213F (with field detection)",
    (0x13, 0x02): "NTAG 216F (with field detection)",
    (0x0B, 0x03): "NTAG I2C 1k",
    (0x0E, 0x03): "NTAG I2C 2k",
}


def _hex(b):
    return b.hex().upper() if b else None


def _is_all_zero(b):
    return b is not None and all(byte == 0 for byte in b)


def _maybe_decode_get_version(version_bytes):
    """
    Decode the 8-byte GET_VERSION response per NXP NTAG family format:
      [0] 0x00 (header byte)
      [1] vendor ID            (0x04 = NXP)
      [2] product type         (0x04 = NTAG)
      [3] product subtype      (0x01 standard, 0x02 with FD, 0x03 I2C)
      [4] major product version
      [5] minor product version
      [6] storage size         (0x0F=NTAG213, 0x11=NTAG215, 0x13=NTAG216)
      [7] protocol type
    Returns a dict, or None if the bytes don't look like a GET_VERSION
    response.
    """
    if not version_bytes or len(version_bytes) != 8:
        return None
    if version_bytes[0] != 0x00:
        return None
    vendor_id = version_bytes[1]
    product_type = version_bytes[2]
    product_subtype = version_bytes[3]
    major_version = version_bytes[4]
    minor_version = version_bytes[5]
    storage_size = version_bytes[6]
    protocol_type = version_bytes[7]

    family_name = NTAG_VERSIONS.get(
        (storage_size, product_subtype), "unknown NTAG variant"
    )

    # Storage size encoding: 2^(n/2) bytes accessible if n is odd, else
    # exactly 2^(n/2) bytes. NXP encodes it as ceil(log2(size_in_bytes))*2.
    # Approximate: storage_size byte 0x0F = 144 user bytes (NTAG213),
    # 0x11 = 504 bytes (NTAG215), 0x13 = 888 bytes (NTAG216).
    storage_size_bytes_approx = {
        0x0F: 144, 0x11: 504, 0x13: 888,
        0x0B: 144, 0x0E: 256,
    }.get(storage_size)

    return {
        "vendor_id_byte": vendor_id,
        "vendor_name": MANUFACTURER_CODES.get(vendor_id, "unknown"),
        "product_type_byte": product_type,
        "product_subtype_byte": product_subtype,
        "major_version": major_version,
        "minor_version": minor_version,
        "storage_size_byte": storage_size,
        "storage_size_user_bytes_approx": storage_size_bytes_approx,
        "protocol_type": protocol_type,
        "family_name": family_name,
    }


def parse_capability_container(pages_bytes):
    """
    Find and parse the NFC Forum Type 2 Tag Capability Container.

    On standard NTAG layout the CC is at page 3 (offset 12). But some
    chips (notably 8-byte-UID clones used in MintID inventory) skip the
    NTAG-style UID/lock prefix entirely and put the CC at offset 0. So
    we scan the first 16 bytes for the 0xE1 magic byte at any of the
    page-aligned offsets (0, 4, 8, 12) and parse from there.

    Returns a dict including 'cc_offset' so callers can reason about
    chip layout. Sets 'layout_kind' to either 'ntag_standard' (CC at
    offset 12) or 'cc_at_origin' (CC at offset 0) or 'unknown'.

    CC format (per NFC Forum Type 2 Tag spec, section 6.1):
      byte 0: magic number (0xE1)
      byte 1: version + access bits
        bits 7..4 = major version
        bits 3..0 = minor version (or access in some interpretations)
      byte 2: data area size in 8-byte units
      byte 3: read/write access bits
        bits 7..4 = read access  (0x0 = open, 0xF = no access)
        bits 3..0 = write access (0x0 = open, 0xF = no access)
    """
    if pages_bytes is None or len(pages_bytes) < 16:
        return {"present": False, "reason": "dump shorter than 16 bytes"}

    # Scan page-aligned offsets in the first 16 bytes for the CC magic.
    cc_offset = None
    for candidate in (12, 0, 4, 8):
        if pages_bytes[candidate] == 0xE1:
            cc_offset = candidate
            break

    if cc_offset is None:
        return {
            "present": False,
            "reason": "no 0xE1 CC magic byte at offset 0/4/8/12",
            "raw_first_16_bytes_hex": pages_bytes[:16].hex().upper(),
        }

    cc = pages_bytes[cc_offset:cc_offset+4]
    layout_kind = (
        "ntag_standard" if cc_offset == 12
        else "cc_at_origin" if cc_offset == 0
        else "unusual_offset_%d" % cc_offset
    )
    version_byte = cc[1]
    storage_units = cc[2]
    access_byte = cc[3]
    return {
        "present": True,
        "cc_offset": cc_offset,
        "layout_kind": layout_kind,
        "magic_byte": cc[0],
        "version_byte": version_byte,
        "version_major": (version_byte >> 4) & 0x0F,
        "version_minor": version_byte & 0x0F,
        "storage_size_units_of_8_bytes": storage_units,
        "storage_size_bytes_advertised": storage_units * 8,
        "read_access_nibble": (access_byte >> 4) & 0x0F,
        "write_access_nibble": access_byte & 0x0F,
        "read_access_open": ((access_byte >> 4) & 0x0F) == 0x00,
        "write_access_open": (access_byte & 0x0F) == 0x00,
        "raw_bytes_hex": _hex(cc),
    }


def parse_lock_bytes(pages_bytes, layout_kind="ntag_standard"):
    """
    Parse static lock bytes. Only meaningful on the standard NTAG
    layout where lock bytes live at page 2 bytes 2-3 (offsets 10-11).
    On 'cc_at_origin' clones those offsets are part of the NDEF stream
    and don't represent locks at all -- we explicitly DON'T parse them
    in that case rather than report meaningless lock-bit decodings.
    """
    if layout_kind != "ntag_standard":
        return {
            "available": False,
            "reason": "lock bytes only present on ntag_standard layout; "
                      "this chip uses %s layout" % layout_kind,
        }
    return _parse_lock_bytes_ntag_standard(pages_bytes)


def _parse_lock_bytes_ntag_standard(pages_bytes):
    """
    Static lock bytes at page 2, bytes 2-3 of the dump. Decoded per the
    NTAG 213 datasheet layout (section 8.3.2):

      lock0 (page 2 byte 2):
        bit 0 = block-lock for pages 10..15 (BL_BL15_10)
        bit 1 = block-lock for pages 4..9   (BL_BL9_4)
        bit 2 = block-lock for CC page 3    (BL_CC)
        bit 3 = lock page 3 (CC)
        bit 4 = lock page 4
        bit 5 = lock page 5
        bit 6 = lock page 6
        bit 7 = lock page 7

      lock1 (page 2 byte 3):
        bit n = lock page (8 + n)  for n in 0..7

    "Block-lock" means the lock bit itself is frozen -- the page can
    still be writable, but its lock bit can never be set.

    Clones may interpret these bytes loosely or not at all. We report
    the NXP spec interpretation as a baseline.
    """
    if pages_bytes is None or len(pages_bytes) < 16:
        return {"available": False}
    lock0 = pages_bytes[10]
    lock1 = pages_bytes[11]

    # Per-page write-lock state per NTAG 213 spec
    locked_pages = []
    block_locked_ranges = []
    cc_locked = False

    if lock0 & 0x01:
        block_locked_ranges.append("pages 10..15 (lock bits frozen)")
    if lock0 & 0x02:
        block_locked_ranges.append("pages 4..9 (lock bits frozen)")
    if lock0 & 0x04:
        block_locked_ranges.append("CC page 3 (lock bit frozen)")
    if lock0 & 0x08:
        cc_locked = True
        locked_pages.append(3)
    for bit, page in [(0x10, 4), (0x20, 5), (0x40, 6), (0x80, 7)]:
        if lock0 & bit:
            locked_pages.append(page)
    for bit_pos in range(8):
        if lock1 & (1 << bit_pos):
            locked_pages.append(8 + bit_pos)

    pages_4_to_15 = list(range(4, 16))
    writable_pages_per_spec = [p for p in pages_4_to_15
                                if p not in locked_pages]
    fully_locked_per_spec = (lock0 == 0xFF and lock1 == 0xFF)

    return {
        "available": True,
        "lock0_byte": lock0,
        "lock1_byte": lock1,
        "lock0_hex": "%02X" % lock0,
        "lock1_hex": "%02X" % lock1,
        "any_static_locks_set": (lock0 != 0 or lock1 != 0),
        "static_lock_count": bin(lock0).count("1") + bin(lock1).count("1"),
        "fully_locked_per_spec": fully_locked_per_spec,
        "cc_page_locked": cc_locked,
        "block_locked_ranges": block_locked_ranges,
        "locked_pages_per_spec": locked_pages,
        "writable_pages_per_spec": writable_pages_per_spec,
    }


def parse_uid_structure(uid_bytes):
    """
    Decompose the UID. For NXP-style 7-byte UIDs:
        byte 0:    manufacturer code (0x04 = NXP)
        bytes 1-6: chip-specific serial number
    For 8-byte UIDs (commonly clones or ICODE-style chips), byte 0 is still
    a manufacturer code in spec-conformant chips, but many clones use
    arbitrary bytes here.
    For 4-byte UIDs (legacy MIFARE Classic etc.) byte 0 is also the
    manufacturer code.
    """
    if uid_bytes is None or len(uid_bytes) == 0:
        return {"valid": False, "reason": "empty UID"}
    manufacturer_code = uid_bytes[0]
    return {
        "valid": True,
        "uid_length_bytes": len(uid_bytes),
        "uid_hex": _hex(uid_bytes),
        "manufacturer_code_byte": manufacturer_code,
        "manufacturer_code_hex": "%02X" % manufacturer_code,
        "manufacturer_name": MANUFACTURER_CODES.get(
            manufacturer_code, "unknown / clone / unregistered"
        ),
        "is_real_nxp_uid": manufacturer_code == 0x04,
        "is_seven_byte_iso14443a": len(uid_bytes) == 7,
        "is_eight_byte_unusual": len(uid_bytes) == 8,
        "is_four_byte_legacy": len(uid_bytes) == 4,
    }


def analyze_pages(pages_bytes):
    """
    Page-by-page summary: which pages are all-zero, which are non-zero,
    SHA-256 of the full dump.
    """
    if pages_bytes is None:
        return {"pages_total": 0}
    pages_total = len(pages_bytes) // 4
    zero_pages = []
    nonzero_pages = []
    for i in range(pages_total):
        page_bytes = pages_bytes[i*4:(i+1)*4]
        if _is_all_zero(page_bytes):
            zero_pages.append(i)
        else:
            nonzero_pages.append(i)
    return {
        "pages_total": pages_total,
        "page_size_bytes": 4,
        "total_dump_bytes": len(pages_bytes),
        "zero_page_count": len(zero_pages),
        "nonzero_page_count": len(nonzero_pages),
        "zero_pages_list": zero_pages,
        "full_dump_sha256": hashlib.sha256(pages_bytes).hexdigest(),
    }


def attempt_active_commands(transmit_fn):
    """
    Try to send NTAG-specific commands through the reader. transmit_fn
    is a callable taking a bytes/list APDU and returning (data_bytes,
    sw1, sw2). If transmit_fn is None, returns a 'not attempted' result.

    Multiple wrapper formats are tried because different ACR-family
    readers and different OS frameworks accept different escape paths:

      A. Direct pseudo-APDU passthrough:
            FF 00 00 00 LC <native NTAG cmd>
      B. ACR1252U/1552U raw transmit:
            FF 00 48 00 LC <native NTAG cmd>
      C. PN532-style InCommunicateThru wrapper:
            FF 00 00 00 (LC+2) D4 42 <native NTAG cmd>

    Each command is attempted via every wrapper until one returns SW=9000
    with a plausible-length payload. If none works, the result is recorded
    as 'attempted but no path returned valid data'.
    """
    result = OrderedDict()
    result["transmit_attempted"] = transmit_fn is not None

    if transmit_fn is None:
        result["get_version"] = {"attempted": False}
        result["read_sig"] = {"attempted": False}
        result["read_cnt"] = {"attempted": False}
        return result

    def try_wrappers(native_cmd_bytes, expected_response_length):
        """
        Try each wrapper format. Return (wrapper_used, data, sw1, sw2)
        for the first one that returns SW=9000 AND produces a payload
        whose length matches the expected response length, or
        (None, None, None, None) if all failed.
        """
        attempts = []
        wrappers = [
            ("direct_pseudo_apdu",
             [0xFF, 0x00, 0x00, 0x00, len(native_cmd_bytes)] + list(native_cmd_bytes)),
            ("acr_raw_transmit",
             [0xFF, 0x00, 0x48, 0x00, len(native_cmd_bytes)] + list(native_cmd_bytes)),
            ("pn532_incommunicatethru",
             [0xFF, 0x00, 0x00, 0x00, len(native_cmd_bytes) + 2,
              0xD4, 0x42] + list(native_cmd_bytes)),
        ]
        for wrapper_name, apdu in wrappers:
            try:
                data, sw1, sw2 = transmit_fn(apdu)
            except Exception as exc:
                attempts.append({
                    "wrapper": wrapper_name,
                    "exception": str(exc),
                })
                continue
            attempt = {
                "wrapper": wrapper_name,
                "sw": "%02X%02X" % (sw1, sw2),
                "data_hex": _hex(data) if data else None,
                "data_length": len(data) if data else 0,
            }
            attempts.append(attempt)
            if (sw1, sw2) == (0x90, 0x00) and data is not None:
                # PN532 wrapper returns: D5 43 <status> <native response>.
                # Strip those four bytes if it looks like a PN532 reply.
                payload = bytes(data)
                if (wrapper_name == "pn532_incommunicatethru"
                        and len(payload) >= 3
                        and payload[0] == 0xD5
                        and payload[1] == 0x43):
                    payload = payload[3:]
                if len(payload) == expected_response_length:
                    return wrapper_name, payload, sw1, sw2, attempts
        return None, None, None, None, attempts

    # GET_VERSION
    wrapper, payload, sw1, sw2, attempts = try_wrappers([0x60], 8)
    if payload:
        decoded = _maybe_decode_get_version(payload)
        result["get_version"] = {
            "attempted": True,
            "succeeded": True,
            "wrapper": wrapper,
            "raw_response_hex": payload.hex().upper(),
            "decoded": decoded,
            "all_attempts": attempts,
        }
    else:
        result["get_version"] = {
            "attempted": True,
            "succeeded": False,
            "all_attempts": attempts,
        }

    # READ_SIG
    wrapper, payload, sw1, sw2, attempts = try_wrappers([0x3C, 0x00], 32)
    if payload:
        result["read_sig"] = {
            "attempted": True,
            "succeeded": True,
            "wrapper": wrapper,
            "raw_signature_hex": payload.hex().upper(),
            "all_attempts": attempts,
        }
    else:
        result["read_sig"] = {
            "attempted": True,
            "succeeded": False,
            "all_attempts": attempts,
        }

    # READ_CNT (NFC counter at address 0x02)
    wrapper, payload, sw1, sw2, attempts = try_wrappers([0x39, 0x02], 3)
    if payload:
        # 3-byte counter, little-endian
        counter_value = payload[0] | (payload[1] << 8) | (payload[2] << 16)
        result["read_cnt"] = {
            "attempted": True,
            "succeeded": True,
            "wrapper": wrapper,
            "raw_response_hex": payload.hex().upper(),
            "counter_value": counter_value,
            "all_attempts": attempts,
        }
    else:
        result["read_cnt"] = {
            "attempted": True,
            "succeeded": False,
            "all_attempts": attempts,
        }
    return result


def build_chip_summary(uid_bytes, pages_bytes, transmit_fn=None):
    """
    Top-level entry point. Build a complete chip summary from a UID and
    memory dump, optionally also attempting active NXP commands.
    """
    summary = OrderedDict()
    summary["uid"] = parse_uid_structure(uid_bytes)
    cc_info = parse_capability_container(pages_bytes)
    summary["capability_container"] = cc_info
    layout = (
        cc_info.get("layout_kind", "ntag_standard")
        if cc_info.get("present") else "ntag_standard"
    )
    summary["lock_bytes"] = parse_lock_bytes(pages_bytes, layout_kind=layout)
    summary["page_analysis"] = analyze_pages(pages_bytes)
    summary["active_commands"] = attempt_active_commands(transmit_fn)

    # Top-level conclusions. These are best-effort heuristics, not
    # cryptographic verdicts.
    uid_info = summary["uid"]
    cc_info = summary["capability_container"]
    active = summary["active_commands"]
    gv = active.get("get_version", {})
    rs = active.get("read_sig", {})

    is_likely_nxp = uid_info.get("is_real_nxp_uid", False)
    if gv.get("succeeded") and gv.get("decoded"):
        is_likely_nxp = (
            gv["decoded"].get("vendor_id_byte") == 0x04
        )
    summary["conclusions"] = {
        "appears_to_be_real_nxp_silicon": is_likely_nxp,
        "ndef_capability_container_valid": cc_info.get("present", False),
        "static_locks_set": summary["lock_bytes"].get(
            "any_static_locks_set", False
        ),
        "originality_signature_obtained": rs.get("succeeded", False),
        "originality_signature_verified_against_nxp": None,
        "chip_family_identified": (
            gv.get("decoded", {}).get("family_name")
            if gv.get("decoded") else None
        ),
    }
    return summary


def format_chip_summary(summary):
    """Human-readable rendering for stdout / CLI."""
    out = []
    out.append("==== CHIP SUMMARY ====")
    uid = summary["uid"]
    if uid["valid"]:
        out.append("UID: %s (%d bytes)" % (
            uid["uid_hex"], uid["uid_length_bytes"],
        ))
        out.append("  Manufacturer code: 0x%s = %s" % (
            uid["manufacturer_code_hex"], uid["manufacturer_name"],
        ))
        if uid["is_real_nxp_uid"]:
            out.append("  -> UID byte 0 == 0x04, consistent with real NXP silicon.")
        else:
            out.append("  -> UID byte 0 != 0x04, NOT registered NXP. Likely a clone.")

    cc = summary["capability_container"]
    out.append("")
    out.append("Capability Container (page 3):")
    if cc.get("present"):
        out.append("  raw bytes : %s" % cc["raw_bytes_hex"])
        out.append("  NDEF Forum version: %d.%d" % (
            cc["version_major"], cc["version_minor"],
        ))
        out.append("  Storage advertised: %d bytes (%d * 8)" % (
            cc["storage_size_bytes_advertised"],
            cc["storage_size_units_of_8_bytes"],
        ))
        out.append("  Read access  : 0x%X (%s)" % (
            cc["read_access_nibble"],
            "open" if cc["read_access_open"] else "restricted",
        ))
        out.append("  Write access : 0x%X (%s)" % (
            cc["write_access_nibble"],
            "open" if cc["write_access_open"] else "restricted",
        ))
    else:
        out.append("  CC missing or invalid (%s)" % cc.get("reason", "?"))

    locks = summary["lock_bytes"]
    out.append("")
    out.append("Lock bytes (page 2 bytes 2..3):")
    if locks.get("available"):
        out.append("  lock0 = 0x%s, lock1 = 0x%s" % (
            locks["lock0_hex"], locks["lock1_hex"],
        ))
        out.append("  any static locks set : %s" % (
            "yes" if locks["any_static_locks_set"] else "no",
        ))
        out.append("  total bits set       : %d" % (
            locks["static_lock_count"],
        ))
        if locks.get("fully_locked_per_spec"):
            out.append("  -> FF FF: every page 3..15 locked per NXP spec")
        elif locks.get("locked_pages_per_spec"):
            out.append("  Locked pages (NXP spec)   : %s" % (
                ", ".join(str(p) for p in locks["locked_pages_per_spec"])
            ))
            out.append("  Writable pages (NXP spec) : %s" % (
                ", ".join(str(p) for p in locks.get("writable_pages_per_spec", []))
            ))
    elif locks.get("reason"):
        out.append("  not parsed (%s)" % locks["reason"])
    else:
        out.append("  not available")

    pages = summary["page_analysis"]
    out.append("")
    out.append("Pages (%d total, %d bytes):" % (
        pages["pages_total"], pages["total_dump_bytes"],
    ))
    out.append("  zero pages    : %d" % pages["zero_page_count"])
    out.append("  nonzero pages : %d" % pages["nonzero_page_count"])
    out.append("  full dump SHA : %s" % pages["full_dump_sha256"])

    active = summary["active_commands"]
    out.append("")
    out.append("Active NXP commands:")
    for cmd_name, cmd_label in [
        ("get_version", "GET_VERSION"),
        ("read_sig", "READ_SIG"),
        ("read_cnt", "READ_CNT"),
    ]:
        info = active.get(cmd_name, {})
        if not info.get("attempted"):
            out.append("  %s : not attempted" % cmd_label)
            continue
        if info.get("succeeded"):
            extras = []
            if cmd_name == "get_version" and info.get("decoded"):
                d = info["decoded"]
                extras.append(d.get("family_name"))
                extras.append("vendor=%s" % d.get("vendor_name"))
            elif cmd_name == "read_cnt":
                extras.append("counter=%d" % info["counter_value"])
            extras_text = "  (" + ", ".join(extras) + ")" if extras else ""
            out.append("  %s : OK via %s%s" % (
                cmd_label, info.get("wrapper"), extras_text,
            ))
        else:
            out.append("  %s : attempted, no wrapper returned valid data" % (
                cmd_label,
            ))

    interrogation = summary.get("interrogation")
    if interrogation:
        out.append("")
        out.append("Deeper interrogation probes:")

        passive = interrogation.get("passive", {})
        if passive:
            out.append("  Layout kind                : %s" % (
                passive.get("layout_kind", "unknown")
            ))
            cc_p = passive.get("cc", {})
            if cc_p.get("cc_offset") is not None:
                out.append("  CC found at offset         : %d" % (
                    cc_p["cc_offset"]
                ))
            mp = passive.get("memory_pattern") or {}
            if mp:
                out.append("  Trailing zero pages        : %d" % (
                    mp.get("trailing_zero_pages", 0)
                ))
                out.append("  Last nonzero page idx      : %d" % (
                    mp.get("last_nonzero_page", -1)
                ))
                out.append("  Entropy of nonzero data    : %.2f bits/byte" % (
                    mp.get("entropy_bits_per_byte_in_nonzero_data", 0.0)
                ))
            cf = passive.get("clone_fingerprint", [])
            if cf:
                out.append("  Likely chip family         :")
                for cand in cf:
                    out.append("    * %s" % cand)
            tlvs = passive.get("tlv_structure", [])
            if tlvs:
                out.append("  TLV stream                 : %d entries" % len(tlvs))
                for t in tlvs[:5]:
                    if "event" in t:
                        out.append("    offset %3d  [%s]" % (
                            t.get("offset", 0), t["event"]
                        ))
                    elif "value_offset" in t:
                        out.append("    offset %3d  %s  length=%d" % (
                            t["offset"], t["tag"], t["length"]
                        ))
                    else:
                        out.append("    offset %3d  %s" % (
                            t.get("offset", 0), t.get("tag", "?")
                        ))

        wt = interrogation.get("writability")
        if wt:
            if wt.get("error"):
                out.append("  Writability test           : ERROR %s" % wt["error"])
            elif wt.get("dry_run"):
                out.append("  Writability test           : (dry-run)")
            else:
                out.append("  Writability test (page %d)  : %s" % (
                    wt.get("page_index", -1),
                    "WRITABLE (chip ACK'd write-back)"
                    if wt.get("writable")
                    else "LOCKED/REJECTED (chip NAK'd write)"
                ))
                if wt.get("wrapper_used"):
                    out.append("    via wrapper               : %s" % wt["wrapper_used"])

        fr = interrogation.get("fast_read")
        if fr:
            out.append("  FAST_READ (0x3A)           : %s" % (
                "supported via " + fr.get("wrapper", "?")
                if fr.get("supported")
                else "rejected on every wrapper"
            ))

        pa = interrogation.get("pwd_auth_default")
        if pa:
            out.append("  PWD_AUTH default password  : %s" % (
                "MATCHED (PACK=%s)" % pa.get("pack", "?")
                if pa.get("matched")
                else "no match / rejected"
            ))

        hp = interrogation.get("hidden_pages")
        if hp:
            results_list = hp.get("results", [])
            ack_via_ff_b0 = sum(1 for r in results_list if r.get("ff_b0"))
            ack_via_native = sum(1 for r in results_list if r.get("native_0x30"))
            out.append("  Hidden pages probe         : %d/%d ACK via FF B0, "
                       "%d/%d ACK via native 0x30" % (
                ack_via_ff_b0, len(results_list),
                ack_via_native, len(results_list),
            ))

        mc = interrogation.get("magic_clone")
        if mc:
            results_list = mc.get("results", [])
            acks = [r for r in results_list if r.get("ack")]
            if acks:
                out.append("  Magic-clone fingerprints   : %d/%d commands "
                           "unexpectedly ACK'd:" % (
                    len(acks), len(results_list)
                ))
                for a in acks:
                    out.append("    * %s -> %s" % (
                        a.get("command", "?"), a.get("payload_hex", "")
                    ))
            else:
                out.append("  Magic-clone fingerprints   : all rejected "
                           "(consistent with non-magic chip)")

    conc = summary["conclusions"]
    out.append("")
    out.append("Conclusions:")
    out.append("  Real NXP silicon          : %s" % (
        "yes (per UID and/or GET_VERSION)"
        if conc["appears_to_be_real_nxp_silicon"]
        else "no (clone, non-NXP, or unreadable)"
    ))
    out.append("  Chip family identified    : %s" % (
        conc["chip_family_identified"] or "unknown"
    ))
    out.append("  NDEF CC valid             : %s" % (
        "yes" if conc["ndef_capability_container_valid"] else "no"
    ))
    out.append("  Static locks set          : %s" % (
        "yes" if conc["static_locks_set"] else "no"
    ))
    out.append("  Originality signature obtained : %s" % (
        "yes" if conc["originality_signature_obtained"] else "no"
    ))
    out.append("======================")
    return "\n".join(out)
