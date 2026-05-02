#!/usr/bin/env python3
"""
mintid_chip_interrogate.py — deeper chip-side interrogation.

Two layers, like mintid_chip_summary but pushing further:

  PASSIVE-DEEPER  (analyses dumps already in your DB, no chip required)
    * Memory structure analysis: zero/non-zero patterns, repetition, entropy
    * Heuristic clone-family fingerprinting from UID prefix + memory layout
    * Identifies the NDEF terminator TLV (0xFE) and reports how much memory
      is actually used vs advertised vs read

  ACTIVE-DEEPER  (requires the chip to be on the reader)
    * NON-DESTRUCTIVE WRITABILITY TEST: writes a page's content back to
      itself and observes whether the chip ACKs. Tests writability without
      changing data. Defaults to testing page 4 (first user data page on
      NTAG 213; check before running on chips with locked user memory).
    * FAST_READ probe (0x3A): tries to read a multi-page range in one
      command. NTAG 21x supports this; many clones do not.
    * PWD_AUTH probe (0x1B): tries the default NXP password (FF FF FF FF)
      to see whether password protection is configured. Returns 0x00 0x00
      ACK on success, NAK on wrong password.
    * READ on 'hidden' pages beyond the advertised storage size.
    * Magic-NTAG fingerprint: a few commands that Chinese magic clones
      respond to but real NXP chips don't.

EVERY ACTIVE TEST IS NON-DESTRUCTIVE BY DESIGN. We never write data that
differs from what's already on the chip, never send commands that would
permanently alter chip state (e.g. WRITE to lock bytes, password set),
never lock pages.

USAGE

    python3 mintid_chip_interrogate.py analyse <UID>
        Analyse a chip dump already in the DB. No reader required.

    python3 mintid_chip_interrogate.py probe
        Read the chip currently on the reader and run all active tests.

    python3 mintid_chip_interrogate.py probe --writability-page N
        Specify which page to use for the writability test (default 4).

    python3 mintid_chip_interrogate.py probe --skip-writability
        Run other active tests but skip the writability test.

    python3 mintid_chip_interrogate.py probe --dry-run
        Print every APDU we would send, without sending them.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
import sys
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mintid_oracle import Oracle
from mintid_chip_summary import (
    MANUFACTURER_CODES,
    parse_uid_structure,
    parse_capability_container,
    parse_lock_bytes,
)


# ---------------------------------------------------------------------------
# Passive deeper analysis
# ---------------------------------------------------------------------------

VALID_TLV_TAGS = {
    0x00: "NULL_TLV",
    0x01: "LOCK_CONTROL_TLV",
    0x02: "MEMORY_CONTROL_TLV",
    0x03: "NDEF_MESSAGE_TLV",
    0xFD: "PROPRIETARY_TLV",
    0xFE: "TERMINATOR_TLV",
}


def find_ndef_tlv_structure(pages_bytes, start_offset=16):
    """
    Walk the TLV stream starting at start_offset (default 16, the page-4
    byte-0 position on standard NTAG layout). For chips with the CC at
    offset 0 (clones), pass start_offset=4 instead.

    Stops on the FIRST unknown tag rather than walking through garbage.
    Collapses runs of NULL_TLV (0x00) and post-terminator zero padding.
    """
    if not pages_bytes or len(pages_bytes) < start_offset + 4:
        return [{"event": "dump_too_short", "offset": 0}]

    tlvs = []
    pos = start_offset
    while pos < len(pages_bytes):
        tag = pages_bytes[pos]

        if tag not in VALID_TLV_TAGS:
            tlvs.append({
                "event": "stream_invalid",
                "offset": pos,
                "tag": "0x%02X (not a valid TLV tag)" % tag,
                "remaining_bytes": len(pages_bytes) - pos,
            })
            break

        if tag == 0xFE:  # TERMINATOR
            tlvs.append({
                "tag": "TERMINATOR_TLV (0xFE)",
                "offset": pos, "length": 0,
            })
            # Count any remaining bytes after terminator
            remaining = pages_bytes[pos+1:]
            n_zeros = sum(1 for b in remaining if b == 0x00)
            if n_zeros > 0:
                tlvs.append({
                    "event": "post_terminator_padding",
                    "offset": pos + 1,
                    "byte_count": n_zeros,
                    "all_zero": (n_zeros == len(remaining)),
                })
            break

        if tag == 0x00:  # NULL
            # Count consecutive NULLs
            run_start = pos
            while pos < len(pages_bytes) and pages_bytes[pos] == 0x00:
                pos += 1
            run_len = pos - run_start
            if run_len <= 2:
                # Short run: report as individual NULLs
                for i in range(run_len):
                    tlvs.append({
                        "tag": "NULL_TLV (0x00)",
                        "offset": run_start + i, "length": 0,
                    })
            else:
                tlvs.append({
                    "event": "null_run",
                    "offset": run_start,
                    "byte_count": run_len,
                })
            continue

        # 0x01, 0x02, 0x03, 0xFD all have a length byte
        if pos + 1 >= len(pages_bytes):
            tlvs.append({
                "event": "truncated_tlv",
                "offset": pos,
                "tag": VALID_TLV_TAGS[tag],
            })
            break
        length_byte = pages_bytes[pos + 1]
        if length_byte == 0xFF:
            if pos + 4 > len(pages_bytes):
                tlvs.append({"event": "truncated_extended_length", "offset": pos})
                break
            length = (pages_bytes[pos + 2] << 8) | pages_bytes[pos + 3]
            value_offset = pos + 4
        else:
            length = length_byte
            value_offset = pos + 2

        tlvs.append({
            "tag": VALID_TLV_TAGS[tag] + " (0x%02X)" % tag,
            "offset": pos, "length": length,
            "value_offset": value_offset,
            "value_end": value_offset + length,
        })
        pos = value_offset + length

        if len(tlvs) > 16:
            tlvs.append({"event": "too_many_tlvs", "offset": pos})
            break

    return tlvs


def analyse_memory_pattern(pages_bytes):
    """
    Look at the page-by-page content of a chip dump for patterns that
    distinguish chip families:
      * Repetition: are pages outside the NDEF area duplicates of pages
        inside it?  (Suggests clone with copy-on-write or storage smaller
        than advertised.)
      * Zero distribution: how many trailing zero pages are there?
        (Real NTAG 213 has 4 zero config pages at the end; clones may have
        none or different counts.)
      * Entropy: how random are the non-zero bytes?
    """
    if not pages_bytes:
        return None

    pages = [pages_bytes[i:i+4] for i in range(0, len(pages_bytes), 4)]
    n = len(pages)

    # Count repeats
    seen = {}
    for i, p in enumerate(pages):
        h = bytes(p)
        seen.setdefault(h, []).append(i)
    repeats = {k.hex(): v for k, v in seen.items() if len(v) > 1}

    # Trailing zeros
    trailing_zero_pages = 0
    for i in range(n - 1, -1, -1):
        if pages[i] == b"\x00\x00\x00\x00":
            trailing_zero_pages += 1
        else:
            break

    # Leading zeros after the user data area
    nonzero_indices = [i for i, p in enumerate(pages) if p != b"\x00\x00\x00\x00"]
    last_nonzero = max(nonzero_indices) if nonzero_indices else -1

    # Entropy estimate over non-zero bytes
    nonzero_bytes = bytes(b for b in pages_bytes if b != 0)
    if nonzero_bytes:
        from collections import Counter
        counter = Counter(nonzero_bytes)
        import math
        total = len(nonzero_bytes)
        entropy_bits_per_byte = -sum(
            (c / total) * math.log2(c / total) for c in counter.values()
        )
    else:
        entropy_bits_per_byte = 0.0

    return {
        "page_count": n,
        "duplicate_pages": {
            page_hex: indices for page_hex, indices in repeats.items()
        },
        "duplicate_page_count": sum(
            len(v) - 1 for v in repeats.values()
        ),
        "trailing_zero_pages": trailing_zero_pages,
        "last_nonzero_page": last_nonzero,
        "entropy_bits_per_byte_in_nonzero_data": entropy_bits_per_byte,
    }


def fingerprint_clone(uid_bytes, pages_bytes, cc):
    """
    Heuristic identification of clone chip family from UID + memory layout.
    Returns a list of candidate family names, most-likely first.
    """
    if not uid_bytes:
        return []
    candidates = []
    uid_len = len(uid_bytes)
    byte0 = uid_bytes[0]
    page_count = len(pages_bytes) // 4 if pages_bytes else 0

    if byte0 == 0x04 and uid_len == 7:
        # Real NXP. Use storage size to narrow down.
        if page_count <= 16:
            candidates.append("NXP NTAG 213 (genuine, 144 bytes user memory)")
        elif page_count <= 41:
            candidates.append("NXP NTAG 215 (genuine, 504 bytes user memory)")
        else:
            candidates.append("NXP NTAG 216 (genuine, 888 bytes user memory)")
        return candidates

    # Anything not 04-prefixed is almost certainly a clone or non-NXP
    if uid_len == 8:
        candidates.append("Generic ISO 14443-3 8-byte UID clone "
                          "(common in Chinese-fab Ultralight clones)")
        if byte0 in (0x0F, 0x05, 0xAD):
            candidates.append("Possibly Mikron JSC clone or Fudan FM11RF005M")
    if uid_len == 7 and byte0 != 0x04:
        candidates.append("7-byte UID with non-NXP manufacturer code "
                          "(0x%02X). Likely Chinese magic NTAG clone." % byte0)

    if page_count == 16:
        candidates.append("Storage matches NTAG 213 layout (64 bytes accessible)")
    elif page_count == 64:
        candidates.append("Storage matches a 256-byte clone "
                          "(no real NXP NTAG variant has this exact size)")
    elif page_count > 41 and byte0 != 0x04:
        candidates.append("Larger than NTAG 213 -- possible cloned NTAG 215 "
                          "or oversized Ultralight clone")

    if not candidates:
        candidates.append("Unknown chip family")
    return candidates


def passive_deeper_report(uid_bytes, pages_bytes):
    """Compose a human-readable report combining all passive analyses."""
    out = []
    out.append("==== DEEPER CHIP ANALYSIS (passive) ====")
    out.append("UID: " + uid_bytes.hex().upper())
    out.append("Dump: %d bytes (%d pages)" % (
        len(pages_bytes), len(pages_bytes) // 4
    ))
    out.append("")

    cc = parse_capability_container(pages_bytes)
    if cc.get("present"):
        out.append("Layout: %s (CC found at offset %d)" % (
            cc.get("layout_kind", "unknown"), cc["cc_offset"]
        ))
        if cc["cc_offset"] == 0:
            out.append("  >> CC at offset 0 means there is NO standard "
                       "NTAG-style UID/internal/lock prefix in readable "
                       "memory. The chip exposes UID via anticollision "
                       "only. Lock byte semantics, if any, are unknown.")
        out.append("CC advertises %d bytes; we read %d." % (
            cc["storage_size_bytes_advertised"], len(pages_bytes)
        ))
        if len(pages_bytes) > cc["storage_size_bytes_advertised"]:
            out.append("  >> we read MORE than CC advertises. The 'extra' "
                       "pages are 'hidden' from NDEF-spec readers.")
        elif len(pages_bytes) < cc["storage_size_bytes_advertised"]:
            out.append("  >> we read LESS than CC advertises. Reader stopped "
                       "early or chip refuses some reads.")

    out.append("")
    out.append("Likely chip family:")
    for cand in fingerprint_clone(uid_bytes, pages_bytes, cc):
        out.append("  * " + cand)

    out.append("")
    pattern = analyse_memory_pattern(pages_bytes)
    if pattern:
        out.append("Memory pattern:")
        out.append("  duplicate page sets    : %d distinct repeating values" % (
            len(pattern["duplicate_pages"])
        ))
        out.append("  duplicate page total   : %d pages are duplicates of "
                   "other pages" % pattern["duplicate_page_count"])
        out.append("  trailing zero pages    : %d" % pattern["trailing_zero_pages"])
        out.append("  last nonzero page idx  : %d" % pattern["last_nonzero_page"])
        out.append("  entropy of nonzero data: %.2f bits/byte (max 8.0)" % (
            pattern["entropy_bits_per_byte_in_nonzero_data"]
        ))
        if pattern["duplicate_page_count"] > 5:
            out.append("  >> high duplication suggests memory wraparound, "
                       "ghosted reads, or a clone that mirrors the user area "
                       "across multiple page ranges.")

    out.append("")
    tlv_start = (cc.get("cc_offset", 12) + 4) if cc.get("present") else 16
    tlvs = find_ndef_tlv_structure(pages_bytes, start_offset=tlv_start)
    out.append("TLV structure (starting at offset %d):" % tlv_start)
    if not tlvs:
        out.append("  (no TLV stream found)")
    for t in tlvs:
        if "event" in t:
            event = t["event"]
            if event == "stream_invalid":
                out.append("  offset %3d  STREAM ENDS: %s "
                           "(%d bytes after this not parsed)" % (
                    t["offset"], t["tag"], t["remaining_bytes"]
                ))
            elif event == "null_run":
                out.append("  offset %3d  %d bytes of NULL_TLV (0x00) padding" % (
                    t["offset"], t["byte_count"]
                ))
            elif event == "post_terminator_padding":
                out.append("  offset %3d  %d bytes of post-terminator data%s" % (
                    t["offset"], t["byte_count"],
                    " (all 0x00)" if t["all_zero"] else ""
                ))
            elif event == "too_many_tlvs":
                out.append("  offset %3d  (too many TLVs, stopping)" % t["offset"])
            elif event == "truncated_tlv":
                out.append("  offset %3d  truncated %s" % (t["offset"], t["tag"]))
            elif event == "dump_too_short":
                out.append("  (dump shorter than 20 bytes, can't parse)")
            elif event == "truncated_extended_length":
                out.append("  offset %3d  truncated extended-length TLV" % t["offset"])
        elif "value_offset" in t:
            out.append("  offset %3d  %s  length=%d  (covers offsets %d..%d)" % (
                t["offset"], t["tag"], t["length"],
                t["value_offset"], t["value_end"] - 1
            ))
        else:
            out.append("  offset %3d  %s" % (t["offset"], t["tag"]))

    out.append("")
    out.append("CC bytes (page 3): " + (cc.get("raw_bytes_hex") or "n/a"))
    if cc.get("present"):
        out.append("  Write-access nibble = 0x%X. This is what the chip "
                   "ADVERTISES to NDEF readers, NOT a guarantee. To know "
                   "actual writability, use the active probe (writes a "
                   "page back to itself and observes ACK/NAK)." % (
                       cc["write_access_nibble"]
                   ))

    layout_kind = cc.get("layout_kind", "unknown") if cc.get("present") else "unknown"
    locks = parse_lock_bytes(pages_bytes, layout_kind=layout_kind)
    if locks.get("available"):
        out.append("")
        out.append("Lock bytes (page 2 bytes 2..3): %s %s" % (
            locks["lock0_hex"], locks["lock1_hex"]
        ))
        if locks.get("fully_locked_per_spec"):
            out.append("  >> FF FF: every page 3..15 is locked per NXP spec. "
                       "Writability test will return NAK on any of them.")
        elif locks["any_static_locks_set"]:
            spec_locked = locks.get("locked_pages_per_spec", [])
            spec_writable = locks.get("writable_pages_per_spec", [])
            block_ranges = locks.get("block_locked_ranges", [])
            if spec_locked:
                out.append("  Pages locked per NXP spec   : %s" % (
                    ", ".join(str(p) for p in spec_locked)
                ))
            if spec_writable:
                out.append("  Pages writable per NXP spec : %s" % (
                    ", ".join(str(p) for p in spec_writable)
                ))
            if block_ranges:
                out.append("  Block-lock bits set         : %s" % (
                    "; ".join(block_ranges)
                ))
            out.append("  >> Caveat: these per-page predictions are the NXP "
                       "NTAG 213 spec interpretation. A clone chip may handle "
                       "lock bytes differently or ignore them entirely. The "
                       "writability test is the only way to know for sure.")
        else:
            out.append("  >> static locks NOT set. The chip is likely "
                       "still writable across the user-data area. "
                       "Confirm with the active writability test.")
    elif locks.get("reason"):
        out.append("")
        out.append("Lock bytes: not parsed (%s)." % locks["reason"])
        out.append("  >> Whether the chip is field-writable is undetermined "
                   "from passive analysis. The active writability test will "
                   "tell us, but the result must be interpreted carefully -- "
                   "macOS framework may filter WRITE commands on non-"
                   "standard chips.")

    out.append("==========================================")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Active probe (requires PC/SC reader)
# ---------------------------------------------------------------------------

# Reuse the simulator's PC/SC plumbing rather than duplicating it.
def get_reader_handle():
    """Open a PC/SC connection. Returns (ctx, handle, io_request) or raises."""
    if sys.platform == "darwin":
        lib_path = "/System/Library/Frameworks/PCSC.framework/PCSC"
    else:
        lib_path = ctypes.util.find_library("pcsclite") or "libpcsclite.so.1"
    pcsc = ctypes.CDLL(lib_path)

    class SCardIoRequest(ctypes.Structure):
        _fields_ = [("dwProtocol", ctypes.c_uint32),
                    ("cbPciLength", ctypes.c_uint32)]

    pcsc.SCardEstablishContext.argtypes = [
        ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    pcsc.SCardListReaders.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    pcsc.SCardConnect.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32),
    ]
    pcsc.SCardTransmit.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(SCardIoRequest),
        ctypes.c_char_p, ctypes.c_uint32,
        ctypes.POINTER(SCardIoRequest), ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    pcsc.SCardDisconnect.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    pcsc.SCardReleaseContext.argtypes = [ctypes.c_void_p]

    ctx = ctypes.c_void_p()
    rv = pcsc.SCardEstablishContext(0x0000, None, None, ctypes.byref(ctx))
    if rv != 0:
        raise RuntimeError("SCardEstablishContext failed: 0x%08X" % (rv & 0xFFFFFFFF))

    needed = ctypes.c_uint32(0)
    pcsc.SCardListReaders(ctx, None, None, ctypes.byref(needed))
    buf = ctypes.create_string_buffer(needed.value)
    pcsc.SCardListReaders(ctx, None, buf, ctypes.byref(needed))
    readers = [s.decode("utf-8") for s in buf.raw[:needed.value].split(b"\x00") if s]
    if not readers:
        pcsc.SCardReleaseContext(ctx)
        raise RuntimeError("No PC/SC readers visible.")
    target = next((r for r in readers if "PICC" in r and "1552" in r), readers[0])

    handle = ctypes.c_void_p()
    proto = ctypes.c_uint32(0)
    rv = pcsc.SCardConnect(
        ctx, target.encode("utf-8"), 0x0002, 0x0003,
        ctypes.byref(handle), ctypes.byref(proto),
    )
    if rv != 0:
        pcsc.SCardReleaseContext(ctx)
        raise RuntimeError("SCardConnect failed: 0x%08X (no card?)" % (rv & 0xFFFFFFFF))

    io = SCardIoRequest(proto.value, ctypes.sizeof(SCardIoRequest))

    def transmit(apdu):
        send = bytes(apdu)
        recv = ctypes.create_string_buffer(2048)
        recv_len = ctypes.c_uint32(2048)
        rv = pcsc.SCardTransmit(
            handle, ctypes.byref(io),
            send, len(send),
            None, recv, ctypes.byref(recv_len),
        )
        if rv != 0:
            return None, 0, 0
        data = recv.raw[:recv_len.value]
        if len(data) < 2:
            return data, 0, 0
        return data[:-2], data[-2], data[-1]

    def cleanup():
        pcsc.SCardDisconnect(handle, 0x0000)
        pcsc.SCardReleaseContext(ctx)

    return target, transmit, cleanup


def transmit_native_command(transmit_fn, native_cmd_bytes,
                            expected_response_length=None, dry_run=False):
    """
    Try the same wrapper formats mintid_chip_summary uses. Returns the
    first one that succeeds, or None. If dry_run=True, just print the
    APDUs and return None.
    """
    wrappers = [
        ("direct_pseudo_apdu",
         [0xFF, 0x00, 0x00, 0x00, len(native_cmd_bytes)] + list(native_cmd_bytes)),
        ("acr_raw_transmit",
         [0xFF, 0x00, 0x48, 0x00, len(native_cmd_bytes)] + list(native_cmd_bytes)),
        ("pn532_incommunicatethru",
         [0xFF, 0x00, 0x00, 0x00, len(native_cmd_bytes) + 2,
          0xD4, 0x42] + list(native_cmd_bytes)),
    ]
    attempts = []
    for wrapper_name, apdu in wrappers:
        if dry_run:
            print("    [dry-run] would send via %s: %s" % (
                wrapper_name, bytes(apdu).hex().upper()
            ))
            attempts.append({"wrapper": wrapper_name, "dry_run": True})
            continue
        data, sw1, sw2 = transmit_fn(apdu)
        attempt = {
            "wrapper": wrapper_name,
            "sw": "%02X%02X" % (sw1, sw2) if data is not None else "ERR",
            "data_hex": data.hex().upper() if data else None,
            "data_length": len(data) if data else 0,
        }
        attempts.append(attempt)
        if (sw1, sw2) == (0x90, 0x00) and data is not None:
            payload = bytes(data)
            if (wrapper_name == "pn532_incommunicatethru"
                    and len(payload) >= 3
                    and payload[0] == 0xD5 and payload[1] == 0x43):
                payload = payload[3:]
            if expected_response_length is None or \
               len(payload) == expected_response_length:
                return wrapper_name, payload, attempts
    return None, None, attempts


def read_page_via_pseudo_apdu(transmit_fn, page_index):
    """Standard FF B0 pseudo-APDU read of one 4-byte page (returns 16
    bytes which is pages N..N+3 on the chip; we want only the first 4)."""
    apdu = [0xFF, 0xB0, 0x00, page_index, 0x10]
    data, sw1, sw2 = transmit_fn(apdu)
    if (sw1, sw2) != (0x90, 0x00) or not data:
        return None
    return bytes(data[:4])


def writability_test(transmit_fn, page_index, dry_run=False,
                     lock_info=None):
    """
    Non-destructive writability test:
      1. Read page <page_index>. Save its 4 bytes.
      2. Send WRITE (0xA2) with the SAME 4 bytes. The chip's response
         tells us whether the page accepts writes:
           ACK (0x0A or whatever the wrapper returns) -> writable
           NAK or no-response                          -> locked
      3. Read page <page_index> again. Confirm bytes are unchanged.
    Returns a structured result.

    If lock_info is provided (the dict returned by parse_lock_bytes), we
    use the per-page spec interpretation to predict the outcome. The
    actual write attempt always runs to confirm; on a clone chip the
    prediction may not match reality.
    """
    print("")
    print("==== WRITABILITY TEST (page %d) ====" % page_index)
    if lock_info is not None:
        if lock_info.get("fully_locked_per_spec"):
            print("  Lock bytes FF FF: chip predicts ALL pages 3..15 locked. "
                  "WRITE should NAK on a real NXP. Running anyway.")
        elif page_index in lock_info.get("locked_pages_per_spec", []):
            print("  Page %d is in locked_pages_per_spec. WRITE should NAK "
                  "if chip honours NXP semantics." % page_index)
        elif page_index in lock_info.get("writable_pages_per_spec", []):
            print("  Page %d is in writable_pages_per_spec. WRITE should "
                  "ACK on a chip honouring NXP semantics." % page_index)
        else:
            print("  Page %d is outside the static lock byte coverage "
                  "(pages 3..15). Outcome depends on dynamic locks." %
                  page_index)
    if dry_run:
        print("[dry-run] would: read page %d, attempt WRITE of same bytes back, "
              "read page %d again." % (page_index, page_index))
        return {"dry_run": True, "page_index": page_index}

    before = read_page_via_pseudo_apdu(transmit_fn, page_index)
    if before is None:
        print("  Could not read page %d. Aborting writability test." % page_index)
        return {"error": "could not read page", "page_index": page_index}
    print("  Page %d before WRITE: %s" % (page_index, before.hex().upper()))

    # Native NTAG WRITE: 0xA2 <page> <4 data bytes>
    write_cmd = bytes([0xA2, page_index]) + before
    wrapper, payload, attempts = transmit_native_command(
        transmit_fn, list(write_cmd),
        expected_response_length=None,  # ACK is variable across wrappers
    )

    accepted = wrapper is not None
    print("  WRITE attempt: %s" % (
        "ACCEPTED via " + wrapper if accepted
        else "REJECTED on every wrapper"
    ))

    after = read_page_via_pseudo_apdu(transmit_fn, page_index)
    print("  Page %d after WRITE : %s" % (
        page_index,
        after.hex().upper() if after else "(could not read back)"
    ))

    unchanged = (after == before)
    if not unchanged and after is not None:
        print("  !! PAGE CONTENT CHANGED. Bytes before/after differ. "
              "This should never happen since we wrote back identical bytes. "
              "Possible explanation: the chip echoed a different value.")

    print("  CONCLUSION: page %d %s" % (
        page_index,
        "is WRITABLE (chip accepted the write back)." if accepted
        else "is LOCKED or rejects writes (chip refused the write)."
    ))
    return {
        "page_index": page_index,
        "before_hex": before.hex().upper(),
        "after_hex": after.hex().upper() if after else None,
        "writable": accepted,
        "wrapper_used": wrapper,
        "all_attempts": attempts,
        "content_unchanged": unchanged,
    }


def fast_read_probe(transmit_fn, start_page=0, end_page=15, dry_run=False):
    """FAST_READ (0x3A) reads pages start..end inclusive in one command."""
    print("")
    print("==== FAST_READ PROBE (pages %d..%d) ====" % (start_page, end_page))
    cmd = [0x3A, start_page, end_page]
    wrapper, payload, attempts = transmit_native_command(
        transmit_fn, cmd,
        expected_response_length=(end_page - start_page + 1) * 4,
        dry_run=dry_run,
    )
    if dry_run:
        return {"dry_run": True}
    if wrapper:
        print("  FAST_READ accepted via %s, returned %d bytes." % (
            wrapper, len(payload)
        ))
        print("  First 32 bytes: %s%s" % (
            payload[:32].hex().upper(),
            "..." if len(payload) > 32 else ""
        ))
        return {"supported": True, "wrapper": wrapper,
                "data_hex": payload.hex().upper(),
                "byte_count": len(payload)}
    else:
        print("  FAST_READ rejected on every wrapper (chip likely doesn't "
              "implement it, or framework rewrites it).")
        return {"supported": False, "all_attempts": attempts}


def pwd_auth_probe(transmit_fn, password=b"\xFF\xFF\xFF\xFF", dry_run=False):
    """
    PWD_AUTH (0x1B + 4-byte password). NXP NTAG 213's factory-default
    password is FFFFFFFF, but this is irrelevant unless config pages
    have been written. ACK == password matches; NAK == doesn't match.
    """
    print("")
    print("==== PWD_AUTH PROBE (password=%s) ====" % password.hex().upper())
    cmd = [0x1B] + list(password)
    wrapper, payload, attempts = transmit_native_command(
        transmit_fn, cmd, expected_response_length=2, dry_run=dry_run,
    )
    if dry_run:
        return {"dry_run": True}
    if wrapper:
        # Successful auth returns a 2-byte PACK
        print("  PWD_AUTH ACCEPTED via %s. PACK returned: %s" % (
            wrapper, payload.hex().upper() if payload else "(none)"
        ))
        print("  Implication: chip has PWD_AUTH configured AND the password "
              "matches the default FFFFFFFF. Could indicate password is "
              "either factory-default or set to FFFFFFFF intentionally.")
        return {"matched": True, "pack": payload.hex().upper(),
                "wrapper": wrapper}
    else:
        print("  PWD_AUTH rejected on every wrapper. Either:")
        print("    * chip has no password set, and 0x1B is unsupported, OR")
        print("    * password doesn't match, OR")
        print("    * framework filters this command")
        return {"matched": False, "all_attempts": attempts}


def hidden_pages_probe(transmit_fn, advertised_page_count, dry_run=False):
    """
    Try to read pages above the chip's advertised storage. Real NTAG
    chips have physical memory beyond what CC advertises; for NTAG 213
    that means pages 16..44 are physically present even when CC says
    pages 4..15 are the only NDEF area.

    Two read paths attempted:
      A. FF B0 storage-card pseudo-APDU (filtered by macOS framework
         against the chip's ADVERTISED capacity).
      B. Native READ (0x30 + page) via wrapper transmit.
         Bypasses the CC limit because we're sending the chip's actual
         command directly.

    A real NXP NTAG 213 with CC=06 (advertising 48 bytes user) should:
      * NAK FF B0 for pages > 15 (framework enforces CC)
      * ACK native 0x30 READ for pages 16..44 (chip honours physical
        memory regardless of CC)
    A clone or 256-byte chip should respond differently in either or
    both paths.
    """
    print("")
    print("==== HIDDEN PAGES PROBE (above advertised %d pages) ====" % (
        advertised_page_count
    ))
    test_pages = [advertised_page_count, advertised_page_count + 4,
                  advertised_page_count + 16, advertised_page_count + 24,
                  advertised_page_count + 44]
    results = []
    for page_index in test_pages:
        if page_index > 255:
            continue

        # Path A: storage-card pseudo-APDU
        if dry_run:
            ff_b0_result = "[dry-run]"
        else:
            ff_b0_bytes = read_page_via_pseudo_apdu(transmit_fn, page_index)
            ff_b0_result = ff_b0_bytes.hex().upper() if ff_b0_bytes else "NAK"

        # Path B: native NTAG READ (0x30 + page) via the wrapper transmit
        if dry_run:
            native_result = "[dry-run]"
            native_data = None
        else:
            wrapper, payload, _ = transmit_native_command(
                transmit_fn, [0x30, page_index],
                expected_response_length=16,  # READ returns 16 bytes (4 pages)
                dry_run=False,
            )
            if wrapper:
                native_result = "%s via %s" % (
                    payload[:4].hex().upper(), wrapper
                )
                native_data = payload[:4].hex().upper()
            else:
                native_result = "NAK on every wrapper"
                native_data = None

        print("  page %3d  FF B0: %-12s  native 0x30: %s" % (
            page_index, ff_b0_result, native_result
        ))
        results.append({
            "page": page_index,
            "ff_b0": ff_b0_result if ff_b0_result not in ("NAK", "[dry-run]") else None,
            "native_0x30": native_data,
        })

    # Interpret
    print("")
    framework_blocks = all(r["ff_b0"] is None for r in results)
    native_works = any(r["native_0x30"] for r in results)
    if framework_blocks and native_works:
        print("  >> The macOS framework blocks reads beyond the CC limit, "
              "but the chip itself happily serves them via native 0x30. "
              "This means hidden pages exist and contain real data.")
    elif framework_blocks and not native_works:
        print("  >> Both paths NAK. Either chip really has no memory above "
              "the advertised limit, or framework filters BOTH paths.")
    elif not framework_blocks:
        print("  >> Chip exposes pages above CC advertised limit even via "
              "the spec-conformant FF B0 path. Unusual; consistent with "
              "a clone that doesn't enforce CC bounds.")
    return {"results": results}


def magic_clone_fingerprint_probe(transmit_fn, dry_run=False):
    """
    Several Chinese magic NTAG clones respond to vendor-specific 'magic'
    commands that real NXP chips reject. We send a few of these and
    record any unexpected ACKs.

    These commands DO NOT modify chip state; they're query-only fingerprints.
    """
    print("")
    print("==== MAGIC-CLONE FINGERPRINT PROBE ====")
    fingerprint_cmds = [
        ("CL2 anticollision (0x9320)", [0x93, 0x20]),
        ("Custom GET_VERSION variant (0xC0)", [0xC0]),
        ("Custom GET_VERSION variant (0x6D)", [0x6D]),
    ]
    results = []
    for label, cmd in fingerprint_cmds:
        print("  Trying %s..." % label)
        wrapper, payload, attempts = transmit_native_command(
            transmit_fn, cmd, expected_response_length=None, dry_run=dry_run,
        )
        if dry_run:
            continue
        if wrapper:
            print("    -> ACK via %s, payload: %s" % (
                wrapper, payload.hex().upper() if payload else "(empty)"
            ))
            results.append({"command": label, "ack": True,
                            "payload_hex": payload.hex().upper() if payload else ""})
        else:
            print("    -> NAK on every wrapper")
            results.append({"command": label, "ack": False})
    return {"results": results}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def cmd_analyse(args):
    oracle = Oracle(args.db)
    cur = oracle.connection.cursor()
    cur.execute(
        "SELECT chip_uid_bytes, chip_pages_bytes FROM scans "
        "WHERE chip_uid = ? AND chip_pages_bytes IS NOT NULL "
        "ORDER BY scan_id DESC LIMIT 1",
        (args.uid.upper(),)
    )
    row = cur.fetchone()
    if row is None:
        print("No dump in DB for UID " + args.uid.upper())
        oracle.close()
        return
    uid_bytes, pages_bytes = bytes(row[0]), bytes(row[1])
    print(passive_deeper_report(uid_bytes, pages_bytes))
    oracle.close()


def run_field_probes(transmit_fn, uid_bytes, pages_bytes,
                     run_writability=False,
                     verbose=True):
    """
    Run the deeper-interrogation probes against a chip whose connection
    is already open (the simulator holds the PC/SC handle and passes us
    its transmit function). Returns a structured dict of all probe
    results suitable for persisting to the oracle.

    Probes run by default (all read-only):
      * passive deeper analysis (memory pattern, fingerprint, TLV)
      * fast_read_probe
      * pwd_auth_probe (default password FF FF FF FF)
      * hidden_pages_probe (FF B0 + native 0x30)
      * magic_clone_fingerprint_probe

    Writability test runs only when run_writability=True. It writes the
    chip's existing bytes back to itself (non-destructive), but every
    write attempt consumes an EEPROM cycle on writable chips. Default
    off to avoid burning cycles on every scan.

    The probes are LAYOUT-AWARE: writability picks a page from the
    user-data area based on whether the chip uses ntag_standard or
    cc_at_origin layout.
    """
    results = {}

    # Passive deeper analysis (computed from pages_bytes alone)
    cc = parse_capability_container(pages_bytes)
    layout = cc.get("layout_kind", "unknown") if cc.get("present") else "unknown"
    advertised_pages = (
        cc["storage_size_bytes_advertised"] // 4
        if cc.get("present") else len(pages_bytes) // 4
    )
    if verbose:
        print(passive_deeper_report(uid_bytes, pages_bytes))

    results["passive"] = {
        "cc": cc,
        "layout_kind": layout,
        "advertised_page_count": advertised_pages,
        "memory_pattern": analyse_memory_pattern(pages_bytes),
        "tlv_structure": find_ndef_tlv_structure(
            pages_bytes,
            start_offset=(cc.get("cc_offset", 12) + 4) if cc.get("present") else 16,
        ),
        "clone_fingerprint": fingerprint_clone(uid_bytes, pages_bytes, cc),
    }

    # Active probes
    if run_writability:
        # Layout-aware page selection
        chosen_page = 4
        if layout == "cc_at_origin":
            for t in results["passive"]["tlv_structure"]:
                if "TERMINATOR" in t.get("tag", ""):
                    chosen_page = t["offset"] // 4
                    break
        lock_info = parse_lock_bytes(pages_bytes, layout_kind=layout)
        results["writability"] = writability_test(
            transmit_fn, chosen_page, dry_run=False, lock_info=lock_info,
        )

    results["fast_read"] = fast_read_probe(
        transmit_fn, 0, min(15, advertised_pages - 1), dry_run=False,
    )
    results["pwd_auth_default"] = pwd_auth_probe(
        transmit_fn, dry_run=False,
    )
    results["hidden_pages"] = hidden_pages_probe(
        transmit_fn, advertised_pages, dry_run=False,
    )
    results["magic_clone"] = magic_clone_fingerprint_probe(
        transmit_fn, dry_run=False,
    )

    return results


def cmd_probe(args):
    oracle = Oracle(args.db) if not args.no_oracle else None
    if args.dry_run:
        print("[dry-run] not connecting to reader, just printing planned APDUs.")
        # Use a no-op transmit
        def fake_transmit(apdu):
            return None, 0, 0
        target, transmit, cleanup = "(dry-run, no reader)", fake_transmit, lambda: None
    else:
        try:
            target, transmit, cleanup = get_reader_handle()
        except RuntimeError as exc:
            print("Could not connect to reader: " + str(exc))
            sys.exit(1)
        print("[reader] " + target)

    try:
        # First read UID + dump for the passive analysis
        if not args.dry_run:
            data, sw1, sw2 = transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            if (sw1, sw2) != (0x90, 0x00):
                print("UID query failed.")
                return
            uid_bytes = bytes(data)
            print("UID: " + uid_bytes.hex().upper())
            pages = bytearray()
            last_ok = -1
            for pi in range(0, 64, 4):
                d, s1, s2 = transmit([0xFF, 0xB0, 0x00, pi, 0x10])
                if (s1, s2) != (0x90, 0x00) or not d:
                    break
                pages.extend(d); last_ok = pi + 3
            pages_bytes = bytes(pages)
            print("Read %d bytes across pages 0..%d" % (len(pages_bytes), last_ok))
            print("")
            print(passive_deeper_report(uid_bytes, pages_bytes))
            page_count_advertised = len(pages_bytes) // 4
        else:
            page_count_advertised = 16

        results = {"active_probes": {}}

        if not args.skip_writability:
            lock_info = None
            chosen_page = args.writability_page
            if not args.dry_run:
                cc_info = parse_capability_container(pages_bytes)
                layout = cc_info.get("layout_kind", "unknown") if cc_info.get("present") else "unknown"
                lock_info = parse_lock_bytes(pages_bytes, layout_kind=layout)
                # Auto-pick a sensible test page if user didn't override.
                # On cc_at_origin clones, page 4 is the NDEF TLV header
                # which we don't want to nudge -- pick the last page of
                # the actual NDEF data area instead, which is also where
                # the TERMINATOR_TLV lives. Writing-back the same bytes
                # is still non-destructive.
                if (args.writability_page == 4
                        and layout == "cc_at_origin"):
                    # Find the terminator and use the page that contains it
                    tlvs = find_ndef_tlv_structure(
                        pages_bytes, start_offset=cc_info["cc_offset"] + 4
                    )
                    for t in tlvs:
                        if "TERMINATOR" in t.get("tag", ""):
                            chosen_page = t["offset"] // 4
                            print("[probe] cc_at_origin layout: using "
                                  "page %d (contains terminator) for "
                                  "writability test instead of page 4." %
                                  chosen_page)
                            break
            results["active_probes"]["writability"] = writability_test(
                transmit, chosen_page,
                dry_run=args.dry_run,
                lock_info=lock_info,
            )
        results["active_probes"]["fast_read"] = fast_read_probe(
            transmit, 0, min(15, page_count_advertised - 1),
            dry_run=args.dry_run,
        )
        results["active_probes"]["pwd_auth_default"] = pwd_auth_probe(
            transmit, dry_run=args.dry_run,
        )
        results["active_probes"]["hidden_pages"] = hidden_pages_probe(
            transmit, page_count_advertised, dry_run=args.dry_run,
        )
        results["active_probes"]["magic_clone"] = magic_clone_fingerprint_probe(
            transmit, dry_run=args.dry_run,
        )

        if oracle is not None and not args.dry_run:
            # Persist as a note on the most recent scan for this UID
            cur = oracle.connection.cursor()
            cur.execute(
                "SELECT scan_id FROM scans WHERE chip_uid = ? "
                "ORDER BY scan_id DESC LIMIT 1",
                (uid_bytes.hex().upper(),)
            )
            row = cur.fetchone()
            if row:
                oracle.annotate(
                    row[0],
                    "deeper-interrogate: " + json.dumps(
                        results, sort_keys=True, default=str
                    )
                )
                print("")
                print("Results stored as note on scan #%d" % row[0])
    finally:
        cleanup()
        if oracle is not None:
            oracle.close()


def main():
    parser = argparse.ArgumentParser(
        description="Deeper chip-side interrogation for MintID coins."
    )
    parser.add_argument("--db", default="mintid_oracle.db")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_analyse = sub.add_parser(
        "analyse", help="Passive analysis of a chip dump already in DB."
    )
    p_analyse.add_argument("uid", help="Chip UID (uppercase hex).")
    p_analyse.set_defaults(func=cmd_analyse)

    p_probe = sub.add_parser(
        "probe", help="Active interrogation of the chip on the reader."
    )
    p_probe.add_argument("--writability-page", type=int, default=4,
                         help="Page to use for writability test (default 4).")
    p_probe.add_argument("--skip-writability", action="store_true",
                         help="Skip the writability test (read-only mode).")
    p_probe.add_argument("--dry-run", action="store_true",
                         help="Print APDUs that would be sent, don't send.")
    p_probe.add_argument("--no-oracle", action="store_true",
                         help="Don't write probe results to the oracle DB.")
    p_probe.set_defaults(func=cmd_probe)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
