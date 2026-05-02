#!/usr/bin/env python3
"""
mintid_probe.py — small, structured, hard-capped probes against MintID's
verification API. NOT a bulk-enumeration tool by design.

Each probe answers a specific question. All probes are bounded by an
explicit MAX_REQUESTS_PER_RUN cap and a per-second rate limit so this
script can never accidentally turn into rapid-fire enumeration. Every
probe is logged to the oracle DB so we can re-query history later
without re-sending.

THE FIVE PROBES

  1. baseline-replay
       Re-sends every (UID, crypto) tuple already in your oracle DB and
       compares the response SHA-256 against history. Confirms the server
       remains deterministic over longer time spans (days/weeks). Already
       done informally; this makes it a structured experiment.

  2. cryptogram-bit-flip
       Takes a single known-good cryptogram, flips one bit at a time in
       the FIRST byte (8 mutations), pairs each with the matching UID,
       and queries. Expected: every response returns Product:null
       because AES decryption fails. If any returns Product != null,
       the server isn't actually decrypting -- huge finding.

  3. uid-bit-flip
       Takes a single known-good (UID, crypto) pair, flips bits in the
       UID (8 mutations of byte 0), and queries with each mutated UID
       alongside the unmodified cryptogram. Expected: Product:null for
       all, because the server's UID lookup matches exact strings. If any
       returns Product != null, the cryptogram alone is sufficient.

  4. uid-nearby-batch
       Probes a small, deliberate set of UIDs near a known-good NXP UID,
       paired with the known cryptogram. Tests whether the cryptogram
       alone is the real lookup key (it shouldn't be, but worth
       verifying). 16 probes total.

  5. objectid-nearby-batch
       Tests whether adjacent MongoDB ObjectIds in the product collection
       resolve to other valid products. Since GetProducyById is dead and
       there's no other catalog-lookup route, we test indirectly: we use
       a synthesised (UID, crypto) pair and see if the server's response
       contains a different Product._id than expected. (This is mostly
       defensive - we don't expect this probe to find anything, but the
       ObjectId structure makes it a cheap experiment.)

LIMITS

  MAX_REQUESTS_PER_RUN  default 60. Hard cap per invocation. Increase
                        only with --max-requests, capped at 200.
  MIN_INTERVAL_SECONDS  default 0.5s between requests, sequential.
                        Configurable via --interval.

USAGE

    python3 mintid_probe.py baseline-replay
    python3 mintid_probe.py cryptogram-bit-flip
    python3 mintid_probe.py uid-bit-flip
    python3 mintid_probe.py uid-nearby-batch
    python3 mintid_probe.py objectid-nearby-batch
    python3 mintid_probe.py all          # runs each in sequence
"""
import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mintid_oracle import Oracle


BASE_URL = "http://mintidapi.droisys.info/api"
ENDPOINT_PATH = "/ProductAuthentication/SecuredScanProduct"
MAX_REQUESTS_HARD_CEILING = 200
DEFAULT_MAX_REQUESTS = 60
DEFAULT_MIN_INTERVAL = 0.5

HEADERS_GUEST = OrderedDict([
    ("OrgAccessID", "000000000000000000000000"),
    ("AuthorizationKey", "2I0mGELp"),
    ("Content-Type", "application/json"),
    ("User-Agent", "okhttp/3.14.9"),
])


# -- shared infrastructure ---------------------------------------------------


class RequestBudget:
    """Tracks request count + interval-spacing across a probe run."""

    def __init__(self, max_requests, min_interval):
        self.max_requests = min(max_requests, MAX_REQUESTS_HARD_CEILING)
        self.min_interval = min_interval
        self.sent = 0
        self._last_send_time = 0.0

    def can_send(self):
        return self.sent < self.max_requests

    def wait_for_slot(self):
        elapsed = time.monotonic() - self._last_send_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_send_time = time.monotonic()

    def mark_sent(self):
        self.sent += 1


def build_request_body(tag_uid_str, crypto_str, device_id="", lat=0.0, lon=0.0):
    """The same request body shape the simulator builds, byte-for-byte
    matching the official Android app's Jackson output."""
    body = OrderedDict([
        ("DeviceID", device_id),
        ("DeviceType", "Android"),
        ("Lat", lat),
        ("Lon", lon),
        ("TagCrypto", crypto_str),
        ("TagProvider", "Identiv"),
        ("TagType", "NFC Tags"),
        ("TagUID", tag_uid_str),
        ("TagValue", "1234567812345678"),
    ])
    return json.dumps(body, separators=(",", ":"))


def send_one_request(tag_uid_str, crypto_str, label, oracle, budget,
                     synthetic_uid_bytes=None):
    """
    Send a single SecuredScanProduct request. Logs everything to oracle.
    Returns (response_status, body_dict_or_none, body_string).
    """
    if not budget.can_send():
        print("[budget] hit max-requests cap of %d, stopping." % budget.max_requests)
        return None, None, None
    budget.wait_for_slot()

    url = BASE_URL + ENDPOINT_PATH
    body_string = build_request_body(tag_uid_str, crypto_str)
    body_bytes = body_string.encode("utf-8")

    print("")
    print("[%d/%d] %s" % (budget.sent + 1, budget.max_requests, label))
    print("    UID    : " + tag_uid_str)
    print("    Crypto : " + crypto_str)

    # Open a scan record so the (synthetic) UID + body get persisted
    # even if the response is bad.
    uid_bytes_for_db = (
        synthetic_uid_bytes if synthetic_uid_bytes is not None
        else bytes.fromhex(tag_uid_str) if all(c in "0123456789ABCDEFabcdef" for c in tag_uid_str) and len(tag_uid_str) % 2 == 0
        else b""
    )
    scan_id = oracle.begin_scan(
        uid_bytes_for_db, b"", crypto_str
    )
    oracle.record_request(scan_id, url, HEADERS_GUEST, body_string)
    oracle.annotate(scan_id, "probe: " + label)

    request = urllib.request.Request(
        url, data=body_bytes, headers=dict(HEADERS_GUEST), method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status = response.status
            response_headers = OrderedDict(response.headers.items())
            body_string_resp = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        response_headers = OrderedDict(exc.headers.items())
        body_string_resp = exc.read().decode("utf-8", errors="replace")
    except Exception as exc:
        print("    ERROR: " + str(exc))
        budget.mark_sent()
        return None, None, None

    budget.mark_sent()

    body_dict = None
    try:
        body_dict = json.loads(body_string_resp)
    except Exception:
        pass

    diff = oracle.record_response(
        scan_id, tag_uid_str, status, response_headers, body_string_resp
    )

    # One-line interpretation
    if body_dict and body_dict.get("Result"):
        product = body_dict["Result"].get("Product")
        ntag_tt = body_dict["Result"].get("NTAGTTStatus")
        tag_num = body_dict["Result"].get("TagNumber") or "(none)"
        product_id = product.get("_id") if product else None
        product_name = product.get("ProductName") if product else None
        print("    -> HTTP %d, NTAGTTStatus=%s, TagNumber=%s, Product=%s" % (
            status, ntag_tt, tag_num,
            (product_name + " (" + product_id + ")") if product_id else "null"
        ))
        if product_id:
            print("    !! PRODUCT FOUND. Probe label: " + label)
    else:
        print("    -> HTTP %d, no Result block" % status)

    return status, body_dict, body_string_resp


def confirm_or_abort(prompt_text, max_requests):
    """Show the user what we're about to do and require explicit OK."""
    print("")
    print("=" * 70)
    print(prompt_text)
    print("Hard cap on this run: " + str(max_requests) + " requests.")
    print("=" * 70)
    answer = input("Proceed? (yes/no): ").strip().lower()
    if answer not in ("y", "yes"):
        print("Aborted.")
        sys.exit(0)


# -- the five probes ---------------------------------------------------------


def probe_baseline_replay(oracle, budget):
    """Re-send every distinct (UID, crypto) tuple in the DB."""
    cur = oracle.connection.cursor()
    cur.execute(
        "SELECT DISTINCT chip_uid, chip_ndef_text FROM scans "
        "WHERE chip_ndef_text IS NOT NULL "
        "AND chip_uid != '' "
        "ORDER BY chip_uid"
    )
    pairs = cur.fetchall()
    print("Found %d distinct (UID, crypto) pairs in oracle DB." % len(pairs))
    for uid, crypto in pairs:
        send_one_request(
            uid, crypto, "baseline-replay UID=%s" % uid, oracle, budget
        )


def probe_cryptogram_bit_flip(oracle, budget):
    """Flip each bit of byte 0 of one known cryptogram, keep UID."""
    cur = oracle.connection.cursor()
    cur.execute(
        "SELECT chip_uid, chip_ndef_text FROM scans "
        "WHERE response_product_id IS NOT NULL "
        "AND chip_uid != '' "
        "ORDER BY scan_id LIMIT 1"
    )
    row = cur.fetchone()
    if not row:
        print("No known-good (UID, crypto) pairs in DB. Run a real scan first.")
        return
    uid, crypto = row
    crypto_bytes = bytes.fromhex(crypto)
    print("Mutating byte 0 of cryptogram " + crypto)
    print("  UID stays " + uid)
    for bit in range(8):
        mutated = bytearray(crypto_bytes)
        mutated[0] ^= (1 << bit)
        new_crypto = mutated.hex()
        send_one_request(
            uid, new_crypto,
            "crypto-bit-flip bit%d (byte0=%02X->%02X)" % (
                bit, crypto_bytes[0], mutated[0]
            ),
            oracle, budget,
        )


def probe_uid_bit_flip(oracle, budget):
    """Flip each bit of byte 0 of one known UID, keep cryptogram."""
    cur = oracle.connection.cursor()
    cur.execute(
        "SELECT chip_uid, chip_ndef_text FROM scans "
        "WHERE response_product_id IS NOT NULL "
        "AND chip_uid != '' "
        "ORDER BY scan_id LIMIT 1"
    )
    row = cur.fetchone()
    if not row:
        print("No known-good (UID, crypto) pairs in DB. Run a real scan first.")
        return
    uid, crypto = row
    uid_bytes = bytes.fromhex(uid)
    print("Mutating byte 0 of UID " + uid)
    print("  Cryptogram stays " + crypto)
    for bit in range(8):
        mutated = bytearray(uid_bytes)
        mutated[0] ^= (1 << bit)
        new_uid = mutated.hex().upper()
        send_one_request(
            new_uid, crypto,
            "uid-bit-flip bit%d (byte0=%02X->%02X)" % (
                bit, uid_bytes[0], mutated[0]
            ),
            oracle, budget,
            synthetic_uid_bytes=bytes(mutated),
        )


def probe_uid_nearby_batch(oracle, budget, count=16):
    """
    Probe UIDs near a known NXP UID (byte +/- 1 ... +/- 8 on byte 6, the
    LSB of the chip-specific serial), paired with the known cryptogram.
    """
    cur = oracle.connection.cursor()
    cur.execute(
        "SELECT chip_uid, chip_ndef_text FROM scans "
        "WHERE response_product_id IS NOT NULL "
        "AND chip_uid != '' "
        "AND chip_uid LIKE '04%' "
        "ORDER BY scan_id LIMIT 1"
    )
    row = cur.fetchone()
    if not row:
        print("No NXP-prefixed (UID, crypto) pairs in DB.")
        return
    uid, crypto = row
    uid_bytes = bytes.fromhex(uid)
    if len(uid_bytes) != 7:
        print("UID is not 7 bytes; skipping nearby-batch.")
        return
    print("Probing UIDs near %s with crypto %s" % (uid, crypto))
    half = count // 2
    for delta in list(range(-half, 0)) + list(range(1, half + 1)):
        new_last = (uid_bytes[6] + delta) & 0xFF
        new_uid_bytes = uid_bytes[:6] + bytes([new_last])
        new_uid = new_uid_bytes.hex().upper()
        send_one_request(
            new_uid, crypto,
            "uid-nearby delta=%+d (last byte %02X->%02X)" % (
                delta, uid_bytes[6], new_last
            ),
            oracle, budget,
            synthetic_uid_bytes=new_uid_bytes,
        )


def probe_objectid_nearby_batch(oracle, budget, count=8):
    """
    Synthesise ObjectIds adjacent to known product IDs by tweaking the
    last 3 bytes (the counter portion) and try them as UIDs paired with
    a known cryptogram. This is mostly a sanity check -- we don't expect
    findings -- but it's cheap.

    Note: ObjectId-as-UID is a category error (UIDs are 4/7/8 bytes; an
    ObjectId is 12 bytes), so the request body will set TagUID to the
    hex-string form of an adjacent ObjectId. The server will treat this
    as a string lookup, fail to match anything, and return Product:null.
    Useful only as a control case showing the server doesn't pattern-match.
    """
    cur = oracle.connection.cursor()
    cur.execute(
        "SELECT product_id FROM product_records "
        "ORDER BY product_updated_date DESC LIMIT 1"
    )
    row = cur.fetchone()
    if not row:
        print("No product records in DB.")
        return
    pid = row[0]
    pid_bytes = bytes.fromhex(pid)

    # Get a known cryptogram to pair with.
    cur.execute(
        "SELECT chip_ndef_text FROM scans WHERE chip_ndef_text IS NOT NULL "
        "ORDER BY scan_id LIMIT 1"
    )
    crypto_row = cur.fetchone()
    if not crypto_row:
        return
    crypto = crypto_row[0]

    print("Probing ObjectIds near %s as TagUID, paired with crypto %s" % (
        pid, crypto
    ))
    half = count // 2
    for delta in list(range(-half, 0)) + list(range(1, half + 1)):
        last_three = int.from_bytes(pid_bytes[9:12], "big") + delta
        last_three &= 0xFFFFFF
        new_pid_bytes = pid_bytes[:9] + last_three.to_bytes(3, "big")
        new_pid_hex = new_pid_bytes.hex().upper()
        send_one_request(
            new_pid_hex, crypto,
            "objectid-nearby delta=%+d (counter %d)" % (delta, last_three),
            oracle, budget,
            synthetic_uid_bytes=new_pid_bytes,
        )


# -- main --------------------------------------------------------------------


PROBES = OrderedDict([
    ("baseline-replay", probe_baseline_replay),
    ("cryptogram-bit-flip", probe_cryptogram_bit_flip),
    ("uid-bit-flip", probe_uid_bit_flip),
    ("uid-nearby-batch", probe_uid_nearby_batch),
    ("objectid-nearby-batch", probe_objectid_nearby_batch),
])


def main():
    parser = argparse.ArgumentParser(
        description="Small, structured probes against MintID. Hard-capped, "
                    "rate-limited, no enumeration."
    )
    parser.add_argument(
        "--db", default="mintid_oracle.db",
        help="Path to the oracle DB (default ./mintid_oracle.db)."
    )
    parser.add_argument(
        "--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
        help="Hard cap on requests per run (default %d, ceiling %d)." % (
            DEFAULT_MAX_REQUESTS, MAX_REQUESTS_HARD_CEILING,
        )
    )
    parser.add_argument(
        "--interval", type=float, default=DEFAULT_MIN_INTERVAL,
        help="Minimum seconds between requests (default %.1fs)." % DEFAULT_MIN_INTERVAL
    )
    parser.add_argument(
        "--no-confirm", action="store_true",
        help="Skip interactive confirmation prompt."
    )
    parser.add_argument(
        "probe", choices=list(PROBES.keys()) + ["all"],
        help="Which probe to run."
    )
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print("Oracle DB not found: " + args.db, file=sys.stderr)
        sys.exit(1)

    if args.max_requests > MAX_REQUESTS_HARD_CEILING:
        print("Refusing --max-requests > %d." % MAX_REQUESTS_HARD_CEILING)
        sys.exit(1)

    oracle = Oracle(args.db)
    budget = RequestBudget(args.max_requests, args.interval)

    if not args.no_confirm:
        if args.probe == "all":
            description = (
                "Will run all 5 probes against production MintID server.\n"
                "  - baseline-replay      (re-query known UIDs)\n"
                "  - cryptogram-bit-flip  (8 mutations of byte 0)\n"
                "  - uid-bit-flip         (8 mutations of byte 0)\n"
                "  - uid-nearby-batch     (16 nearby UIDs)\n"
                "  - objectid-nearby-batch (8 nearby ObjectIds)\n"
                "All requests use guest creds, all logged to oracle DB."
            )
        else:
            description = "Will run probe: " + args.probe
        confirm_or_abort(description, args.max_requests)

    if args.probe == "all":
        for name, fn in PROBES.items():
            print("")
            print("##### " + name.upper() + " #####")
            fn(oracle, budget)
            if not budget.can_send():
                print("Budget exhausted after probe '%s'." % name)
                break
    else:
        PROBES[args.probe](oracle, budget)

    print("")
    print("Done. Sent %d/%d requests." % (budget.sent, budget.max_requests))
    print("All probe results stored in oracle DB. Inspect with:")
    print("  python3 mintid_oracle_cli.py list")
    print("  python3 mintid_oracle_cli.py show <UID>")

    oracle.close()


if __name__ == "__main__":
    main()
