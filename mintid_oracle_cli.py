#!/usr/bin/env python3
"""
mintid_oracle_cli.py — inspect the local SQLite oracle DB without scanning.

Subcommands:
  list                   Show every coin we've recorded, with seen counts.
  show <UID>             Show full history for a given chip UID (uppercase hex).
  products               Show every distinct product record we've seen.
  product <product_id>   Show every version of a given product record.
  diff <scan_a> <scan_b> Diff the response bodies of two scans by scan_id.
  export <scan_id>       Print a single scan's full request+response in detail.
  schema                 Print the SQLite schema.
"""
import argparse
import json
import os
import sqlite3
import sys


def _db(path):
    if not os.path.exists(path):
        print("Oracle DB not found: " + path, file=sys.stderr)
        sys.exit(1)
    return sqlite3.connect(path)


def cmd_list(args):
    conn = _db(args.db)
    cur = conn.cursor()
    cur.execute(
        "SELECT chip_uid, COUNT(*) AS n, MIN(scan_started_at), "
        "MAX(scan_started_at), "
        "MAX(response_product_name), MAX(response_tag_number) "
        "FROM scans GROUP BY chip_uid ORDER BY MAX(scan_started_at) DESC"
    )
    rows = cur.fetchall()
    if not rows:
        print("(no scans recorded yet)")
        return
    print("UID               Scans  First seen                       "
          "Last seen                        Product                            Serial")
    print("-" * 145)
    for uid, n, first, last, name, tag in rows:
        print("%-17s %5d  %-32s %-32s %-34s %s" % (
            uid, n, first or "-", last or "-",
            (name or "-")[:34], tag or "-"
        ))


def cmd_show(args):
    uid = args.uid.upper()
    conn = _db(args.db)
    cur = conn.cursor()
    cur.execute(
        "SELECT scan_id, scan_started_at, chip_ndef_text, "
        "response_status, response_status_code, response_ntag_tt_status, "
        "response_tag_number, response_product_name, "
        "response_product_id, response_product_updated_date, "
        "request_body_sha256, response_body_sha256 "
        "FROM scans WHERE chip_uid = ? ORDER BY scan_id",
        (uid,),
    )
    rows = cur.fetchall()
    if not rows:
        print("No scans for UID " + uid)
        return

    print("All scans for UID " + uid + ":")
    print("")
    for row in rows:
        (scan_id, ts, ndef, http, status_code, ntag_tt,
         tag_number, product_name, product_id, product_updated,
         req_sha, resp_sha) = row
        print("scan #%d  @ %s" % (scan_id, ts))
        print("  NDEF text         : %r" % ndef)
        print("  HTTP status       : %s" % http)
        print("  Result.StatusCode : %s" % status_code)
        print("  NTAGTTStatus      : %s" % ntag_tt)
        print("  TagNumber         : %s" % tag_number)
        print("  Product           : %s" % product_name)
        print("  Product._id       : %s" % product_id)
        print("  Product UpdatedDate: %s" % product_updated)
        print("  Request body SHA  : %s" % req_sha)
        print("  Response body SHA : %s" % resp_sha)
        print("")

    cur.execute(
        "SELECT chip_ndef_text, COUNT(*), MIN(scan_started_at), "
        "MAX(scan_started_at) FROM scans WHERE chip_uid = ? "
        "GROUP BY chip_ndef_text ORDER BY MIN(scan_started_at)",
        (uid,),
    )
    ndef_rows = cur.fetchall()
    if len(ndef_rows) > 1:
        print("!! Chip NDEF text has CHANGED across scans of this UID:")
        for ndef, n, first, last in ndef_rows:
            print("    %r  (seen %d times, %s .. %s)" % (
                ndef, n, first, last
            ))
    else:
        print("Chip NDEF text has been stable across all %d scans." % len(rows))

    cur.execute(
        "SELECT product_id, MAX(tag_number), SUM(seen_count) "
        "FROM coin_to_product WHERE chip_uid = ? GROUP BY product_id",
        (uid,),
    )
    coin_products = cur.fetchall()
    if coin_products:
        print("")
        print("Linked product records:")
        for product_id, tag, total in coin_products:
            cur.execute(
                "SELECT product_name, COUNT(*) FROM product_records "
                "WHERE product_id = ? GROUP BY product_id",
                (product_id,),
            )
            r = cur.fetchone()
            name = r[0] if r else "?"
            versions = r[1] if r else 0
            print("  %s (%s) tag=%s versions=%d" % (
                product_id, name, tag, versions
            ))


def cmd_products(args):
    conn = _db(args.db)
    cur = conn.cursor()
    cur.execute(
        "SELECT product_id, product_name, sku, manufacturer, "
        "COUNT(*) AS versions, SUM(seen_count) AS total_seen "
        "FROM product_records GROUP BY product_id "
        "ORDER BY total_seen DESC"
    )
    rows = cur.fetchall()
    if not rows:
        print("(no product records yet)")
        return
    print("Product ID                 Versions  Seen   SKU              "
          "Manufacturer        ProductName")
    print("-" * 130)
    for pid, name, sku, mfr, vers, seen in rows:
        print("%-26s %8d  %5d  %-16s %-19s %s" % (
            pid, vers, seen, sku or "-", mfr or "-", name or "-"
        ))


def cmd_product(args):
    conn = _db(args.db)
    cur = conn.cursor()
    cur.execute(
        "SELECT product_updated_date, product_name, sku, manufacturer, "
        "first_seen_at, last_seen_at, seen_count, full_record_json "
        "FROM product_records WHERE product_id = ? "
        "ORDER BY product_updated_date",
        (args.product_id,),
    )
    rows = cur.fetchall()
    if not rows:
        print("No product records for " + args.product_id)
        return
    print("Product: " + args.product_id)
    print("Versions seen: %d" % len(rows))
    print("")
    for row in rows:
        (upd, name, sku, mfr, first, last, seen, full) = row
        print("  Version with UpdatedDate = %s" % upd)
        print("    ProductName  : %s" % name)
        print("    SKU          : %s" % sku)
        print("    Manufacturer : %s" % mfr)
        print("    First seen   : %s" % first)
        print("    Last seen    : %s" % last)
        print("    Seen count   : %d" % seen)
        if args.full:
            try:
                parsed = json.loads(full)
                print("    Full record  : " + json.dumps(parsed, indent=6))
            except Exception:
                print("    Full record  : " + full)
        print("")


def cmd_diff(args):
    import difflib
    conn = _db(args.db)
    cur = conn.cursor()
    cur.execute(
        "SELECT scan_id, response_body FROM scans WHERE scan_id IN (?, ?)",
        (args.scan_a, args.scan_b),
    )
    bodies = {row[0]: row[1] for row in cur.fetchall()}
    if args.scan_a not in bodies:
        print("No such scan: %d" % args.scan_a, file=sys.stderr)
        sys.exit(1)
    if args.scan_b not in bodies:
        print("No such scan: %d" % args.scan_b, file=sys.stderr)
        sys.exit(1)

    a = bodies[args.scan_a] or ""
    b = bodies[args.scan_b] or ""
    try:
        a_pretty = json.dumps(json.loads(a), indent=2, sort_keys=True)
    except Exception:
        a_pretty = a
    try:
        b_pretty = json.dumps(json.loads(b), indent=2, sort_keys=True)
    except Exception:
        b_pretty = b

    diff = difflib.unified_diff(
        a_pretty.splitlines(keepends=True),
        b_pretty.splitlines(keepends=True),
        fromfile="scan #%d" % args.scan_a,
        tofile="scan #%d" % args.scan_b,
        n=3,
    )
    sys.stdout.write("".join(diff))


def cmd_export(args):
    conn = _db(args.db)
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM scans WHERE scan_id = ?", (args.scan_id,)
    )
    row = cur.fetchone()
    if row is None:
        print("No such scan: %d" % args.scan_id, file=sys.stderr)
        sys.exit(1)
    columns = [d[0] for d in cur.description]
    record = dict(zip(columns, row))

    for key, value in record.items():
        if isinstance(value, bytes):
            record[key] = value.hex()
    print(json.dumps(record, indent=2, default=str))


def cmd_schema(args):
    conn = _db(args.db)
    cur = conn.cursor()
    cur.execute(
        "SELECT sql FROM sqlite_master WHERE type IN ('table', 'index') "
        "ORDER BY type, name"
    )
    for row in cur.fetchall():
        if row[0]:
            print(row[0] + ";")
            print("")


def cmd_repair(args):
    """
    Re-parse every stored response body and backfill TotalNFCCount /
    Material / troy_ounces_per_unit columns on the scans and
    product_records tables. Useful after upgrading from an older oracle
    that didn't capture those values at scan time.
    """
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mintid_oracle import Oracle

    oracle = Oracle(args.db)
    print("Running backfill against " + os.path.abspath(args.db))
    summary = oracle.backfill_from_stored_responses()
    print("Done.")
    print("  Scans examined            : %d" % summary["scans_total"])
    print("  Scans updated             : %d" % summary["scans_updated"])
    print("  Product records examined  : %d" % summary["product_records_total"])
    print("  Product records updated   : %d" % summary["product_records_updated"])
    print("  Unparseable responses     : %d" % summary["unparseable_responses"])
    if summary["product_records_updated"] > 0:
        print("")
        print("Run `mintid_oracle_cli.py summary` to see the refreshed table.")
    oracle.close()


def cmd_chips(args):
    """List every distinct chip we've ever scanned, with chip-side facts."""
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mintid_oracle import Oracle
    oracle = Oracle(args.db)
    rows = oracle.get_chip_summaries()
    if not rows:
        print("(no chip_summary rows; run a scan or `chips-repair`.)")
        oracle.close()
        return

    print("%-17s  %-8s  %-23s  %-12s  %-7s  %-5s  %-7s" % (
        "UID", "UID len", "Manufacturer", "Family", "NXP UID", "SIG", "Seen"
    ))
    print("-" * 90)
    for r in rows:
        full = r["full_summary"] or {}
        uid_info = full.get("uid", {})
        family = r["get_version_chip_family"] or "-"
        print("%-17s  %-8d  %-23s  %-12s  %-7s  %-5s  %-7d" % (
            r["chip_uid"],
            uid_info.get("uid_length_bytes", 0),
            (r["uid_manufacturer_name"] or "-")[:23],
            family[:12],
            "yes" if r["uid_appears_to_be_real_nxp"] else "no",
            "yes" if r["read_sig_succeeded"] else "no",
            r["seen_count"],
        ))
    oracle.close()


def cmd_chip(args):
    """Show full chip summary for one UID."""
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mintid_oracle import Oracle
    from mintid_chip_summary import format_chip_summary
    oracle = Oracle(args.db)
    rows = oracle.get_chip_summaries(args.uid.upper())
    if not rows:
        print("No chip summary recorded for UID " + args.uid.upper())
        oracle.close()
        return
    for i, r in enumerate(rows):
        if i > 0:
            print("")
        print("# Summary version %d/%d, dump SHA %s" % (
            i + 1, len(rows), r["full_dump_sha256"][:16] + "..."
        ))
        print("# First seen %s, last seen %s, count %d" % (
            r["first_seen_at"], r["last_seen_at"], r["seen_count"]
        ))
        if r["full_summary"]:
            print(format_chip_summary(r["full_summary"]))
    oracle.close()


def cmd_chips_repair(args):
    """
    Walk every scan that has chip_pages_bytes stored and rebuild the
    chip_summaries table from those dumps. Useful after upgrading from a
    pre-chip-summary oracle (the dumps were captured but never analysed).
    """
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mintid_oracle import Oracle
    from mintid_chip_summary import build_chip_summary
    oracle = Oracle(args.db)
    cur = oracle.connection.cursor()
    cur.execute(
        "SELECT DISTINCT chip_uid, chip_uid_bytes, chip_pages_bytes "
        "FROM scans WHERE chip_pages_bytes IS NOT NULL"
    )
    rows = cur.fetchall()
    print("Found %d unique scan(uid, dump) pairs to analyse." % len(rows))
    inserted = 0
    for chip_uid, uid_bytes, pages_bytes in rows:
        if not uid_bytes or not pages_bytes:
            continue
        summary = build_chip_summary(
            bytes(uid_bytes), bytes(pages_bytes), transmit_fn=None
        )
        result = oracle.record_chip_summary(chip_uid, summary)
        if result is not None:
            inserted += 1
    print("Recorded/updated %d chip_summary rows." % inserted)
    oracle.close()


def cmd_export_bin(args):
    """Export a chip's memory dump as a binary file.

    Produces a raw .bin file with the chip's pages concatenated, suitable
    for:
      * Proxmark 3:  hf mfu restore -f <file>.bin
      * MTools (Android): load dump
      * NFC Tools Pro (Android): write tag from dump
      * Chameleon Mini/Tiny: load slot via app

    The output file is just the concatenated bytes of pages 0..N as
    captured. For the genuine NXP coins this is 64 bytes (16 pages); for
    the clone it's 256 bytes (64 pages). If --pad-to-ntag213 is given,
    pads to NTAG 213's full 180 bytes (45 pages) by appending zeros so
    PM3's mfu restore won't complain about size mismatch.

    SAFETY NOTE: this exports the raw chip bytes. Writing this onto a
    magic chip and tapping it against the MintID app will produce a
    successful authentication. Use only for research on coins you own.
    """
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mintid_oracle import Oracle

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
    out_bytes = bytearray(pages_bytes)

    if args.pad_to_ntag213:
        target_size = 180  # NTAG 213 total memory
        if len(out_bytes) < target_size:
            out_bytes.extend(b"\x00" * (target_size - len(out_bytes)))
        elif len(out_bytes) > target_size:
            print("Warning: chip dump (%d bytes) is LARGER than NTAG 213 "
                  "size (180 bytes). Truncating may lose data. Use "
                  "without --pad-to-ntag213 to keep full %d bytes." % (
                      len(out_bytes), len(out_bytes)
                  ))
            return

    output_path = args.output or "%s.bin" % args.uid.upper()
    with open(output_path, "wb") as f:
        f.write(bytes(out_bytes))

    print("Wrote %d bytes to %s" % (len(out_bytes), output_path))
    print("UID embedded in dump: " + uid_bytes.hex().upper())
    print("")
    print("To write this onto a magic NTAG 213 / Ultralight-C with Proxmark 3:")
    print("  hf 14a info")
    print("  hf mfu setuid --uid %s" % uid_bytes.hex().upper())
    print("  hf mfu restore -f %s" % output_path)
    print("")
    print("To verify after writing:")
    print("  hf mfu dump -f verify_dump")
    print("  diff %s verify_dump.bin" % output_path)
    print("")
    print("To write via Android (MTools / NFC Tools Pro):")
    print("  Load the .bin file as a dump, place phone over magic tag,")
    print("  app will write all pages including UID.")

    oracle.close()


def cmd_dump(args):
    """Show the raw chip dump bytes for a UID, alongside parser
    interpretations. Useful for understanding why TLV parsing finds
    different things on different chips."""
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mintid_oracle import Oracle

    oracle = Oracle(args.db)
    cur = oracle.connection.cursor()
    cur.execute(
        "SELECT chip_uid_bytes, chip_pages_bytes, chip_ndef_text "
        "FROM scans WHERE chip_uid = ? AND chip_pages_bytes IS NOT NULL "
        "ORDER BY scan_id DESC LIMIT 1",
        (args.uid.upper(),)
    )
    row = cur.fetchone()
    if row is None:
        print("No dump in DB for UID " + args.uid.upper())
        oracle.close()
        return
    uid_bytes, pages_bytes, ndef_text = bytes(row[0]), bytes(row[1]), row[2]

    print("UID: " + uid_bytes.hex().upper() + " (%d bytes)" % len(uid_bytes))
    print("Dump: %d bytes" % len(pages_bytes))
    print("Cryptogram extracted by simulator: " + repr(ndef_text))
    print("")

    print("Hex dump (page-by-page):")
    print("Page  Off   Bytes (hex)        ASCII")
    print("-" * 60)
    for page_idx in range(len(pages_bytes) // 4):
        start = page_idx * 4
        bs = pages_bytes[start:start+4]
        ascii_repr = "".join(
            chr(b) if 0x20 <= b < 0x7F else "." for b in bs
        )
        print("%4d  %3d   %s          %s" % (
            page_idx, start, bs.hex().upper(), ascii_repr
        ))
        if page_idx >= 16 and all(b == 0 for b in bs):
            # Stop showing trailing zeros
            remaining = (len(pages_bytes) // 4) - page_idx - 1
            if remaining > 0:
                print("...   (%d more pages, all zeros)" % remaining)
            break

    print("")
    # Find where 0x03 (NDEF TLV tag) appears in the first 32 bytes
    print("Searches for NDEF markers in first 32 bytes:")
    search_window = pages_bytes[:32]
    for offset in range(len(search_window)):
        b = search_window[offset]
        if b == 0x03:
            length_byte = search_window[offset+1] if offset+1 < len(search_window) else None
            print("  offset %2d: 0x03 (NDEF_MESSAGE_TLV)%s" % (
                offset,
                ", followed by length=0x%02X (%d)" % (length_byte, length_byte)
                if length_byte is not None else ""
            ))
        elif b == 0xE1:
            print("  offset %2d: 0xE1 (NDEF Forum CC magic byte)" % offset)
        elif b == 0xD1:
            print("  offset %2d: 0xD1 (NDEF Record header: MB+ME+SR+TNF=Well-known)" % offset)
        elif b == 0xFE:
            print("  offset %2d: 0xFE (TERMINATOR_TLV)" % offset)

    print("")
    # If the cryptogram is in the dump as ASCII, find it
    crypto_bytes = ndef_text.encode("utf-8") if ndef_text else b""
    if crypto_bytes:
        idx = pages_bytes.find(crypto_bytes)
        if idx >= 0:
            print("Cryptogram ASCII bytes appear at offset %d in the dump." % idx)
            # Show 8 bytes of context before
            ctx_start = max(0, idx - 8)
            print("Context (offsets %d..%d):" % (ctx_start, idx + len(crypto_bytes) - 1))
            print("  " + pages_bytes[ctx_start:idx+len(crypto_bytes)].hex(" ").upper())
            print("  " + " " * (3 * (idx - ctx_start)) +
                  ("^^ " * len(crypto_bytes)))
        else:
            print("Cryptogram ASCII bytes NOT FOUND in raw dump.")
            print("(Maybe encoded as UTF-16, or simulator extracted from elsewhere.)")
            crypto_utf16 = ndef_text.encode("utf-16-le")
            idx = pages_bytes.find(crypto_utf16)
            if idx >= 0:
                print("Found as UTF-16-LE at offset %d." % idx)
    oracle.close()


def cmd_summary(args):
    """
    Print per-product totals: TotalNFCCount, troy ounces per coin, total
    troy ounces issued, and how many of each you've personally scanned.
    """
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from mintid_oracle import Oracle

    oracle = Oracle(args.db)
    summary = oracle.get_catalog_summary()
    products = summary["products"]

    if not products:
        print("(no product records yet)")
        oracle.close()
        return

    name_w = max(35, max(len(p["product_name"] or "-") for p in products))
    sku_w  = max(16, max(len(p["sku"] or "-") for p in products))
    mat_w  = max(13, max(len(p["material"] or "-") for p in products))

    fmt = (
        "  %-" + str(name_w) + "s  "
        "%-" + str(sku_w) + "s  "
        "%-" + str(mat_w) + "s  "
        "%12s  %15s  %18s  %10s"
    )
    header = fmt % (
        "Product", "SKU", "Material",
        "Oz/coin", "TotalNFCCount", "Total Oz Issued", "Your Scans",
    )
    rule = "  " + "-" * (len(header) - 2)

    print("=== MintID Catalog Summary (your local oracle) ===")
    print("")
    print(header)
    print(rule)
    for p in products:
        ounces_per = p["troy_ounces_per_unit"]
        nfc_count = p["total_nfc_count"]
        total_oz = p["total_troy_ounces_issued"]
        print(fmt % (
            (p["product_name"] or "-")[:name_w],
            (p["sku"] or "-")[:sku_w],
            (p["material"] or "-")[:mat_w],
            ("%.3f" % ounces_per) if ounces_per is not None else "-",
            ("{:,}".format(nfc_count)) if nfc_count is not None else "-",
            ("{:,.3f}".format(total_oz)) if total_oz is not None else "-",
            "{:,}".format(p["your_scan_count"]),
        ))
    print(rule)

    total_count = summary["total_nfc_count_sum"]
    total_oz = summary["total_troy_ounces_sum"]
    print(fmt % (
        "TOTAL", "", "", "",
        ("{:,}".format(total_count)) if total_count is not None else "-",
        ("{:,.3f}".format(total_oz)) if total_oz is not None else "-",
        "{:,}".format(summary["your_scan_count"]),
    ))
    print("")
    print("Notes:")
    print("  * 'Oz/coin' is parsed from each product's Material field. "
          "Products whose Material we can't parse show '-' here.")
    print("  * 'TotalNFCCount' is what MintID's server reports as the "
          "number of chips personalized for that product. We use the most "
          "recently observed value.")
    print("  * 'Total Oz Issued' = TotalNFCCount * Oz/coin, when both "
          "are known.")
    print("  * 'Your Scans' is the number of times you've scanned a coin "
          "matching that product (across all UIDs).")
    oracle.close()


def main():
    parser = argparse.ArgumentParser(
        description="Inspect the MintID oracle SQLite DB."
    )
    parser.add_argument(
        "--db",
        default="mintid_oracle.db",
        help="Path to the SQLite oracle database (default: ./mintid_oracle.db).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List all scanned coins.").set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Show full history for a UID.")
    p_show.add_argument("uid", help="Chip UID (uppercase hex, no separators).")
    p_show.set_defaults(func=cmd_show)

    sub.add_parser("products", help="List product records.").set_defaults(
        func=cmd_products
    )

    p_product = sub.add_parser(
        "product", help="Show all versions of a product record."
    )
    p_product.add_argument("product_id")
    p_product.add_argument(
        "--full", action="store_true",
        help="Print the full JSON of each version."
    )
    p_product.set_defaults(func=cmd_product)

    p_diff = sub.add_parser("diff", help="Diff two scans by scan_id.")
    p_diff.add_argument("scan_a", type=int)
    p_diff.add_argument("scan_b", type=int)
    p_diff.set_defaults(func=cmd_diff)

    p_export = sub.add_parser(
        "export", help="Print a single scan's full record as JSON."
    )
    p_export.add_argument("scan_id", type=int)
    p_export.set_defaults(func=cmd_export)

    sub.add_parser("schema", help="Print SQLite schema.").set_defaults(
        func=cmd_schema
    )

    sub.add_parser(
        "summary",
        help="Per-product TotalNFCCount, ounces, and your scan counts.",
    ).set_defaults(func=cmd_summary)

    sub.add_parser(
        "repair",
        help="Re-parse stored response bodies and backfill columns that "
             "were NULL because of an older oracle version.",
    ).set_defaults(func=cmd_repair)

    sub.add_parser(
        "chips",
        help="List all chips with their chip-side facts (UID family, "
             "manufacturer, NXP-vs-clone, etc).",
    ).set_defaults(func=cmd_chips)

    p_chip = sub.add_parser(
        "chip",
        help="Show the full chip summary for one UID.",
    )
    p_chip.add_argument("uid", help="Chip UID (uppercase hex).")
    p_chip.set_defaults(func=cmd_chip)

    sub.add_parser(
        "chips-repair",
        help="Rebuild chip_summaries table from chip_pages_bytes already "
             "stored in the scans table. Use after upgrading from an "
             "older oracle.",
    ).set_defaults(func=cmd_chips_repair)

    p_dump = sub.add_parser(
        "dump",
        help="Show raw hex dump for a UID with NDEF marker locations."
    )
    p_dump.add_argument("uid", help="Chip UID (uppercase hex).")
    p_dump.set_defaults(func=cmd_dump)

    p_export = sub.add_parser(
        "export-bin",
        help="Export a chip's memory dump as a binary file for PM3 / "
             "MTools / Chameleon."
    )
    p_export.add_argument("uid", help="Chip UID (uppercase hex).")
    p_export.add_argument("--output", "-o", help="Output filename "
                          "(default: <UID>.bin)")
    p_export.add_argument("--pad-to-ntag213", action="store_true",
                          help="Pad dump to NTAG 213's full 180-byte size "
                               "by appending zeros. Some PM3 commands "
                               "expect a specific size.")
    p_export.set_defaults(func=cmd_export_bin)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
