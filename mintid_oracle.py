"""
mintid_oracle.py — local SQLite oracle for MintID coin scans.

Records every chip read and server interaction:
  - Chip reads:    UID, raw page bytes, NDEF text payload, scan timestamp
  - Server I/O:    full request body bytes, full response body bytes, headers,
                   HTTP status, request/response timestamps

When a coin is scanned, the oracle reports:
  - Whether we've ever seen this UID before
  - Whether the chip's NDEF content matches what we saw last time
    (would catch chip-rewrites or cloning to a different UID)
  - Whether the server's response matches what we saw last time
    (would catch deactivation, re-personalization, product record edits)
  - History summary: how many times scanned, first seen, last seen,
    extracted product info if a Product record was seen for this coin

Schema:

  scans            One row per scan event. Joins everything together.
  chips            One row per (uid, ndef_text). New row if either changes.
  product_records  One row per (server_product_id, server_product_updated_date).
                   New row each time the server reports a different version of
                   the product (e.g. UpdatedDate changed).
  raw_responses    One row per server response. Stored full so we can re-parse.

Database file defaults to ./mintid_oracle.db in the script's working directory.
"""

import hashlib
import json
import sqlite3
import sys
import time
from collections import OrderedDict
from datetime import datetime, timezone


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_started_at    TEXT NOT NULL,                  -- ISO-8601 UTC
    scan_finished_at   TEXT,                           -- ISO-8601 UTC
    chip_uid           TEXT NOT NULL,                  -- uppercase hex
    chip_uid_bytes     BLOB NOT NULL,
    chip_pages_bytes   BLOB,                           -- full FF B0 dump
    chip_ndef_text     TEXT,                           -- after .trim()
    request_url        TEXT,
    request_headers    TEXT,                           -- JSON
    request_body       TEXT,                           -- exact wire bytes
    request_body_sha256 TEXT,
    response_status    INTEGER,
    response_headers   TEXT,                           -- JSON
    response_body      TEXT,                           -- exact wire bytes
    response_body_sha256 TEXT,
    response_status_code INTEGER,                      -- Result.StatusCode
    response_ntag_tt_status INTEGER,                   -- Result.NTAGTTStatus
    response_tag_number TEXT,                          -- Result.TagNumber
    response_product_id TEXT,                          -- Result.Product._id
    response_product_name TEXT,                        -- Result.Product.ProductName
    response_product_updated_date TEXT,                -- Result.Product.UpdatedDate
    notes              TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_uid ON scans(chip_uid);
CREATE INDEX IF NOT EXISTS idx_scans_ts  ON scans(scan_started_at);

CREATE TABLE IF NOT EXISTS chips (
    chip_uid           TEXT NOT NULL,
    chip_ndef_text     TEXT,
    first_seen_at      TEXT NOT NULL,
    last_seen_at       TEXT NOT NULL,
    seen_count         INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (chip_uid, chip_ndef_text)
);

CREATE TABLE IF NOT EXISTS product_records (
    product_id         TEXT NOT NULL,
    product_updated_date TEXT NOT NULL,
    product_name       TEXT,
    sku                TEXT,
    brand_name         TEXT,
    manufacturer       TEXT,
    material           TEXT,
    purity             TEXT,
    full_record_json   TEXT NOT NULL,
    first_seen_at      TEXT NOT NULL,
    last_seen_at       TEXT NOT NULL,
    seen_count         INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (product_id, product_updated_date)
);

CREATE TABLE IF NOT EXISTS coin_to_product (
    chip_uid           TEXT NOT NULL,
    product_id         TEXT NOT NULL,
    tag_number         TEXT,
    first_seen_at      TEXT NOT NULL,
    last_seen_at       TEXT NOT NULL,
    seen_count         INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (chip_uid, product_id)
);

-- One row per (chip_uid, full_dump_sha256). A new row is inserted when the
-- memory dump changes for the same UID (e.g., chip rewritten).
CREATE TABLE IF NOT EXISTS chip_summaries (
    chip_uid                       TEXT NOT NULL,
    full_dump_sha256               TEXT NOT NULL,
    first_seen_at                  TEXT NOT NULL,
    last_seen_at                   TEXT NOT NULL,
    seen_count                     INTEGER NOT NULL DEFAULT 1,
    uid_length_bytes               INTEGER,
    uid_manufacturer_code_byte     INTEGER,
    uid_manufacturer_name          TEXT,
    uid_appears_to_be_real_nxp     INTEGER,
    cc_present                     INTEGER,
    cc_version_major               INTEGER,
    cc_version_minor               INTEGER,
    cc_storage_size_bytes          INTEGER,
    cc_read_access_open            INTEGER,
    cc_write_access_open           INTEGER,
    cc_raw_hex                     TEXT,
    lock0_byte                     INTEGER,
    lock1_byte                     INTEGER,
    any_static_locks_set           INTEGER,
    static_lock_count              INTEGER,
    pages_total                    INTEGER,
    zero_page_count                INTEGER,
    nonzero_page_count             INTEGER,
    total_dump_bytes               INTEGER,
    get_version_attempted          INTEGER,
    get_version_succeeded          INTEGER,
    get_version_raw_hex            TEXT,
    get_version_chip_family        TEXT,
    read_sig_attempted             INTEGER,
    read_sig_succeeded             INTEGER,
    read_sig_raw_hex               TEXT,
    read_cnt_attempted             INTEGER,
    read_cnt_succeeded             INTEGER,
    read_cnt_value                 INTEGER,
    full_summary_json              TEXT NOT NULL,
    PRIMARY KEY (chip_uid, full_dump_sha256)
);
"""

# Columns added in later iterations; applied as ALTER TABLE so an existing
# DB from an earlier run gets upgraded in place.
SCHEMA_MIGRATIONS = [
    "ALTER TABLE scans ADD COLUMN response_total_nfc_count INTEGER",
    "ALTER TABLE scans ADD COLUMN response_material TEXT",
    "ALTER TABLE product_records ADD COLUMN total_nfc_count INTEGER",
    "ALTER TABLE product_records ADD COLUMN troy_ounces_per_unit REAL",
]


import re

_MATERIAL_PATTERN = re.compile(
    r"^\s*(?P<num>\d+(?:\.\d+)?|\d+/\d+)\s*"
    r"(?P<unit>troy\s*ounces?|ounces?|oz|grams?|g|kilograms?|kg|kilos?)\s*$",
    re.IGNORECASE,
)
_GRAMS_PER_TROY_OUNCE = 31.1034768


def parse_material_to_troy_ounces(material):
    """
    Parse strings like '1 Troy Ounce', '5 Troy Ounces', '0.5 oz', '100g',
    '1 kg', '1/2 Troy Ounce' into a float number of troy ounces.

    Returns None if the material string is empty, None, or doesn't match a
    recognised pattern. We deliberately keep the parser conservative -- if we
    don't recognise the format we return None rather than guess, since the
    'total ounces issued' aggregation should NOT silently fold unparseable
    rows into zero.
    """
    if not material:
        return None
    match = _MATERIAL_PATTERN.match(material)
    if not match:
        return None
    num_str = match.group("num")
    if "/" in num_str:
        numerator, denominator = num_str.split("/")
        value = float(numerator) / float(denominator)
    else:
        value = float(num_str)
    unit = match.group("unit").lower().replace(" ", "")
    if unit in ("troyounce", "troyounces", "ounce", "ounces", "oz"):
        return value
    if unit in ("gram", "grams", "g"):
        return value / _GRAMS_PER_TROY_OUNCE
    if unit in ("kilogram", "kilograms", "kg", "kilo", "kilos"):
        return value * 1000.0 / _GRAMS_PER_TROY_OUNCE
    return None


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256_hex(data):
    if data is None:
        return None
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class Oracle:
    """Local SQLite-backed scan oracle."""

    def __init__(self, db_path):
        self.db_path = db_path
        self.connection = sqlite3.connect(db_path)
        self.connection.executescript(SCHEMA)
        for migration in SCHEMA_MIGRATIONS:
            try:
                self.connection.execute(migration)
            except sqlite3.OperationalError:
                # Column already present; harmless on an upgraded DB.
                pass
        self.connection.commit()

    # -- read-side queries (used to report what we know before a request) ----

    def lookup_chip(self, chip_uid_uppercase, current_ndef_text):
        """
        Return a dict describing what we know about this UID:
          previously_seen      : bool
          ndef_unchanged       : bool (or None if not previously seen)
          previous_ndef_text   : the last NDEF text we recorded for this UID
                                  (or None)
          first_seen_at        : ISO timestamp of earliest scan record (or None)
          last_seen_at         : ISO timestamp of most recent scan record
                                  (or None)
          total_scans          : int
          known_products       : list of (product_id, product_name, tag_number,
                                          seen_count) tuples for this UID
        """
        cur = self.connection.cursor()
        cur.execute(
            "SELECT COUNT(*), MIN(scan_started_at), MAX(scan_started_at) "
            "FROM scans WHERE chip_uid = ?",
            (chip_uid_uppercase,),
        )
        total, first_seen, last_seen = cur.fetchone()
        if total == 0:
            return {
                "previously_seen": False,
                "ndef_unchanged": None,
                "previous_ndef_text": None,
                "first_seen_at": None,
                "last_seen_at": None,
                "total_scans": 0,
                "known_products": [],
            }

        cur.execute(
            "SELECT chip_ndef_text FROM scans "
            "WHERE chip_uid = ? AND chip_ndef_text IS NOT NULL "
            "ORDER BY scan_started_at DESC LIMIT 1",
            (chip_uid_uppercase,),
        )
        row = cur.fetchone()
        previous_ndef = row[0] if row else None

        cur.execute(
            "SELECT product_id, MAX(tag_number), SUM(seen_count) "
            "FROM coin_to_product WHERE chip_uid = ? GROUP BY product_id",
            (chip_uid_uppercase,),
        )
        product_rows = cur.fetchall()
        known_products = []
        for product_id, tag_number, scan_count in product_rows:
            cur.execute(
                "SELECT product_name FROM product_records "
                "WHERE product_id = ? "
                "ORDER BY last_seen_at DESC LIMIT 1",
                (product_id,),
            )
            name_row = cur.fetchone()
            product_name = name_row[0] if name_row else None
            known_products.append(
                {
                    "product_id": product_id,
                    "product_name": product_name,
                    "tag_number": tag_number,
                    "seen_count": scan_count,
                }
            )

        return {
            "previously_seen": True,
            "ndef_unchanged": (
                previous_ndef == current_ndef_text
                if previous_ndef is not None
                else None
            ),
            "previous_ndef_text": previous_ndef,
            "first_seen_at": first_seen,
            "last_seen_at": last_seen,
            "total_scans": total,
            "known_products": known_products,
        }

    def lookup_product_record_history(self, product_id):
        """Return all distinct product-record versions we've recorded."""
        cur = self.connection.cursor()
        cur.execute(
            "SELECT product_updated_date, product_name, sku, manufacturer, "
            "first_seen_at, last_seen_at, seen_count "
            "FROM product_records WHERE product_id = ? "
            "ORDER BY product_updated_date",
            (product_id,),
        )
        return [
            {
                "product_updated_date": row[0],
                "product_name": row[1],
                "sku": row[2],
                "manufacturer": row[3],
                "first_seen_at": row[4],
                "last_seen_at": row[5],
                "seen_count": row[6],
            }
            for row in cur.fetchall()
        ]

    # -- write-side: record one scan -----------------------------------------

    def begin_scan(self, chip_uid_bytes, chip_pages_bytes, chip_ndef_text):
        """
        Start a scan record, recording chip-side data immediately so we have
        it even if the server request fails. Returns scan_id.
        """
        scan_started_at = _now_iso()
        chip_uid = chip_uid_bytes.hex().upper()

        cur = self.connection.cursor()
        cur.execute(
            "INSERT INTO scans (scan_started_at, chip_uid, chip_uid_bytes, "
            "chip_pages_bytes, chip_ndef_text) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                scan_started_at,
                chip_uid,
                chip_uid_bytes,
                chip_pages_bytes,
                chip_ndef_text,
            ),
        )
        scan_id = cur.lastrowid

        # Update the chips table (composite key (uid, ndef_text)).
        cur.execute(
            "INSERT INTO chips (chip_uid, chip_ndef_text, first_seen_at, "
            "last_seen_at, seen_count) VALUES (?, ?, ?, ?, 1) "
            "ON CONFLICT(chip_uid, chip_ndef_text) DO UPDATE SET "
            "last_seen_at = excluded.last_seen_at, "
            "seen_count = chips.seen_count + 1",
            (chip_uid, chip_ndef_text, scan_started_at, scan_started_at),
        )

        self.connection.commit()
        return scan_id

    def record_request(self, scan_id, url, headers, body_string):
        """Record the outgoing request bytes."""
        body_bytes = body_string.encode("utf-8")
        cur = self.connection.cursor()
        cur.execute(
            "UPDATE scans SET request_url = ?, request_headers = ?, "
            "request_body = ?, request_body_sha256 = ? WHERE scan_id = ?",
            (
                url,
                json.dumps(dict(headers)),
                body_string,
                _sha256_hex(body_bytes),
                scan_id,
            ),
        )
        self.connection.commit()

    def record_response(
        self,
        scan_id,
        chip_uid,
        http_status,
        response_headers,
        response_body_string,
    ):
        """
        Record the server response, parse out salient Result.Product fields,
        and update product_records / coin_to_product tables. Returns a dict
        describing what changed compared to previous scans of this coin.
        """
        scan_finished_at = _now_iso()
        body_bytes = response_body_string.encode("utf-8")
        body_sha256 = _sha256_hex(body_bytes)

        result_status_code = None
        result_ntagtt = None
        result_tag_number = None
        product_id = None
        product_name = None
        product_updated_date = None
        product_block = None
        total_nfc_count = None
        product_material = None
        troy_ounces_per_unit = None
        try:
            parsed = json.loads(response_body_string)
            result = parsed.get("Result") or {}
            result_status_code = parsed.get("StatusCode")
            result_ntagtt = result.get("NTAGTTStatus")
            result_tag_number = result.get("TagNumber") or None
            product_block = result.get("Product")
            if product_block:
                product_id = product_block.get("_id")
                product_name = product_block.get("ProductName")
                product_updated_date = product_block.get("UpdatedDate")
                total_nfc_count = product_block.get("TotalNFCCount")
                product_material = product_block.get("Material")
                troy_ounces_per_unit = parse_material_to_troy_ounces(
                    product_material
                )
        except Exception:
            pass

        cur = self.connection.cursor()
        cur.execute(
            "UPDATE scans SET scan_finished_at = ?, response_status = ?, "
            "response_headers = ?, response_body = ?, response_body_sha256 = ?, "
            "response_status_code = ?, response_ntag_tt_status = ?, "
            "response_tag_number = ?, response_product_id = ?, "
            "response_product_name = ?, response_product_updated_date = ?, "
            "response_total_nfc_count = ?, response_material = ? "
            "WHERE scan_id = ?",
            (
                scan_finished_at,
                http_status,
                json.dumps(dict(response_headers)) if response_headers else None,
                response_body_string,
                body_sha256,
                result_status_code,
                result_ntagtt,
                result_tag_number,
                product_id,
                product_name,
                product_updated_date,
                total_nfc_count,
                product_material,
                scan_id,
            ),
        )

        diff_summary = {
            "is_first_scan": True,
            "ntag_tt_status_changed": False,
            "product_id_changed": False,
            "product_record_changed": False,
            "previous_product_id": None,
            "previous_ntag_tt_status": None,
            "previous_response_sha256": None,
            "current_product_id": product_id,
            "current_ntag_tt_status": result_ntagtt,
            "current_product_name": product_name,
            "current_tag_number": result_tag_number,
            "current_response_sha256": body_sha256,
        }

        cur.execute(
            "SELECT response_product_id, response_ntag_tt_status, "
            "response_body_sha256 FROM scans "
            "WHERE chip_uid = ? AND scan_id < ? "
            "ORDER BY scan_id DESC LIMIT 1",
            (chip_uid, scan_id),
        )
        previous = cur.fetchone()
        if previous is not None:
            diff_summary["is_first_scan"] = False
            (
                prev_product_id,
                prev_ntag_tt,
                prev_response_sha,
            ) = previous
            diff_summary["previous_product_id"] = prev_product_id
            diff_summary["previous_ntag_tt_status"] = prev_ntag_tt
            diff_summary["previous_response_sha256"] = prev_response_sha
            diff_summary["ntag_tt_status_changed"] = (
                prev_ntag_tt != result_ntagtt
            )
            diff_summary["product_id_changed"] = (
                prev_product_id != product_id
            )
            diff_summary["product_record_changed"] = (
                prev_response_sha != body_sha256
            )

        # Update product_records (composite key on (id, updated_date)).
        if product_block and product_id and product_updated_date:
            full_record_json = json.dumps(product_block, sort_keys=True)
            cur.execute(
                "INSERT INTO product_records (product_id, "
                "product_updated_date, product_name, sku, brand_name, "
                "manufacturer, material, purity, full_record_json, "
                "first_seen_at, last_seen_at, seen_count, "
                "total_nfc_count, troy_ounces_per_unit) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?) "
                "ON CONFLICT(product_id, product_updated_date) DO UPDATE SET "
                "last_seen_at = excluded.last_seen_at, "
                "seen_count = product_records.seen_count + 1, "
                "total_nfc_count = excluded.total_nfc_count, "
                "troy_ounces_per_unit = excluded.troy_ounces_per_unit",
                (
                    product_id,
                    product_updated_date,
                    product_block.get("ProductName"),
                    product_block.get("SKU"),
                    product_block.get("BrandName"),
                    product_block.get("Manufacturer"),
                    product_block.get("Material"),
                    product_block.get("Purity"),
                    full_record_json,
                    scan_finished_at,
                    scan_finished_at,
                    total_nfc_count,
                    troy_ounces_per_unit,
                ),
            )

            cur.execute(
                "INSERT INTO coin_to_product (chip_uid, product_id, "
                "tag_number, first_seen_at, last_seen_at, seen_count) "
                "VALUES (?, ?, ?, ?, ?, 1) "
                "ON CONFLICT(chip_uid, product_id) DO UPDATE SET "
                "last_seen_at = excluded.last_seen_at, "
                "tag_number = COALESCE(excluded.tag_number, "
                "coin_to_product.tag_number), "
                "seen_count = coin_to_product.seen_count + 1",
                (
                    chip_uid,
                    product_id,
                    result_tag_number,
                    scan_finished_at,
                    scan_finished_at,
                ),
            )

        self.connection.commit()
        return diff_summary

    # -- maintenance ---------------------------------------------------------

    def annotate(self, scan_id, note):
        cur = self.connection.cursor()
        cur.execute(
            "UPDATE scans SET notes = COALESCE(notes || char(10), '') || ? "
            "WHERE scan_id = ?",
            (note, scan_id),
        )
        self.connection.commit()

    def get_catalog_summary(self):
        """
        Return aggregate statistics across every product we've ever queried.

        Structure:
            {
                "products": [
                    {
                        "product_id": str,
                        "product_name": str,
                        "sku": str,
                        "manufacturer": str,
                        "material": str,
                        "troy_ounces_per_unit": float | None,
                        "total_nfc_count": int | None,
                        "total_troy_ounces_issued": float | None,
                        "your_scan_count": int,
                        "first_seen_at": str,
                        "last_seen_at": str,
                        "versions_seen": int,
                    },
                    ...
                ],
                "total_nfc_count_sum": int | None,
                "total_troy_ounces_sum": float | None,
                "your_scan_count": int,
            }

        We use the LATEST product_record version (most recent UpdatedDate)
        for the count and ounces fields, on the assumption that MintID's
        TotalNFCCount only ever increases as more chips are personalised.
        Older versions are still in product_records for forensic purposes
        but the latest is the most accurate "as of" number.
        """
        cur = self.connection.cursor()
        cur.execute(
            "SELECT product_id, MAX(product_updated_date) "
            "FROM product_records GROUP BY product_id"
        )
        latest_versions = dict(cur.fetchall())

        products = []
        total_count_sum = 0
        total_ounces_sum = 0.0
        any_count_known = False
        any_ounces_known = False
        total_your_scans = 0

        for product_id, latest_updated_date in latest_versions.items():
            cur.execute(
                "SELECT product_name, sku, manufacturer, material, "
                "troy_ounces_per_unit, total_nfc_count, first_seen_at, "
                "last_seen_at FROM product_records "
                "WHERE product_id = ? AND product_updated_date = ?",
                (product_id, latest_updated_date),
            )
            row = cur.fetchone()
            if row is None:
                continue
            (product_name, sku, manufacturer, material,
             troy_ounces_per_unit, total_nfc_count,
             first_seen_at, last_seen_at) = row

            cur.execute(
                "SELECT COUNT(*) FROM product_records WHERE product_id = ?",
                (product_id,),
            )
            versions_seen = cur.fetchone()[0]

            cur.execute(
                "SELECT COALESCE(SUM(seen_count), 0) FROM coin_to_product "
                "WHERE product_id = ?",
                (product_id,),
            )
            your_scan_count = cur.fetchone()[0]
            total_your_scans += your_scan_count

            total_troy_ounces_issued = None
            if total_nfc_count is not None and troy_ounces_per_unit is not None:
                total_troy_ounces_issued = (
                    float(total_nfc_count) * float(troy_ounces_per_unit)
                )

            if total_nfc_count is not None:
                total_count_sum += total_nfc_count
                any_count_known = True
            if total_troy_ounces_issued is not None:
                total_ounces_sum += total_troy_ounces_issued
                any_ounces_known = True

            products.append({
                "product_id": product_id,
                "product_name": product_name,
                "sku": sku,
                "manufacturer": manufacturer,
                "material": material,
                "troy_ounces_per_unit": troy_ounces_per_unit,
                "total_nfc_count": total_nfc_count,
                "total_troy_ounces_issued": total_troy_ounces_issued,
                "your_scan_count": your_scan_count,
                "first_seen_at": first_seen_at,
                "last_seen_at": last_seen_at,
                "versions_seen": versions_seen,
            })

        products.sort(
            key=lambda p: (p["total_nfc_count"] or 0),
            reverse=True,
        )

        return {
            "products": products,
            "total_nfc_count_sum": total_count_sum if any_count_known else None,
            "total_troy_ounces_sum": total_ounces_sum if any_ounces_known else None,
            "your_scan_count": total_your_scans,
        }

    def backfill_from_stored_responses(self):
        """
        Re-parse every stored response_body and backfill the count/ounces
        columns on both the scans table and the product_records table.

        Useful when you've upgraded the oracle from an older version that
        didn't capture TotalNFCCount/Material/troy_ounces_per_unit, but the
        full response bytes are still in the DB. Idempotent.

        Returns a summary dict:
            {
                "scans_total":              int,
                "scans_updated":            int,
                "product_records_total":    int,
                "product_records_updated":  int,
                "unparseable_responses":    int,
            }
        """
        cur = self.connection.cursor()
        result = {
            "scans_total": 0,
            "scans_updated": 0,
            "product_records_total": 0,
            "product_records_updated": 0,
            "unparseable_responses": 0,
        }

        # Pass 1: refill scans rows.
        cur.execute(
            "SELECT scan_id, response_body, response_total_nfc_count, "
            "response_material FROM scans WHERE response_body IS NOT NULL"
        )
        scan_rows = cur.fetchall()
        result["scans_total"] = len(scan_rows)

        for scan_id, body, existing_count, existing_material in scan_rows:
            try:
                parsed = json.loads(body)
            except Exception:
                result["unparseable_responses"] += 1
                continue
            product = (parsed.get("Result") or {}).get("Product") or {}
            new_count = product.get("TotalNFCCount")
            new_material = product.get("Material")
            if (new_count != existing_count) or \
               (new_material != existing_material):
                cur.execute(
                    "UPDATE scans SET response_total_nfc_count = ?, "
                    "response_material = ? WHERE scan_id = ?",
                    (new_count, new_material, scan_id),
                )
                result["scans_updated"] += 1

        # Pass 2: refill product_records rows. We pick the MOST RECENT scan
        # for each (product_id, product_updated_date) pair and use its parsed
        # values to backfill total_nfc_count + troy_ounces_per_unit.
        cur.execute(
            "SELECT product_id, product_updated_date, total_nfc_count, "
            "troy_ounces_per_unit, material FROM product_records"
        )
        pr_rows = cur.fetchall()
        result["product_records_total"] = len(pr_rows)

        for product_id, updated_date, cur_count, cur_ounces, cur_material in pr_rows:
            cur.execute(
                "SELECT response_body FROM scans "
                "WHERE response_product_id = ? "
                "AND response_product_updated_date = ? "
                "AND response_body IS NOT NULL "
                "ORDER BY scan_id DESC LIMIT 1",
                (product_id, updated_date),
            )
            row = cur.fetchone()
            if row is None or row[0] is None:
                continue
            try:
                parsed = json.loads(row[0])
            except Exception:
                continue
            product = (parsed.get("Result") or {}).get("Product") or {}
            new_count = product.get("TotalNFCCount")
            new_material = product.get("Material") or cur_material
            new_ounces = parse_material_to_troy_ounces(new_material)

            if (new_count != cur_count) or \
               (new_ounces != cur_ounces) or \
               (new_material != cur_material):
                cur.execute(
                    "UPDATE product_records SET total_nfc_count = ?, "
                    "troy_ounces_per_unit = ?, material = ? "
                    "WHERE product_id = ? AND product_updated_date = ?",
                    (new_count, new_ounces, new_material,
                     product_id, updated_date),
                )
                result["product_records_updated"] += 1

        self.connection.commit()
        return result

    def record_chip_summary(self, chip_uid_uppercase, summary_dict):
        """
        Persist a chip_summary record. summary_dict is the structure
        produced by mintid_chip_summary.build_chip_summary(). Returns
        the (chip_uid, sha) tuple of the row that was inserted/updated.
        """
        full_sha = summary_dict["page_analysis"].get("full_dump_sha256")
        if not full_sha:
            return None

        ts = _now_iso()
        uid_info = summary_dict["uid"]
        cc = summary_dict["capability_container"]
        locks = summary_dict["lock_bytes"]
        pages = summary_dict["page_analysis"]
        active = summary_dict["active_commands"]
        gv = active.get("get_version", {})
        rs = active.get("read_sig", {})
        rc = active.get("read_cnt", {})
        full_json = json.dumps(summary_dict, sort_keys=True, default=str)

        cur = self.connection.cursor()
        cur.execute(
            "INSERT INTO chip_summaries ("
            "chip_uid, full_dump_sha256, first_seen_at, last_seen_at, "
            "seen_count, uid_length_bytes, uid_manufacturer_code_byte, "
            "uid_manufacturer_name, uid_appears_to_be_real_nxp, "
            "cc_present, cc_version_major, cc_version_minor, "
            "cc_storage_size_bytes, cc_read_access_open, "
            "cc_write_access_open, cc_raw_hex, lock0_byte, lock1_byte, "
            "any_static_locks_set, static_lock_count, pages_total, "
            "zero_page_count, nonzero_page_count, total_dump_bytes, "
            "get_version_attempted, get_version_succeeded, "
            "get_version_raw_hex, get_version_chip_family, "
            "read_sig_attempted, read_sig_succeeded, read_sig_raw_hex, "
            "read_cnt_attempted, read_cnt_succeeded, read_cnt_value, "
            "full_summary_json) "
            "VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(chip_uid, full_dump_sha256) DO UPDATE SET "
            "last_seen_at = excluded.last_seen_at, "
            "seen_count = chip_summaries.seen_count + 1, "
            "full_summary_json = excluded.full_summary_json",
            (
                chip_uid_uppercase, full_sha, ts, ts,
                uid_info.get("uid_length_bytes"),
                uid_info.get("manufacturer_code_byte"),
                uid_info.get("manufacturer_name"),
                1 if uid_info.get("is_real_nxp_uid") else 0,
                1 if cc.get("present") else 0,
                cc.get("version_major"),
                cc.get("version_minor"),
                cc.get("storage_size_bytes_advertised"),
                1 if cc.get("read_access_open") else 0,
                1 if cc.get("write_access_open") else 0,
                cc.get("raw_bytes_hex"),
                locks.get("lock0_byte"),
                locks.get("lock1_byte"),
                1 if locks.get("any_static_locks_set") else 0,
                locks.get("static_lock_count"),
                pages.get("pages_total"),
                pages.get("zero_page_count"),
                pages.get("nonzero_page_count"),
                pages.get("total_dump_bytes"),
                1 if gv.get("attempted") else 0,
                1 if gv.get("succeeded") else 0,
                gv.get("raw_response_hex"),
                (gv.get("decoded") or {}).get("family_name"),
                1 if rs.get("attempted") else 0,
                1 if rs.get("succeeded") else 0,
                rs.get("raw_signature_hex"),
                1 if rc.get("attempted") else 0,
                1 if rc.get("succeeded") else 0,
                rc.get("counter_value"),
                full_json,
            ),
        )
        self.connection.commit()
        return (chip_uid_uppercase, full_sha)

    def get_chip_summaries(self, chip_uid_uppercase=None):
        """
        Return all chip_summary rows, optionally filtered by UID.
        Each row is returned as a dict including the parsed full_summary_json.
        """
        cur = self.connection.cursor()
        if chip_uid_uppercase:
            cur.execute(
                "SELECT chip_uid, full_dump_sha256, first_seen_at, "
                "last_seen_at, seen_count, uid_manufacturer_name, "
                "uid_appears_to_be_real_nxp, get_version_chip_family, "
                "read_sig_succeeded, full_summary_json "
                "FROM chip_summaries WHERE chip_uid = ? "
                "ORDER BY first_seen_at",
                (chip_uid_uppercase,),
            )
        else:
            cur.execute(
                "SELECT chip_uid, full_dump_sha256, first_seen_at, "
                "last_seen_at, seen_count, uid_manufacturer_name, "
                "uid_appears_to_be_real_nxp, get_version_chip_family, "
                "read_sig_succeeded, full_summary_json "
                "FROM chip_summaries ORDER BY chip_uid, first_seen_at"
            )
        out = []
        for row in cur.fetchall():
            (uid, sha, first, last, n, mfr, real_nxp,
             family, rs_ok, full_json) = row
            try:
                parsed = json.loads(full_json)
            except Exception:
                parsed = None
            out.append({
                "chip_uid": uid,
                "full_dump_sha256": sha,
                "first_seen_at": first,
                "last_seen_at": last,
                "seen_count": n,
                "uid_manufacturer_name": mfr,
                "uid_appears_to_be_real_nxp": bool(real_nxp),
                "get_version_chip_family": family,
                "read_sig_succeeded": bool(rs_ok),
                "full_summary": parsed,
            })
        return out

    def close(self):
        self.connection.close()


def format_pre_scan_report(uid_uppercase, ndef_text, lookup):
    """Human-readable summary of what we know about a coin before sending."""
    out = []
    out.append("==== ORACLE: pre-scan report ====")
    out.append("UID: " + uid_uppercase)
    if not lookup["previously_seen"]:
        out.append("This UID has NEVER been scanned before by this oracle.")
        out.append("=" * 33)
        return "\n".join(out)

    out.append(
        "Previously scanned %d time(s)." % lookup["total_scans"]
    )
    out.append("First seen: " + str(lookup["first_seen_at"]))
    out.append("Last seen:  " + str(lookup["last_seen_at"]))

    if lookup["previous_ndef_text"] is None:
        out.append("No previous NDEF text recorded for this UID.")
    elif lookup["ndef_unchanged"]:
        out.append("Chip NDEF text MATCHES previous reads.")
    else:
        out.append("!! Chip NDEF text DIFFERS from previous read !!")
        out.append("    previous: " + repr(lookup["previous_ndef_text"]))
        out.append("    current : " + repr(ndef_text))

    if lookup["known_products"]:
        out.append("Previously linked to product(s):")
        for prod in lookup["known_products"]:
            out.append(
                "  - %s (id=%s) tag_number=%s seen_count=%d"
                % (
                    prod["product_name"] or "?",
                    prod["product_id"],
                    prod["tag_number"] or "?",
                    prod["seen_count"],
                )
            )
    else:
        out.append(
            "No product record has ever been associated with this UID."
        )

    out.append("=" * 33)
    return "\n".join(out)


def format_post_scan_report(diff_summary, catalog_summary=None):
    """Human-readable summary of what changed in this scan vs prior.

    If catalog_summary is provided (a dict from Oracle.get_catalog_summary()),
    a brief 'catalog so far' line is appended at the end.
    """
    out = []
    out.append("==== ORACLE: post-scan report ====")
    if diff_summary["is_first_scan"]:
        out.append("This is the first time we've recorded a server "
                   "response for this UID.")
    elif not diff_summary["ntag_tt_status_changed"] and \
         not diff_summary["product_id_changed"] and \
         not diff_summary["product_record_changed"]:
        out.append("Server response is identical to the previous scan "
                   "(byte-equal).")
    else:
        _append_diff_lines(out, diff_summary)

    if catalog_summary is not None:
        out.append("")
        out.append(_format_catalog_summary_inline(catalog_summary))
    out.append("=" * 34)
    return "\n".join(out)


def _append_diff_lines(out, diff_summary):
    """Append the per-field 'what changed' lines used when not the first
    scan and not byte-equal to the prior response."""

    if diff_summary["ntag_tt_status_changed"]:
        out.append(
            "!! NTAGTTStatus CHANGED: %s -> %s"
            % (
                diff_summary["previous_ntag_tt_status"],
                diff_summary["current_ntag_tt_status"],
            )
        )
    if diff_summary["product_id_changed"]:
        prev_id = diff_summary["previous_product_id"]
        cur_id = diff_summary["current_product_id"]
        cur_name = diff_summary["current_product_name"]
        out.append(
            "!! Product._id CHANGED: %s -> %s%s"
            % (
                prev_id if prev_id else "(no product)",
                cur_id if cur_id else "(no product)",
                (" (" + cur_name + ")") if cur_name else "",
            )
        )
    if diff_summary["product_record_changed"] and \
       not diff_summary["product_id_changed"] and \
       not diff_summary["ntag_tt_status_changed"]:
        out.append(
            "Server response body differs from last scan but the headline "
            "Product._id and NTAGTTStatus are unchanged. The product record "
            "may have been edited (e.g. UpdatedDate, ProductImages, "
            "ProductOutlet). Check product_records table for full history."
        )


def _format_catalog_summary_inline(summary):
    """Compact one-liner version of the catalog summary, for post-scan use."""
    products = summary["products"]
    total_count = summary["total_nfc_count_sum"]
    total_ounces = summary["total_troy_ounces_sum"]
    your_scans = summary["your_scan_count"]
    return (
        "Catalog: %d distinct product(s) seen, %s NFC chips total, "
        "%s troy oz issued, %d scan(s) by you."
        % (
            len(products),
            "{:,}".format(total_count) if total_count is not None else "?",
            "{:,.3f}".format(total_ounces) if total_ounces is not None else "?",
            your_scans,
        )
    )
