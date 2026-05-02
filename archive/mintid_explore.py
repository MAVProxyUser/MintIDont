#!/usr/bin/env python3
"""
mintid_explore.py — probe MintID API endpoints we haven't tested yet.

Decompiled from the APK, these are the known endpoint URLs (Constants.NEW_BASE_URL
prefix is http://mintidapi.droisys.info/api/):

    POST  ProductAuthentication/SecuredScanProduct  (current, takes ProductRequestBody)
    POST  ProductAuthentication/ScanProduct         (legacy, takes String -- the cryptogram)
    POST  Mint/UserRegistration
    GET?  Mint/GetProducyById?                      (note typo + trailing ?, query-string style)
    GET?  Mint/ForgotPassword?
    GET?  Mint/Login?

The trailing `?` on three Mint/* routes is suggestive of `@GET`/`@POST` annotations
with embedded query parameters (the `?` is left in by Retrofit when a method
uses `@Query("...")` to append params). The other three (SecuredScanProduct,
ScanProduct, UserRegistration) lack the trailing `?` so they're plain
JSON-body POSTs.

This script exercises ScanProduct and GetProducyById, and logs everything to
the oracle so we can diff results, replay later, etc. The other three are
authenticated routes (Login/UserRegistration/ForgotPassword) which we don't
need to poke for the disclosure.

USAGE
    python3 mintid_explore.py scan-product <cryptogram>
    python3 mintid_explore.py get-product-by-id <product_id>
    python3 mintid_explore.py probe-all-known
        runs every test we know how to construct against IDs already in
        the oracle DB

For each test, multiple body shapes are tried (since we don't know the exact
Retrofit annotation):
  - Plain JSON-quoted string:       "ABC123..."
  - Field-wrapped JSON object:      {"value": "ABC123..."}
  - ProductRequestBody-shaped:      same body the SecuredScanProduct uses
  - Form-encoded:                   value=ABC123...&...
  - Query string in URL:            ?id=ABC123...
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mintid_oracle import Oracle


BASE_URL = "http://mintidapi.droisys.info/api"

# Same hardcoded guest credentials that every install of the official
# app uses. These are present verbatim in classes2.dex.
HEADERS_GUEST = OrderedDict([
    ("OrgAccessID", "000000000000000000000000"),
    ("AuthorizationKey", "2I0mGELp"),
    ("Content-Type", "application/json"),
    ("User-Agent", "okhttp/3.14.9"),
])

HEADERS_GUEST_FORM = OrderedDict([
    ("OrgAccessID", "000000000000000000000000"),
    ("AuthorizationKey", "2I0mGELp"),
    ("Content-Type", "application/x-www-form-urlencoded"),
    ("User-Agent", "okhttp/3.14.9"),
])


def _do_request(method, url, headers, body_bytes, label):
    """
    Send one request, return (status, response_headers, body_string).
    Print everything for the user. Treat 4xx and 5xx as data, not exceptions.
    """
    print("")
    print("===== " + label + " =====")
    print(method + " " + url)
    for k, v in headers.items():
        print("  " + k + ": " + v)
    if body_bytes:
        print("  Content-Length: " + str(len(body_bytes)))
        try:
            print("")
            print(body_bytes.decode("utf-8"))
        except Exception:
            print(repr(body_bytes))

    request = urllib.request.Request(
        url, data=body_bytes, headers=dict(headers), method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status = response.status
            response_headers = OrderedDict(response.headers.items())
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        response_headers = OrderedDict(exc.headers.items())
        body = exc.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        print("  -> URLError: " + str(exc))
        return None, None, None

    print("")
    print("---- HTTP " + str(status) + " ----")
    for k, v in response_headers.items():
        print("  " + k + ": " + v)
    print("")
    try:
        parsed = json.loads(body)
        print(json.dumps(parsed, indent=2))
    except Exception:
        print(repr(body[:1000]) + ("..." if len(body) > 1000 else ""))
    return status, response_headers, body


def test_scan_product_legacy(cryptogram):
    """
    The legacy `ProductAuthentication/ScanProduct` endpoint, which the older
    `MainActivity.getProductInfo(String)` path calls via
    WebApis.getProductDetail(String).

    The bytecode passes the raw NDEF text content to it, so the body is a
    single string -- but Retrofit + Jackson could serialize that string in
    several ways. Try the three most likely.
    """
    url = BASE_URL + "/ProductAuthentication/ScanProduct"
    results = []

    # Variant 1: JSON-quoted string body.
    body = json.dumps(cryptogram).encode("utf-8")
    results.append(_do_request(
        "POST", url, HEADERS_GUEST, body,
        "ScanProduct (legacy) -- body=JSON-quoted string"
    ))

    # Variant 2: ProductRequestBody-shaped (same as SecuredScanProduct).
    pr_body = OrderedDict([
        ("DeviceID", ""),
        ("DeviceType", "Android"),
        ("Lat", 0.0),
        ("Lon", 0.0),
        ("TagCrypto", cryptogram),
        ("TagProvider", "Identiv"),
        ("TagType", "NFC Tags"),
        ("TagUID", ""),
        ("TagValue", "1234567812345678"),
    ])
    body = json.dumps(pr_body, separators=(",", ":")).encode("utf-8")
    results.append(_do_request(
        "POST", url, HEADERS_GUEST, body,
        "ScanProduct (legacy) -- body=ProductRequestBody shape"
    ))

    # Variant 3: form-urlencoded.
    body = urllib.parse.urlencode({"value": cryptogram}).encode("utf-8")
    results.append(_do_request(
        "POST", url, HEADERS_GUEST_FORM, body,
        "ScanProduct (legacy) -- body=form value=<crypto>"
    ))

    # Variant 4: TagCrypto field only, JSON.
    body = json.dumps({"TagCrypto": cryptogram}).encode("utf-8")
    results.append(_do_request(
        "POST", url, HEADERS_GUEST, body,
        "ScanProduct (legacy) -- body={'TagCrypto': ...}"
    ))

    return results


def test_get_product_by_id(product_id):
    """
    Mint/GetProducyById? -- the trailing ? in the string suggests
    Retrofit appends query params here. Try multiple shapes.
    """
    base_url = BASE_URL + "/Mint/GetProducyById"
    results = []

    # Variant 1: GET with ?id=<product_id>
    url = base_url + "?id=" + urllib.parse.quote(product_id)
    results.append(_do_request(
        "GET", url, HEADERS_GUEST, None,
        "GetProducyById -- GET ?id=<id>"
    ))

    # Variant 2: GET with ?ProductId=<product_id>
    url = base_url + "?ProductId=" + urllib.parse.quote(product_id)
    results.append(_do_request(
        "GET", url, HEADERS_GUEST, None,
        "GetProducyById -- GET ?ProductId=<id>"
    ))

    # Variant 3: GET with ?productId=<product_id>
    url = base_url + "?productId=" + urllib.parse.quote(product_id)
    results.append(_do_request(
        "GET", url, HEADERS_GUEST, None,
        "GetProducyById -- GET ?productId=<id>"
    ))

    # Variant 4: GET with ?_id=<product_id>
    url = base_url + "?_id=" + urllib.parse.quote(product_id)
    results.append(_do_request(
        "GET", url, HEADERS_GUEST, None,
        "GetProducyById -- GET ?_id=<id>"
    ))

    # Variant 5: POST with body
    body = json.dumps({"ProductId": product_id}).encode("utf-8")
    results.append(_do_request(
        "POST", base_url, HEADERS_GUEST, body,
        "GetProducyById -- POST {'ProductId': ...}"
    ))

    return results


def cmd_scan_product(args):
    test_scan_product_legacy(args.cryptogram)


def cmd_get_product_by_id(args):
    test_get_product_by_id(args.product_id)


def cmd_probe_all_known(args):
    """
    Pull every distinct (cryptogram, product_id) tuple from the oracle DB and
    test the legacy/lookup endpoints with them. This is bounded by what's
    already in your local DB, not by guessing/enumerating.
    """
    oracle = Oracle(args.db)
    cur = oracle.connection.cursor()

    # Distinct cryptograms we've seen
    cur.execute(
        "SELECT DISTINCT chip_ndef_text FROM scans WHERE chip_ndef_text IS NOT NULL"
    )
    cryptograms = [row[0] for row in cur.fetchall()]
    print("Cryptograms in oracle DB: " + str(len(cryptograms)))
    for c in cryptograms:
        print("  " + c)

    # Distinct product IDs we've seen
    cur.execute(
        "SELECT DISTINCT product_id FROM product_records"
    )
    product_ids = [row[0] for row in cur.fetchall()]
    print("\nProduct IDs in oracle DB: " + str(len(product_ids)))
    for p in product_ids:
        print("  " + p)

    if not cryptograms and not product_ids:
        print("\n(empty oracle DB; nothing to probe)")
        oracle.close()
        return

    # Test legacy ScanProduct on FIRST cryptogram only (to identify the
    # right body shape) -- if one shape works, we can re-run with others
    # as needed.
    if cryptograms:
        print("\n\n##### LEGACY ScanProduct probe #####")
        test_scan_product_legacy(cryptograms[0])

    # Test GetProducyById on each known product ID
    for pid in product_ids:
        print("\n\n##### GetProducyById probe: " + pid + " #####")
        test_get_product_by_id(pid)

    oracle.close()


def main():
    parser = argparse.ArgumentParser(
        description="Probe MintID API endpoints we haven't tested yet."
    )
    parser.add_argument(
        "--db", default="mintid_oracle.db",
        help="Path to the oracle DB (used by probe-all-known)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("scan-product",
                        help="Probe legacy ScanProduct with a cryptogram.")
    p1.add_argument("cryptogram",
                    help="The 32-char NDEF text from a chip.")
    p1.set_defaults(func=cmd_scan_product)

    p2 = sub.add_parser("get-product-by-id",
                        help="Probe Mint/GetProducyById with a product _id.")
    p2.add_argument("product_id",
                    help="MongoDB ObjectId of the product.")
    p2.set_defaults(func=cmd_get_product_by_id)

    p3 = sub.add_parser("probe-all-known",
                        help="Test every endpoint variant against every "
                             "(cryptogram, product_id) in the oracle DB.")
    p3.set_defaults(func=cmd_probe_all_known)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
