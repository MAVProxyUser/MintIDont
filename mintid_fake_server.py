#!/usr/bin/env python3
"""
mintid_fake_server.py - implementation of MintID's verification API
that serves responses from the local oracle DB.

Endpoints implemented:

  POST /api/ProductAuthentication/SecuredScanProduct
       Returns the same shape as the real server. For known (UID, crypto)
       tuples in the oracle DB, returns a populated Product record. For
       unknown tuples, returns NTAGTTStatus=2/0 + Product=null per the
       real server's behaviour.

  GET  /api/Document/GetImage?documentID=<id>
       Returns image bytes for a document ID. Serves files from a local
       images/ directory (one .jpg or .png per documentID). If the
       documentID is unknown, returns 404. Optionally proxies upstream
       to the real server for unknown IDs (--proxy-images).

  POST /api/AccountAccess/Login
       Stubbed login. Accepts any credentials and returns a fake user
       token. Useful for testing flows that require authentication.

  POST /api/ProductAuthentication/ScanProduct  (legacy, returns 404)
  Any /api/Mint/*                               (legacy, returns 404)

USAGE

    # Default: bind 0.0.0.0:80 (run with sudo on macOS to bind low port)
    sudo python3 mintid_fake_server.py

    # Higher port (no sudo needed):
    python3 mintid_fake_server.py --port 8080

    # Pre-fetch images from the real server for all products in DB:
    python3 mintid_fake_server.py --fetch-images

    # Proxy unknown image requests to the real server (cache-on-fetch):
    python3 mintid_fake_server.py --proxy-images

    # Custom DB path:
    python3 mintid_fake_server.py --db /path/to/mintid_oracle.db

    # Inject a fake (UID, crypto) -> Product mapping at runtime:
    python3 mintid_fake_server.py --inject-uid 04ABCDEF123456 \\
        --inject-crypto deadbeefcafef00d... --inject-product-id <oid>

REQUIREMENTS
  pip install flask requests

The server is intentionally simple - no TLS, no auth, single-threaded by
default. Mirrors the real server's dubious operational hygiene because
that is part of what we are demonstrating.
"""
import argparse
import json
import os
import sys
import sqlite3
import urllib.request
import urllib.error
from pathlib import Path

try:
    from flask import Flask, request, Response, jsonify, send_file, abort
except ImportError:
    print("[fail] Flask not installed. Install with: pip install flask")
    sys.exit(1)


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

REAL_SERVER = "http://mintidapi.droisys.info"
IMAGES_DIR = Path(os.path.dirname(os.path.abspath(__file__))) / "fake_server_images"


def list_local_ipv4_addresses():
    """Return all IPv4 addresses bound to local network interfaces.

    Tries netifaces first (most reliable on macOS/Linux); falls back to a
    socket-based probe that connects-but-doesn't-send to a public-ish IP
    so the kernel picks a route, revealing the active outbound interface
    address. Always includes 127.0.0.1 in the result.
    """
    addrs = set(["127.0.0.1"])

    # Method 1: netifaces (best, but optional dependency)
    try:
        import netifaces
        for iface in netifaces.interfaces():
            try:
                ifaddrs = netifaces.ifaddresses(iface)
            except ValueError:
                continue
            for ent in ifaddrs.get(netifaces.AF_INET, []):
                a = ent.get("addr")
                if a:
                    addrs.add(a)
        return sorted(addrs)
    except ImportError:
        pass

    # Method 2: socket.getaddrinfo on hostname
    import socket
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, family=socket.AF_INET):
            a = info[4][0]
            if a:
                addrs.add(a)
    except OSError:
        pass

    # Method 3: outbound-route probe (does not send any packets)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            addrs.add(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass

    return sorted(addrs)


def load_oracle_records(db_path):
    """
    Load all (UID, crypto, product_id, tag_number, response_blob) tuples
    from the oracle DB. Returns a dict keyed by (UID_upper, crypto_lower)
    -> response JSON dict ready to be served.

    The oracle DB stores raw response bodies; we parse them into Python
    dicts so we can serve them back with minor edits if needed.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT chip_uid, chip_ndef_text, response_body, request_body, "
        "       scan_finished_at "
        "FROM scans "
        "WHERE response_body IS NOT NULL "
        "ORDER BY scan_id"
    )
    records = {}
    for row in cur.fetchall():
        uid, ndef_text, response_body, request_body, scan_finished_at = row
        if not uid or not ndef_text:
            continue
        try:
            parsed = json.loads(response_body)
        except (json.JSONDecodeError, TypeError):
            continue
        # The real server's tuple matching is case-insensitive on crypto
        # (server hex-decodes before comparing), case-sensitive on UID.
        key = (uid.upper(), ndef_text.lower())
        records[key] = parsed
    conn.close()
    return records


def prompt_with_timeout(prompt_text, valid_choices, default, timeout=10,
                          countdown=False):
    """Print prompt_text, wait up to timeout seconds for user input from
    stdin. Returns one of valid_choices, or default on timeout/EOF.

    If countdown=True, print a visible 1-second countdown so the operator
    sees the timer ticking. Useful for short timeouts where a silent wait
    would feel like a hang.
    """
    import select
    import sys
    sys.stdout.write(prompt_text)
    sys.stdout.flush()

    if countdown and timeout >= 1:
        # Print countdown ticks while polling stdin once per second
        remaining = int(timeout)
        while remaining > 0:
            try:
                ready, _, _ = select.select([sys.stdin], [], [], 1.0)
            except (OSError, ValueError):
                return default
            if ready:
                break
            sys.stdout.write(" %d..." % remaining)
            sys.stdout.flush()
            remaining -= 1
        else:
            sys.stdout.write(" [auto: %s]\n" % default)
            return default
    else:
        try:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
        except (OSError, ValueError):
            return default
        if not ready:
            sys.stdout.write(" [timeout, defaulting to %s]\n" % default)
            return default

    try:
        line = sys.stdin.readline().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if not line:
        return default
    # Accept first letter or full word match
    for choice in valid_choices:
        if line == choice or line == choice[0]:
            return choice
    sys.stdout.write("(unrecognised choice '%s', using default %s)\n"
                     % (line, default))
    return default


def persist_enrolment(db_path, uid, crypto, response_dict):
    """Persist an enrolled (UID, crypto) -> response mapping to the
    oracle DB so subsequent server restarts pick it up.

    Writes a synthetic row to the scans table with a marker note so it's
    distinguishable from real captures."""
    import sqlite3
    import json
    import datetime
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        result = response_dict.get("Result") or {}
        product = result.get("Product") or {}
        cur.execute("""
            INSERT INTO scans (
                scan_started_at, scan_finished_at,
                chip_uid, chip_uid_bytes, chip_pages_bytes,
                chip_ndef_text,
                request_url, request_headers, request_body,
                request_body_sha256,
                response_status, response_headers, response_body,
                response_body_sha256,
                response_status_code, response_ntag_tt_status,
                response_tag_number, response_product_id,
                response_product_name, response_product_updated_date,
                notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now, now,
            uid, bytes.fromhex(uid) if all(c in "0123456789ABCDEFabcdef" for c in uid) else b"",
            None, crypto,
            None, None, None, None,
            200, None, json.dumps(response_dict), None,
            result.get("StatusCode"),
            result.get("NTAGTTStatus"),
            result.get("TagNumber"),
            product.get("_id"),
            product.get("ProductName"),
            product.get("UpdatedDate"),
            "ENROLLED via fake_server interactive prompt",
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as exc:
        print("    [persist] failed to write to DB: %s" % exc)
        return False


def apply_product_overrides(response_dict, args):
    """Apply CLI-specified overrides to a response dict's Product fields.
    Modifies in place. Safe to call on responses with Product=None."""
    result = response_dict.get("Result")
    if not result:
        return response_dict
    product = result.get("Product")
    if not product:
        return response_dict

    name = getattr(args, "product_name", None)
    if name:
        product["ProductName"] = name
    desc = getattr(args, "product_description", None)
    if desc:
        product["ProductDescription"] = desc
    material = getattr(args, "material", None)
    if material:
        product["Material"] = material
    mfg = getattr(args, "manufacturer", None)
    if mfg:
        product["Manufacturer"] = mfg
    sku = getattr(args, "sku", None)
    if sku:
        product["SKU"] = sku
        product["ModelNumber"] = sku
    purity = getattr(args, "purity", None)
    if purity:
        product["Purity"] = purity
    serial = getattr(args, "serial_number", None)
    if serial:
        result["TagNumber"] = str(serial)

    return response_dict


def build_unknown_response():
    """
    Returns the shape the real server returns for unknown (UID, crypto)
    tuples: NTAGTTStatus=2, Product=null, but Status=1 (request well-formed).
    """
    return {
        "Status": 1,
        "Message": None,
        "MessageCode": 0,
        "StatusCode": -1,
        "Result": {
            "Product": None,
            "NTAGTTStatus": 2,
            "ProductOutlet": [],
            "TagNumber": None,
        },
        "Description": None,
        "UpdatedSyncTime": 0,
        "ResultCount": 0,
    }


def build_in_db_no_match_response():
    """
    Returns the shape the real server returns for (UID, crypto) tuples
    where the crypto exists somewhere in the DB but doesn't match this
    UID: NTAGTTStatus=0, Product=null. (We don't currently distinguish
    crypto-known vs crypto-unknown in the fake server because that would
    require a different lookup; we just serve build_unknown_response.)
    """
    out = build_unknown_response()
    out["Result"]["NTAGTTStatus"] = 0
    return out


def make_app(args):
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    records = load_oracle_records(args.db)

    print("[server] Loaded %d (UID, crypto) -> Product records from oracle." %
          len(records))
    for (uid, crypto), resp in records.items():
        product = (resp.get("Result") or {}).get("Product") or {}
        tag_number = (resp.get("Result") or {}).get("TagNumber")
        print("         UID=%s crypto=%s... -> %s (TagNumber=%s)" % (
            uid, crypto[:8], product.get("ProductName", "?"), tag_number,
        ))

    if args.inject_uid and args.inject_crypto:
        # Allow runtime injection: clone an existing product record and
        # re-tag it with the injected UID/crypto/product_id.
        if not records:
            print("[warn] --inject-* given but no records in DB to clone from.")
        else:
            template_resp = next(iter(records.values()))
            import copy
            injected = copy.deepcopy(template_resp)
            if args.inject_product_id:
                injected["Result"]["Product"]["_id"] = args.inject_product_id
            injected["Result"]["TagNumber"] = "999999"
            key = (args.inject_uid.upper(), args.inject_crypto.lower())
            records[key] = injected
            print("[server] Injected fake record for UID=%s crypto=%s..." % (
                key[0], key[1][:8],
            ))

    # Pre-fetch images if requested
    if args.fetch_images and not args.no_network:
        IMAGES_DIR.mkdir(exist_ok=True)
        print("[server] Pre-fetching images for %d products..." % len(records))
        seen_doc_ids = set()
        for resp in records.values():
            product = (resp.get("Result") or {}).get("Product") or {}
            for img in product.get("ProductImages") or []:
                doc_id = img.get("ProductImageDocumentID")
                if doc_id and doc_id not in seen_doc_ids:
                    seen_doc_ids.add(doc_id)
                    fetch_image_to_local(doc_id)

    def _prompt_for_enrolment(uid, crypto, records_dict, db_path):
        """Interactively ask the operator how to handle a new (UID, crypto)
        tuple. Returns the response dict to use (and to cache in records),
        or None to fall through to the normal unknown-tuple flow.
        """
        print("\n" + "=" * 60)
        print("UNKNOWN TUPLE -- enrol?")
        print("  UID    : %s" % uid)
        print("  crypto : %s" % crypto)
        print("=" * 60)
        print("Choose an action (10s timeout):")
        print("  [g] Genuine, clone an existing product record (you'll pick)")
        print("  [s] Genuine, minimal stub product record")
        print("  [t] Tampered (NTAGTTStatus=2, like real server says for unknowns)")
        print("  [n] None of the above, return unknown for this scan")
        # Default action is "g" (auto-enrol as Genuine clone) so the
        # phone doesn't get stuck on "tampered" while waiting for a human.
        # Timeout is short with a visible countdown.
        timeout_secs = getattr(args, "auto_enrol_timeout", 5)
        choice = prompt_with_timeout(
            "> ", ["g", "s", "t", "n"], default="g",
            timeout=timeout_secs, countdown=True,
        )

        if choice == "g":
            # List existing products and let operator pick which to clone
            seen_pids = {}
            for r in records_dict.values():
                p = (r.get("Result") or {}).get("Product") or {}
                pid = p.get("_id")
                if pid and pid not in seen_pids:
                    seen_pids[pid] = (p.get("ProductName"), r)
            if not seen_pids:
                print("    [no existing products to clone, falling back to stub]")
                choice = "s"
            else:
                items = list(seen_pids.items())
                print("Available product records:")
                for i, (pid, (pname, _)) in enumerate(items, start=1):
                    print("  [%d] %s (id=%s)" % (i, pname, pid))
                pick = prompt_with_timeout(
                    "Pick number (default 1): ",
                    [str(i) for i in range(1, len(items)+1)],
                    default="1",
                    timeout=getattr(args, "auto_enrol_timeout", 5),
                    countdown=True,
                )
                try:
                    idx = int(pick) - 1
                except ValueError:
                    idx = 0
                if idx < 0 or idx >= len(items):
                    idx = 0
                _, (_, template) = items[idx]
                import copy
                resp = copy.deepcopy(template)
                # Synthesize a TagNumber so it's distinguishable
                import time as _t
                resp["Result"]["TagNumber"] = "ENRL%d" % int(_t.time() % 100000)

                # Override ProductImages if operator supplied a default
                default_img = getattr(args, "default_image_doc_id", None)
                if default_img:
                    resp["Result"]["Product"]["ProductImages"] = [
                        {"ProductImageDocumentID": default_img,
                         "IsPrimary": True}
                    ]
                    print("    [overrode ProductImages to documentID=%s]" %
                          default_img)

                # Apply product field overrides (name, description, etc.)
                apply_product_overrides(resp, args)

                print("    [enrolled as Genuine clone of %s, TagNumber=%s]" % (
                    items[idx][1][0], resp["Result"]["TagNumber"],
                ))
                if persist_enrolment(db_path, uid, crypto, resp):
                    print("    [persisted to DB; will survive server restart]")
                return resp

        if choice == "s":
            import time as _t
            default_img = getattr(args, "default_image_doc_id", None)
            stub_images = (
                [{"ProductImageDocumentID": default_img, "IsPrimary": True}]
                if default_img else []
            )
            resp = {
                "Status": 1, "Message": None, "MessageCode": 0,
                "StatusCode": -1,
                "Result": {
                    "Product": {
                        "_id": "stub" + uid.lower(),
                        "ProductName": "Enrolled Stub Product",
                        "Manufacturer": "Operator-Enrolled",
                        "SKU": "STUB",
                        "ProductImages": stub_images,
                        "TotalNFCCount": 1,
                    },
                    "NTAGTTStatus": 0,
                    "ProductOutlet": [],
                    "TagNumber": "ENRL%d" % int(_t.time() % 100000),
                },
                "Description": None, "UpdatedSyncTime": 0, "ResultCount": 0,
            }
            apply_product_overrides(resp, args)
            print("    [enrolled as Genuine stub, TagNumber=%s]" %
                  resp["Result"]["TagNumber"])
            if persist_enrolment(db_path, uid, crypto, resp):
                print("    [persisted to DB]")
            return resp

        if choice == "t":
            resp = build_unknown_response()  # NTAGTTStatus=2
            print("    [enrolled as Tampered (NTAGTTStatus=2)]")
            if persist_enrolment(db_path, uid, crypto, resp):
                print("    [persisted to DB]")
            return resp

        # choice == "n": don't enrol, fall through
        print("    [not enrolled; this scan will return unknown]")
        return None

    def _log_response_body(resp_dict, max_chars=600):
        """Pretty-print the response payload in the server log so we can
        see exactly what's getting sent back to the client."""
        import json as _json
        try:
            text = _json.dumps(resp_dict, indent=2)
        except Exception:
            text = repr(resp_dict)
        if len(text) > max_chars:
            text = text[:max_chars] + "...[truncated, full body sent on wire]"
        print("    Response body:")
        for line in text.splitlines():
            print("      " + line)

    def _log_request(label, body=None):
        print("\n>>> %s %s %s" % (request.method, request.path, label))
        if body is not None:
            try:
                print(json.dumps(body, indent=2))
            except Exception:
                print(repr(body)[:500])

    @app.route("/api/ProductAuthentication/SecuredScanProduct",
               methods=["POST"])
    def secured_scan_product():
        # Log everything we got, even if body is empty -- helps debug
        # what the real client (iPhone, patched APK, curl, etc.) is
        # actually sending.
        raw_body = request.get_data() or b""
        ct = request.content_type or "(none)"
        print("\n>>> POST /api/ProductAuthentication/SecuredScanProduct")
        print("    Content-Type: %s" % ct)
        print("    Content-Length: %d" % len(raw_body))
        if raw_body:
            try:
                preview = raw_body.decode("utf-8", errors="replace")
            except Exception:
                preview = repr(raw_body[:200])
            if len(preview) > 400:
                preview = preview[:400] + "...[truncated]"
            print("    Body: %s" % preview)
        else:
            print("    Body: (empty -- check Content-Type, charset, or "
                  "compression)")

        # Try multiple decode strategies
        payload = {}
        if raw_body:
            # Strategy A: JSON via Flask's parser (force=True bypasses CT check)
            try:
                payload = request.get_json(force=True, silent=True) or {}
            except Exception:
                payload = {}
            # Strategy B: if A failed, try gzip-then-json (some clients
            # set Content-Encoding: gzip)
            if not payload and request.headers.get("Content-Encoding") == "gzip":
                try:
                    import gzip, json
                    decompressed = gzip.decompress(raw_body)
                    payload = json.loads(decompressed)
                    print("    [decode] body was gzip-compressed")
                except Exception as exc:
                    print("    [decode] gzip attempt failed: %s" % exc)
            # Strategy C: form-urlencoded (unlikely for this app, but cheap)
            if not payload and "form-urlencoded" in ct:
                try:
                    payload = dict(request.form)
                    print("    [decode] body parsed as form-urlencoded")
                except Exception:
                    pass

        # Tolerate alternate spellings of the key fields. The strings
        # table contained both "TagUID" and "TagUid" / "TagUdid"; the
        # canonical wire shape uses "TagUID" + "TagCrypto" but we
        # accept variants in case of patched/legacy clients.
        def pick(d, *keys):
            for k in keys:
                if k in d and d[k]:
                    return d[k]
            return ""

        uid = pick(payload, "TagUID", "TagUid", "tagUID", "tagUid",
                    "TagUdid").upper()
        crypto = pick(payload, "TagCrypto", "tagCrypto",
                       "TagCryptogram").lower()
        key = (uid, crypto)
        print("    Parsed: TagUID=%s TagCrypto=%s..." % (
            uid or "(missing)",
            (crypto[:8] + "..." if crypto else "(missing)"),
        ))

        # If the tuple is unknown AND we have both halves AND interactive
        # enrolment is enabled, prompt the operator
        if (key not in records and uid and crypto
                and getattr(args, "interactive_enrol", False)):
            enrolled = _prompt_for_enrolment(uid, crypto, records, args.db)
            if enrolled is not None:
                records[key] = enrolled

        if key in records:
            import copy
            response = copy.deepcopy(records[key])
            # Optional global image override
            if getattr(args, "override_images_globally", False):
                doc_id = getattr(args, "default_image_doc_id", None)
                if doc_id and response.get("Result", {}).get("Product"):
                    response["Result"]["Product"]["ProductImages"] = [
                        {"ProductImageDocumentID": doc_id,
                         "IsPrimary": True}
                    ]
            # Optional global product field overrides
            if getattr(args, "product_overrides_globally", True):
                apply_product_overrides(response, args)
            print("    -> KNOWN: returning Product record")
            _log_response_body(response)
            return jsonify(response)

        # Mimic the three-state oracle: if crypto exists somewhere in DB,
        # return NTAGTTStatus=0; otherwise NTAGTTStatus=2.
        crypto_known = any(c == crypto for (_, c) in records.keys())
        if crypto_known:
            print("    -> CRYPTO KNOWN, UID MISMATCH: NTAGTTStatus=0")
            response = build_in_db_no_match_response()
            _log_response_body(response)
            return jsonify(response)
        print("    -> UNKNOWN: NTAGTTStatus=2")
        response = build_unknown_response()
        _log_response_body(response)
        return jsonify(response)

    @app.route("/api/Document/GetImage", methods=["GET"])
    def get_image():
        doc_id = request.args.get("documentID", "")
        _log_request("GetImage doc_id=%s" % doc_id)

        local_path = IMAGES_DIR / ("%s.bin" % doc_id)
        if local_path.exists():
            mime = guess_image_mime(local_path)
            print("    -> serving local image %s (%d bytes, %s)" % (
                local_path.name, local_path.stat().st_size, mime,
            ))
            return send_file(str(local_path), mimetype=mime)

        if args.proxy_images and not args.no_network:
            # Fetch from real server, cache locally, serve back
            try:
                fetched = fetch_image_to_local(doc_id)
                if fetched and fetched.exists():
                    mime = guess_image_mime(fetched)
                    print("    -> proxied %d bytes, cached at %s" % (
                        fetched.stat().st_size, fetched.name,
                    ))
                    return send_file(str(fetched), mimetype=mime)
            except Exception as exc:
                print("    -> proxy failed: %s" % exc)

        # Fallback: a 1x1 transparent PNG placeholder so the app's image
        # decoder doesn't crash
        print("    -> unknown documentID, returning placeholder PNG")
        return Response(_PLACEHOLDER_PNG, mimetype="image/png")

    def _decode_login_body():
        """Login/Logout: parse body whether it's JSON (Android) or
        form-encoded (iOS), and log raw bytes either way for capture."""
        raw_body = request.get_data() or b""
        ct = request.content_type or "(none)"
        print("    Content-Type   : %s" % ct)
        print("    Content-Length : %d" % len(raw_body))
        if raw_body:
            preview = raw_body.decode("utf-8", errors="replace")
            if len(preview) > 800:
                preview = preview[:800] + "...[truncated]"
            print("    Body           : %s" % preview)
        else:
            print("    Body           : (empty)")

        payload = {}
        if raw_body:
            try:
                payload = request.get_json(force=True, silent=True) or {}
            except Exception:
                payload = {}
            if not payload and "form-urlencoded" in ct:
                try:
                    payload = dict(request.form)
                    print("    [decode] body parsed as form-urlencoded")
                except Exception:
                    pass
        return payload

    @app.route("/api/AccountAccess/Login", methods=["POST"])
    def login():
        print("\n>>> POST /api/AccountAccess/Login")
        payload = _decode_login_body()

        username = payload.get("UserName") or payload.get("Email") or ""
        password = payload.get("Password") or ""
        device_id = payload.get("DeviceID") or ""
        device_type = payload.get("DeviceType") or ""

        print("    Parsed:")
        print("      UserName   : %r" % username)
        print("      Password   : %r" % password)
        print("      DeviceID   : %r" % device_id)
        print("      DeviceType : %r" % device_type)

        # Build the LoginJSONResponse shape the app's POJO expects.
        # Fields lifted from Lcom/droisys/mintid/pojo/LoginResponse/
        # LoginJSONResponse and ResultLogin in the bytecode:
        #   status, message, description, updatedSyncTime, resultLogin
        #   resultLogin: accountID, authorizationKey, firstName, lastName,
        #               orgAccessID, organizationID, sessionToken
        import uuid as _uuid
        response = {
            "Status": 1,
            "Message": None,
            "MessageCode": 0,
            "StatusCode": -1,
            "Result": {
                "AccountID": "fake-account-" + (_uuid.uuid4().hex[:8]),
                "AuthorizationKey": "2I0mGELp",
                "FirstName": "Test",
                "LastName": "User",
                "OrgAccessID": "000000000000000000000000",
                "OrganizationID": "594b66c071945a30d03d28bf",
                "SessionToken": "fake-session-" + _uuid.uuid4().hex,
            },
            "Description": None,
            "UpdatedSyncTime": 0,
            "ResultCount": 1,
        }
        print("    -> Returning fake-success Login response")
        _log_response_body(response)
        return jsonify(response)

    @app.route("/api/AccountAccess/Logout", methods=["POST"])
    def logout():
        print("\n>>> POST /api/AccountAccess/Logout")
        payload = _decode_login_body()

        username = payload.get("UserName") or ""
        device_id = payload.get("DeviceID") or ""
        device_type = payload.get("DeviceType") or ""

        print("    Parsed:")
        print("      UserName   : %r" % username)
        print("      DeviceID   : %r" % device_id)
        print("      DeviceType : %r" % device_type)

        # Logout response: similar envelope, no resultLogin needed
        response = {
            "Status": 1,
            "Message": "Logged out",
            "MessageCode": 0,
            "StatusCode": -1,
            "Result": None,
            "Description": None,
            "UpdatedSyncTime": 0,
            "ResultCount": 0,
        }
        print("    -> Returning fake-success Logout response")
        _log_response_body(response)
        return jsonify(response)

    @app.route("/api/ProductAuthentication/ScanProduct", methods=["POST"])
    def legacy_scan_product():
        _log_request("legacy ScanProduct (returning 404 like real server)")
        return Response(
            json.dumps({
                "Message": "No HTTP resource was found that matches the "
                           "request URI 'http://localhost/api/Product"
                           "Authentication/ScanProduct'.",
                "MessageDetail": "No type was found that matches the "
                                  "controller named 'ProductAuthentication'.",
            }),
            status=404,
            mimetype="application/json",
        )

    @app.route("/api/Mint/<path:rest>", methods=["GET", "POST"])
    def legacy_mint_namespace(rest):
        _log_request("legacy Mint/ (returning 404 like real server)")
        return Response(
            json.dumps({
                "Message": "No HTTP resource was found.",
                "MessageDetail": "No type was found that matches the "
                                  "controller named 'Mint'.",
            }),
            status=404,
            mimetype="application/json",
        )

    @app.route("/admin/image/<doc_id>", methods=["PUT"])
    def admin_upload_image(doc_id):
        """Upload an image to be served at /api/Document/GetImage?documentID=<doc_id>.

        Body: raw image bytes (image/png, image/jpeg, image/gif, image/webp).
        Content-Type header is honoured but PUT body is what's stored verbatim.
        """
        if not doc_id or "/" in doc_id or ".." in doc_id:
            return jsonify({"error": "invalid doc_id"}), 400
        IMAGES_DIR.mkdir(exist_ok=True)
        target = IMAGES_DIR / ("%s.bin" % doc_id)
        body = request.get_data()
        if not body:
            return jsonify({"error": "empty body"}), 400
        target.write_bytes(body)
        mime = guess_image_mime(target)
        print("[admin] uploaded %d bytes for doc_id=%s (%s)" % (
            len(body), doc_id, mime,
        ))
        return jsonify({
            "ok": True,
            "doc_id": doc_id,
            "size": len(body),
            "mime": mime,
        })

    @app.route("/admin/image/<doc_id>", methods=["DELETE"])
    def admin_delete_image(doc_id):
        if not doc_id or "/" in doc_id or ".." in doc_id:
            return jsonify({"error": "invalid doc_id"}), 400
        target = IMAGES_DIR / ("%s.bin" % doc_id)
        if target.exists():
            target.unlink()
            print("[admin] deleted image for doc_id=%s" % doc_id)
            return jsonify({"ok": True, "doc_id": doc_id, "deleted": True})
        return jsonify({"ok": True, "doc_id": doc_id, "deleted": False}), 404

    @app.route("/admin/images", methods=["GET"])
    def admin_list_images():
        IMAGES_DIR.mkdir(exist_ok=True)
        out = []
        for fname in sorted(IMAGES_DIR.iterdir()):
            if fname.suffix == ".bin":
                doc_id = fname.stem
                out.append({
                    "doc_id": doc_id,
                    "size": fname.stat().st_size,
                    "mime": guess_image_mime(fname),
                })
        return jsonify({"count": len(out), "images": out})

    @app.route("/admin/records", methods=["GET"])
    def admin_list_records():
        out = []
        for (uid, crypto), resp in records.items():
            product = (resp.get("Result") or {}).get("Product") or {}
            tag_number = (resp.get("Result") or {}).get("TagNumber")
            out.append({
                "uid": uid,
                "crypto_prefix": crypto[:8] + "...",
                "product_name": product.get("ProductName"),
                "product_id": product.get("_id"),
                "tag_number": tag_number,
                "image_doc_ids": [
                    img.get("ProductImageDocumentID")
                    for img in (product.get("ProductImages") or [])
                ],
            })
        return jsonify({"count": len(out), "records": out})

    @app.route("/admin/inject", methods=["POST"])
    def admin_inject():
        """Inject a (UID, crypto) -> Product mapping at runtime.

        Body: JSON with at minimum {"uid": "...", "crypto": "...",
        "product_id": "..."}. If product_id matches an existing record,
        clones that response shape with the new UID/crypto. Otherwise
        builds a minimal Product record.
        """
        payload = request.get_json(force=True, silent=True) or {}
        uid = (payload.get("uid") or "").upper()
        crypto = (payload.get("crypto") or "").lower()
        if not uid or not crypto:
            return jsonify({"error": "uid and crypto required"}), 400

        # Try to clone an existing record for the same product_id
        product_id = payload.get("product_id")
        template = None
        if product_id:
            for r in records.values():
                rp = (r.get("Result") or {}).get("Product") or {}
                if rp.get("_id") == product_id:
                    template = r
                    break

        import copy
        if template:
            injected = copy.deepcopy(template)
        else:
            # Minimal stub response
            injected = {
                "Status": 1, "Message": None, "MessageCode": 0,
                "StatusCode": -1,
                "Result": {
                    "Product": {
                        "_id": product_id or "fake000000000000000000",
                        "ProductName": payload.get("product_name") or "Fake Product",
                        "Manufacturer": payload.get("manufacturer") or "Fake Mint",
                        "SKU": payload.get("sku") or "FAKE",
                        "ProductImages": [],
                        "TotalNFCCount": 1,
                    },
                    "NTAGTTStatus": 0,
                    "ProductOutlet": [],
                    "TagNumber": payload.get("tag_number") or "999999",
                },
                "Description": None, "UpdatedSyncTime": 0, "ResultCount": 0,
            }
        if "tag_number" in payload:
            injected["Result"]["TagNumber"] = str(payload["tag_number"])

        records[(uid, crypto)] = injected
        print("[admin] injected record: UID=%s crypto=%s... -> %s" % (
            uid, crypto[:8],
            injected["Result"]["Product"].get("ProductName", "?"),
        ))
        return jsonify({
            "ok": True,
            "uid": uid,
            "crypto_prefix": crypto[:8] + "...",
            "product_name": injected["Result"]["Product"].get("ProductName"),
        })

    @app.route("/admin/record/<uid>/<crypto>", methods=["DELETE"])
    def admin_delete_record(uid, crypto):
        key = (uid.upper(), crypto.lower())
        if key in records:
            del records[key]
            print("[admin] deleted record UID=%s" % uid.upper())
            return jsonify({"ok": True, "deleted": True})
        return jsonify({"ok": True, "deleted": False}), 404

    @app.route("/", methods=["GET"])
    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "ok": True,
            "records_loaded": len(records),
            "endpoints": [
                "POST /api/ProductAuthentication/SecuredScanProduct",
                "GET  /api/Document/GetImage?documentID=<id>",
                "POST /api/AccountAccess/Login",
                "POST /api/AccountAccess/Logout",
                "PUT  /admin/image/<doc_id>",
                "DELETE /admin/image/<doc_id>",
                "GET  /admin/images",
                "GET  /admin/records",
                "POST /admin/inject",
                "DELETE /admin/record/<uid>/<crypto>",
            ],
        })

    @app.before_request
    def log_unknown():
        if request.path == "/" or request.path == "/health":
            return
        if request.path.startswith("/api/"):
            return
        if request.path.startswith("/admin/"):
            return
        # Log unrecognised routes so we know what else the app might call
        print("[unknown-route] %s %s" % (request.method, request.path))

    @app.errorhandler(404)
    def fallback_404(e):
        return Response(
            json.dumps({
                "Message": "No HTTP resource found.",
                "MessageDetail": "No route at " + request.path,
            }),
            status=404,
            mimetype="application/json",
        )

    return app


def fetch_image_to_local(doc_id):
    IMAGES_DIR.mkdir(exist_ok=True)
    target = IMAGES_DIR / ("%s.bin" % doc_id)
    if target.exists():
        return target
    url = "%s/api/Document/GetImage?documentID=%s" % (REAL_SERVER, doc_id)
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = r.read()
    except urllib.error.URLError as exc:
        print("    [fetch] failed: %s" % exc)
        return None
    target.write_bytes(data)
    return target


def guess_image_mime(path):
    """Sniff the first few bytes to pick a MIME type."""
    with open(path, "rb") as f:
        head = f.read(16)
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head[:2] == b"\xff\xd8":
        return "image/jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    return "application/octet-stream"


# Tiny 1x1 transparent PNG used as a fallback for unknown image requests
_PLACEHOLDER_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c63600100000005000160a3eea4000000004945"
    "4e44ae426082"
)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default="mintid_oracle.db",
                   help="Path to oracle DB (default: mintid_oracle.db).")
    p.add_argument("--port", type=int, default=80,
                   help="Bind port (default: 80, requires sudo on macOS).")
    p.add_argument("--host", default="0.0.0.0",
                   help="Bind address (default: 0.0.0.0).")
    p.add_argument("--fetch-images", action="store_true",
                   help="Pre-fetch all product images from the real server "
                        "before starting.")
    p.add_argument("--proxy-images", action="store_true",
                   help="On unknown image requests, proxy to real server "
                        "and cache locally.")
    p.add_argument("--no-network", action="store_true",
                   help="Don't make any outbound HTTP requests.")
    p.add_argument("--interactive-enrol", "--enrol", action="store_true",
                   help="When the server sees an unknown (UID, crypto) "
                        "tuple, prompt at the terminal whether to enrol it "
                        "as Genuine (clone existing product / minimal stub) "
                        "or Tampered. Persists choice to the DB so it "
                        "survives restarts. Default action on timeout is "
                        "'g' (Genuine clone of first product) so the phone "
                        "does not block on 'tampered'.")
    p.add_argument("--auto-enrol-timeout", type=int, default=5,
                   help="Seconds to wait for operator input before "
                        "auto-enrolling as Genuine (default: 5).")
    p.add_argument("--default-image-doc-id",
                   help="When auto-enrolling, override the cloned product's "
                        "ProductImages to reference this documentID instead "
                        "of the original. Place the image file at "
                        "fake_server_images/<doc_id>.bin so the GetImage "
                        "endpoint can serve it.")
    p.add_argument("--override-images-globally", action="store_true",
                   help="Apply --default-image-doc-id to ALL responses, "
                        "including ones served from existing DB rows. "
                        "Without this, the override only applies to "
                        "newly auto-enrolled tuples.")
    p.add_argument("--product-name",
                   help="Override Product.ProductName in all responses.")
    p.add_argument("--product-description",
                   help="Override Product.ProductDescription in all responses.")
    p.add_argument("--material",
                   help="Override Product.Material in all responses "
                        "(displayed as 'Metal Content' in the iOS app).")
    p.add_argument("--manufacturer",
                   help="Override Product.Manufacturer in all responses.")
    p.add_argument("--sku",
                   help="Override Product.SKU and Product.ModelNumber in "
                        "all responses.")
    p.add_argument("--serial-number", "--tag-number",
                   help="Override TagNumber (shown as 'Serial Number' in "
                        "the iOS app) in all responses.")
    p.add_argument("--purity",
                   help="Override Product.Purity in all responses.")
    p.add_argument("--product-overrides-globally", action="store_true",
                   default=True,
                   help="Apply product field overrides to ALL responses "
                        "(default: True). Set to False with "
                        "--no-product-overrides-globally to limit overrides "
                        "to newly auto-enrolled tuples only.")
    p.add_argument("--no-product-overrides-globally",
                   dest="product_overrides_globally",
                   action="store_false",
                   help="Disable global product overrides (overrides apply "
                        "only to newly auto-enrolled tuples).")
    p.add_argument("--inject-uid", help="Inject a fake (UID, crypto) "
                    "record at startup.")
    p.add_argument("--inject-crypto", help="Inject crypto for the "
                    "injected UID.")
    p.add_argument("--inject-product-id", help="Inject product _id for "
                    "the injected record.")
    args = p.parse_args()

    if not os.path.exists(args.db):
        print("[fail] Oracle DB not found at %s" % args.db)
        print("       The bundle ships with a pre-populated mintid_oracle.db")
        print("       containing 3 captured coin records. If you have")
        print("       deleted it, re-run mintid_simulate.py against your")
        print("       coins to regenerate, or restore from the bundle.")
        return 1

    app = make_app(args)
    print("=" * 60)
    print("MintID fake server")
    print("=" * 60)
    if args.host in ("0.0.0.0", "::", ""):
        ips = list_local_ipv4_addresses()
        print("Listening on all interfaces, port %d. Reachable at:" % args.port)
        for ip in ips:
            print("  http://%s:%d" % (ip, args.port))
        # Pick the most likely LAN address for the example commands below
        lan_ips = [ip for ip in ips
                   if not ip.startswith("127.")
                   and not ip.startswith("169.254.")]
        primary = lan_ips[0] if lan_ips else "127.0.0.1"
    else:
        primary = args.host
        print("Listening on http://%s:%d" % (args.host, args.port))
    print("")
    print("Health check: http://%s:%d/health" % (primary, args.port))
    print("")
    print("Point an APK-patched MintID app at this server with:")
    print("  python3 mintid_apk_repoint.py MintID.apk \\")
    print("      --new-base-url http://%s" % primary
          + (":%d" % args.port if args.port != 80 else ""))
    print("")
    print("Or run the DNS spoofer so the unmodified app can reach this:")
    print("  sudo python3 mintid_dns_spoof.py --target-ip %s" % primary)
    print("=" * 60)
    print("")

    app.run(host=args.host, port=args.port, threaded=False)


if __name__ == "__main__":
    sys.exit(main() or 0)
