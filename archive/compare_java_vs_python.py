#!/usr/bin/env python3
"""
compare_java_vs_python.py — verify that the Python simulator's request
construction is byte-identical to the real Java code from the APK.

Workflow:
  1. Run the Java harness with a known TagUID and TagCrypto. It emits
     /tmp/java_emitted_request.json containing the exact body, headers,
     and field order the real app would produce.
  2. Run the Python body-construction logic with the SAME inputs, with no
     reader access needed (tests offline against canned chip data).
  3. Diff the two outputs byte-for-byte and report mismatches.

Run:
  python3 compare_java_vs_python.py
"""
import json
import os
import subprocess
import sys

# Import the body-construction functions from the simulator without touching
# the chip-reading code path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mintid_simulate import (
    build_request_body,
    build_request_headers,
    serialize_body_jackson_compatible,
)


# Canned test inputs. Match what the user's most recent scan produced so the
# comparison reflects the actual coin in their hand.
TEST_TAG_UID_HEX = "ADF61606013C16E0"
TEST_TAG_CRYPTO = "A125B451690E7E8C4C33AF273DB1ACFB"
TEST_DEVICE_ID = ""
TEST_LAT = 0.0
TEST_LON = 0.0


def run_java_harness(tag_uid_string, tag_crypto):
    """Invoke the compiled Java harness and return parsed envelope."""
    harness_dir = "/home/claude/harness/java"
    classpath_parts = [
        os.path.join(harness_dir, "build"),
        "/usr/share/java/jackson-core.jar",
        "/usr/share/java/jackson-annotations.jar",
        "/usr/share/java/jackson-databind.jar",
    ]
    classpath = ":".join(classpath_parts)
    result = subprocess.run(
        [
            "java",
            "-cp",
            classpath,
            "harness.Harness",
            tag_uid_string,
            tag_crypto,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    print("--- Java harness stdout ---")
    print(result.stdout)
    if result.stderr:
        print("--- Java harness stderr ---")
        print(result.stderr)
    with open("/tmp/java_emitted_request.json") as fh:
        return json.load(fh)


def run_python_simulator(uid_bytes, tag_crypto, device_id, lat, lon):
    """Run the Python simulator body+headers construction (no reader)."""
    body = build_request_body(uid_bytes, tag_crypto, device_id, lat, lon)
    body_string = serialize_body_jackson_compatible(body)
    headers = build_request_headers()
    return {
        "body": body_string,
        "body_length": len(body_string.encode("utf-8")),
        "field_order": list(body.keys()),
        "headers": headers,
    }


def compare(java_envelope, python_envelope):
    """Diff the two envelopes, returning a list of mismatch descriptions."""
    mismatches = []

    # Body bytes
    java_body = java_envelope["body"]
    python_body = python_envelope["body"]
    if java_body != python_body:
        mismatches.append(
            "BODY DIFFERS"
            "\n  Java   : " + java_body
            + "\n  Python : " + python_body
        )
    else:
        print("[OK] BODY matches byte-for-byte (%d bytes)" % len(java_body))

    # Body length
    if java_envelope["body_length"] != python_envelope["body_length"]:
        mismatches.append(
            "Content-Length differs: Java=%d Python=%d" % (
                java_envelope["body_length"],
                python_envelope["body_length"],
            )
        )
    else:
        print("[OK] Content-Length matches: %d" % java_envelope["body_length"])

    # Field order
    if java_envelope["field_order"] != python_envelope["field_order"]:
        mismatches.append(
            "Field order differs:"
            "\n  Java   : " + str(java_envelope["field_order"])
            + "\n  Python : " + str(python_envelope["field_order"])
        )
    else:
        print(
            "[OK] Field order matches: %s"
            % ", ".join(java_envelope["field_order"])
        )

    # Headers (comparing only the three the interceptor sets; User-Agent
    # is added by OkHttp/urllib themselves and won't match exactly)
    interceptor_headers = ["OrgAccessID", "AuthorizationKey", "Content-Type"]
    for header in interceptor_headers:
        java_value = java_envelope["headers"].get(header)
        python_value = python_envelope["headers"].get(header)
        if java_value != python_value:
            mismatches.append(
                "Header %s differs: Java=%r Python=%r"
                % (header, java_value, python_value)
            )
        else:
            print("[OK] Header %s matches: %s" % (header, java_value))

    return mismatches


def main():
    print("=" * 70)
    print("Java harness vs Python simulator — byte-for-byte comparison")
    print("=" * 70)
    print("Inputs:")
    print("  TagUID (hex, uppercase): " + TEST_TAG_UID_HEX)
    print("  TagCrypto              : " + TEST_TAG_CRYPTO)
    print("  DeviceID               : " + repr(TEST_DEVICE_ID))
    print("  Lat, Lon               : %s, %s" % (TEST_LAT, TEST_LON))
    print()

    print("--- Running Java harness ---")
    tag_uid_to_send = TEST_TAG_UID_HEX.upper()  # AOSP %02X
    java_envelope = run_java_harness(tag_uid_to_send, TEST_TAG_CRYPTO)

    print()
    print("--- Running Python simulator (offline body construction) ---")
    uid_bytes = bytes.fromhex(TEST_TAG_UID_HEX)
    python_envelope = run_python_simulator(
        uid_bytes, TEST_TAG_CRYPTO, TEST_DEVICE_ID, TEST_LAT, TEST_LON
    )
    print("Python body: " + python_envelope["body"])
    print("Python body length: %d" % python_envelope["body_length"])
    print("Python field order: " + ", ".join(python_envelope["field_order"]))

    print()
    print("--- Comparison ---")
    mismatches = compare(java_envelope, python_envelope)

    print()
    if mismatches:
        print("FAIL: %d mismatch(es)" % len(mismatches))
        for m in mismatches:
            print("- " + m)
        sys.exit(1)
    else:
        print("PASS: Python simulator output matches Java harness "
              "byte-for-byte.")


if __name__ == "__main__":
    main()
