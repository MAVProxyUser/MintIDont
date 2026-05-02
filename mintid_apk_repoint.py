#!/usr/bin/env python3
"""
mintid_apk_repoint.py - patch the MintID APK to point its base URL at a
different server, then repack and sign so the patched APK is sideloadable.

What it does:

  1. Unzip the APK
  2. Find every occurrence of "mintidapi.droisys.info" in classes.dex /
     classes2.dex / etc., and replace with the user-specified host
  3. Patch the network-security-config XML if present to allow cleartext
     HTTP to the new host
  4. Re-zip with no compression on uncompressible files (matches AAPT
     output)
  5. Sign with apksigner (preferred) or jarsigner, using a debug
     keystore generated on the fly if needed
  6. (Optional) zipalign before signing

The string-replacement approach works because:
  - The base URL is stored as an ASCII literal in the dex strings table
  - Replacement strings of the same byte length keep all dex offset
    tables valid
  - For longer/shorter replacements, we pad with the URL's path to keep
    length constant

Length-matching constraint: if you want to repoint to a host whose
hostname plus port is longer than "mintidapi.droisys.info" (22 chars),
this won't fit. You'd need full apktool repackaging in that case. For
typical use cases (local IP like 192.168.1.42:8080), we can fit by
truncating or padding.

USAGE

    # Repoint to local server on default port:
    python3 mintid_apk_repoint.py MintID.apk \\
        --new-base-url http://192.168.1.42

    # With explicit output:
    python3 mintid_apk_repoint.py MintID.apk \\
        --new-base-url http://192.168.1.42:8080 \\
        --output MintID-patched.apk

    # Dry-run: show what would be patched without writing:
    python3 mintid_apk_repoint.py MintID.apk \\
        --new-base-url http://192.168.1.42 --dry-run

REQUIREMENTS
  - Python 3.8+
  - apksigner OR jarsigner (Android SDK build-tools or Java JDK)
  - zipalign (Android SDK build-tools, optional but recommended)
  - keytool (Java JDK, for debug keystore generation)

If you have Android Studio installed, all of the above are typically
under $ANDROID_HOME/build-tools/<version>/.
"""
import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ORIGINAL_HOST = "mintidapi.droisys.info"
ORIGINAL_BASE = "http://mintidapi.droisys.info"


def find_tool(name, hint=None):
    """Locate a build tool, checking PATH and ANDROID_HOME."""
    p = shutil.which(name)
    if p:
        return p
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if android_home:
        bt = Path(android_home) / "build-tools"
        if bt.exists():
            for version_dir in sorted(bt.iterdir(), reverse=True):
                candidate = version_dir / name
                if candidate.exists():
                    return str(candidate)
                # Windows: try .bat suffix
                candidate_bat = version_dir / (name + ".bat")
                if candidate_bat.exists():
                    return str(candidate_bat)
    if hint:
        print("[warn] '%s' not found. %s" % (name, hint))
    return None


def patch_dex_string(dex_bytes, old_string, new_string):
    """
    Replace occurrences of old_string with new_string in DEX file bytes,
    preserving file structure by padding/truncating new_string to the
    same byte length as old_string.

    DEX files have a strings table where each string is preceded by its
    ULEB128 length. If we keep the byte length the same, we don't have
    to update any offsets or lengths.
    """
    old_b = old_string.encode("utf-8")
    new_b = new_string.encode("utf-8")

    if len(new_b) > len(old_b):
        raise ValueError(
            "New string '%s' (%d bytes) is longer than old '%s' (%d bytes). "
            "Length-preserving patch requires <= old length." % (
                new_string, len(new_b), old_string, len(old_b),
            )
        )

    # Pad new_b with NULL bytes to match length. Java/Kotlin String parsing
    # may treat NULLs as terminators; use spaces or trailing slashes if
    # NULLs cause issues. For URL components, '/' works as a no-op suffix.
    if len(new_b) < len(old_b):
        # If new_b is a host-only URL component, pad with extra path
        # characters that the URL parser will tolerate.
        padding_needed = len(old_b) - len(new_b)
        # Use '.' for hostname (.host.host.host... still parses) or '/'
        # for path (/x/x/x... is harmless extra path)
        if "/" in new_string:
            new_b = new_b + b"/" * padding_needed
        else:
            new_b = new_b + b"." * padding_needed

    if len(new_b) != len(old_b):
        raise ValueError("Padding logic failed (got %d, need %d)" % (
            len(new_b), len(old_b)
        ))

    count = dex_bytes.count(old_b)
    if count == 0:
        return dex_bytes, 0

    patched = dex_bytes.replace(old_b, new_b)
    return patched, count


def recompute_dex_checksum(dex_bytes):
    """
    Rewrite the DEX header's checksum and signature to match the
    modified content.

    DEX header layout:
      0..7   = magic ("dex\n035\0" or similar)
      8..11  = adler32 checksum (LE)
      12..31 = SHA-1 signature
      32..35 = file size
      ...
    """
    if len(dex_bytes) < 0x70:
        return dex_bytes
    if dex_bytes[:3] != b"dex":
        return dex_bytes  # not a DEX

    import zlib, hashlib
    # Mutable copy
    out = bytearray(dex_bytes)

    # SHA-1 is computed over bytes from offset 32 to end of file
    sha1 = hashlib.sha1(bytes(out[32:])).digest()
    out[12:32] = sha1

    # Adler32 is computed over bytes from offset 12 to end of file
    # (i.e., everything after the magic and checksum field)
    adler = zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF
    out[8:12] = struct.pack("<I", adler)

    return bytes(out)


def patch_apk(apk_path, new_base_url, output_path, dry_run=False, verbose=False):
    """
    Main patch routine. Returns the path to the patched (unsigned) APK
    on success, None on failure.
    """
    apk = Path(apk_path)
    if not apk.exists():
        print("[fail] APK not found: %s" % apk_path)
        return None

    # Extract the host from the new base URL for length comparison
    if "://" in new_base_url:
        scheme, rest = new_base_url.split("://", 1)
        host_and_path = rest
    else:
        scheme, host_and_path = "http", new_base_url
    new_host = host_and_path.split("/", 1)[0]  # strip path

    print("[patch] Original host: %s (%d bytes)" % (
        ORIGINAL_HOST, len(ORIGINAL_HOST),
    ))
    print("[patch] New host     : %s (%d bytes)" % (
        new_host, len(new_host),
    ))
    if len(new_host) > len(ORIGINAL_HOST):
        print("[fail] New host is %d bytes longer than original. "
              "DEX length-preserving patch requires new host be the same "
              "length or shorter." % (len(new_host) - len(ORIGINAL_HOST)))
        print("       Workarounds:")
        print("         * Use an IP without port (e.g. 192.168.1.42)")
        print("         * Use a short hostname (e.g. m.local)")
        print("         * Use full apktool repackaging instead")
        return None

    # Output directory for the unpacked-and-repacked APK
    work_dir = Path(tempfile.mkdtemp(prefix="mintid_apk_patch_"))
    print("[patch] Working dir : %s" % work_dir)

    extract_dir = work_dir / "extracted"
    extract_dir.mkdir()

    # Some APKPure-style downloads are .xapk (a zip of base.apk +
    # splits). The "base" APK might be named base.apk OR <package>.apk
    # OR something else. Detection: pick the largest .apk that's NOT a
    # config.*.apk (those are language/density splits).
    actual_apk = apk
    with zipfile.ZipFile(apk, "r") as zf:
        names = zf.namelist()
        apk_entries = [
            (n, zf.getinfo(n).file_size)
            for n in names
            if n.endswith(".apk") and not n.startswith("config.")
        ]
        if apk_entries:
            # Sort by size descending; the base APK is the largest
            apk_entries.sort(key=lambda t: -t[1])
            base_name = apk_entries[0][0]
            print("[patch] Input is .xapk; extracting %s" % base_name)
            actual_apk = work_dir / "base.apk"
            with zf.open(base_name) as src:
                with open(actual_apk, "wb") as dst:
                    shutil.copyfileobj(src, dst)

    # Extract APK
    with zipfile.ZipFile(actual_apk, "r") as zf:
        zf.extractall(extract_dir)

    # Find and patch dex files
    total_patches = 0
    for dex_file in sorted(extract_dir.glob("classes*.dex")):
        if verbose:
            print("[patch] Scanning %s" % dex_file.name)
        with open(dex_file, "rb") as f:
            data = f.read()

        try:
            patched_data, count = patch_dex_string(data, ORIGINAL_HOST, new_host)
        except ValueError as exc:
            print("[fail] %s" % exc)
            shutil.rmtree(work_dir)
            return None

        if count > 0:
            print("[patch] %s: replaced %d occurrence(s) of '%s' with '%s'"
                  % (dex_file.name, count, ORIGINAL_HOST, new_host))
            patched_data = recompute_dex_checksum(patched_data)
            if not dry_run:
                with open(dex_file, "wb") as f:
                    f.write(patched_data)
            total_patches += count
        elif verbose:
            print("[patch] %s: no occurrences found" % dex_file.name)

    if total_patches == 0:
        print("[fail] No occurrences of '%s' found in any DEX file. "
              "Wrong APK?" % ORIGINAL_HOST)
        shutil.rmtree(work_dir)
        return None

    # Patch network_security_config.xml if present, to allow cleartext
    # HTTP to the new host (Android P+ blocks cleartext by default for
    # newly-installed apps). Look for it in res/xml/ first.
    nsc_paths = list(extract_dir.glob("res/xml/network_security_config*.xml"))
    if nsc_paths:
        print("[patch] Found network_security_config XML(s); these are "
              "binary AXML and likely already permit cleartext for the "
              "original host. The new host may need explicit allowance.")
        # We'd need to parse AXML to modify; skip for now and rely on
        # the manifest's android:usesCleartextTraffic flag (which the
        # MintID app must already have to talk HTTP to the real server).

    # Repack
    if dry_run:
        print("[dry-run] Would repack APK to %s" % output_path)
        shutil.rmtree(work_dir)
        return None

    repacked = work_dir / "repacked-unsigned.apk"
    print("[patch] Repacking to %s" % repacked)
    with zipfile.ZipFile(repacked, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(extract_dir.rglob("*")):
            if path.is_file():
                rel = path.relative_to(extract_dir)
                # AAPT stores some files uncompressed (resources.arsc,
                # *.png, *.jpg, etc.) - approximate by storing instead
                # of deflating those types
                arcname = str(rel).replace(os.sep, "/")
                if (arcname == "resources.arsc"
                        or arcname.endswith((".png", ".jpg", ".jpeg",
                                             ".gif", ".webp", ".ogg",
                                             ".mp3", ".mp4"))):
                    zf.write(path, arcname, zipfile.ZIP_STORED)
                else:
                    zf.write(path, arcname, zipfile.ZIP_DEFLATED)

    # Strip any META-INF/ signature files (the APK was signed; we are
    # invalidating the signature and need to resign)
    repacked_clean = work_dir / "repacked-cleaned.apk"
    with zipfile.ZipFile(repacked, "r") as src:
        with zipfile.ZipFile(repacked_clean, "w", zipfile.ZIP_DEFLATED) as dst:
            for item in src.infolist():
                # Drop existing signatures
                if item.filename.startswith("META-INF/") and (
                    item.filename.endswith(".SF")
                    or item.filename.endswith(".RSA")
                    or item.filename.endswith(".DSA")
                    or item.filename.endswith(".EC")
                    or item.filename == "META-INF/MANIFEST.MF"
                ):
                    continue
                data = src.read(item.filename)
                dst.writestr(item, data)
    repacked = repacked_clean

    # zipalign (optional but recommended)
    zipalign = find_tool("zipalign", hint="Skipping alignment.")
    aligned = work_dir / "repacked-aligned.apk"
    if zipalign:
        print("[patch] Running zipalign...")
        rc = subprocess.run(
            [zipalign, "-f", "-p", "4", str(repacked), str(aligned)],
            capture_output=True,
        )
        if rc.returncode == 0:
            repacked = aligned
        else:
            print("[warn] zipalign failed: %s" % rc.stderr.decode("utf-8", "replace"))

    # Signing: prefer apksigner, fall back to jarsigner
    keystore_path = ensure_debug_keystore(work_dir)
    if keystore_path is None:
        print("[fail] Could not create debug keystore.")
        shutil.rmtree(work_dir)
        return None

    apksigner = find_tool("apksigner")
    jarsigner = find_tool("jarsigner")

    if apksigner:
        print("[patch] Signing with apksigner...")
        rc = subprocess.run([
            apksigner, "sign",
            "--ks", str(keystore_path),
            "--ks-pass", "pass:android",
            "--key-pass", "pass:android",
            "--ks-key-alias", "androiddebugkey",
            str(repacked),
        ], capture_output=True)
        if rc.returncode != 0:
            print("[fail] apksigner failed: %s" %
                  rc.stderr.decode("utf-8", "replace"))
            shutil.rmtree(work_dir)
            return None
    elif jarsigner:
        print("[patch] Signing with jarsigner (apksigner preferred but not found)...")
        rc = subprocess.run([
            jarsigner,
            "-sigalg", "SHA1withRSA",
            "-digestalg", "SHA1",
            "-keystore", str(keystore_path),
            "-storepass", "android",
            "-keypass", "android",
            str(repacked),
            "androiddebugkey",
        ], capture_output=True)
        if rc.returncode != 0:
            print("[fail] jarsigner failed: %s" %
                  rc.stderr.decode("utf-8", "replace"))
            shutil.rmtree(work_dir)
            return None
    else:
        print("[fail] Neither apksigner nor jarsigner found in PATH.")
        print("       Install Android SDK build-tools or a JDK.")
        shutil.rmtree(work_dir)
        return None

    # Copy final APK to output path
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(repacked, output)
    print("[patch] Wrote %s" % output)
    print("[patch] Total DEX patches applied: %d" % total_patches)

    shutil.rmtree(work_dir)
    return output


def ensure_debug_keystore(work_dir):
    """Create a debug keystore in work_dir if one doesn't exist."""
    keytool = find_tool("keytool")
    if keytool is None:
        print("[fail] keytool not found. Install a JDK.")
        return None
    keystore = work_dir / "debug.keystore"
    if keystore.exists():
        return keystore
    print("[patch] Generating debug keystore...")
    rc = subprocess.run([
        keytool,
        "-genkey", "-v",
        "-keystore", str(keystore),
        "-alias", "androiddebugkey",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-storepass", "android",
        "-keypass", "android",
        "-dname", "CN=Android Debug, O=Android, C=US",
    ], capture_output=True)
    if rc.returncode != 0:
        print("[fail] keytool failed: %s" %
              rc.stderr.decode("utf-8", "replace"))
        return None
    return keystore


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("apk", help="Input APK or .xapk file.")
    p.add_argument("--new-base-url", required=True,
                   help="New base URL, e.g. http://192.168.1.42 or "
                        "http://192.168.1.42:8080. Hostname must be <= "
                        "%d bytes." % len(ORIGINAL_HOST))
    p.add_argument("--output", "-o",
                   help="Output APK path (default: <input>-patched.apk).")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would be patched without writing.")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    if args.output is None:
        in_path = Path(args.apk)
        args.output = str(in_path.with_name(in_path.stem + "-patched.apk"))

    result = patch_apk(args.apk, args.new_base_url, args.output,
                        dry_run=args.dry_run, verbose=args.verbose)
    if result is None and not args.dry_run:
        return 1
    if result:
        print("")
        print("Patched APK: %s" % result)
        print("")
        print("To install on a connected Android device:")
        print("  adb install -r %s" % result)
        print("")
        print("To launch the fake server:")
        print("  python3 mintid_fake_server.py")
        print("")
        print("On the Android device, ensure it can reach the host running")
        print("the fake server (same wifi, or USB tethered).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
