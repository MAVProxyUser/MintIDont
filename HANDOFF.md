# HANDOFF — MintID Interoperability Research

For future sessions (or future-you returning months later) picking up this project.

## One-line summary

Empirically demonstrated end-to-end clone-and-tap against MintID's production verification API and official iOS app. Disclosure draft ready. Not yet sent.

## What's done

- **Static analysis** of MintID Android APK v1.8 — found 14 architectural vulnerabilities, all documented in `DISCLOSURE_DRAFT.md`
- **Empirical confirmation** of every static finding via probes against production API (hard-capped, ethical bounds maintained)
- **Chip cloning demonstrated**: ACR1552 captured Coin 3 Round → PM3 wrote UID + NDEF onto magic Gen 2/CUID Ultralight-C → cloned chip read via ACR1552 produced byte-equal server response to genuine coin
- **iOS spoofing demonstrated**: official MintID app from App Store, on stock iPhone, rendered "GENUINE" with operator-controlled product name, description, serial number, and image. Achieved by DNS spoofing alone (no app modification, no jailbreak).
- **All four endpoints implemented** in `mintid_fake_server.py`:
  - `SecuredScanProduct` (verification)
  - `GetImage` (product photos)
  - `Login` (returns LoginJSONResponse-shaped success with fake AccountID/SessionToken)
  - `Logout` (returns success envelope)
  All four log raw bodies + parsed payloads to stdout. All four accept both `application/json` (Android) and `application/x-www-form-urlencoded` (iOS).
- **Toolkit packaged** at present-day state.

## What's not done

- **Disclosure send.** Pick disclosure channel and recipients. No published security@ for MintID/Highland Mint/Identiv/Cut Saw/Droisys; cold-email candidates. The disclosure body itself is complete (no placeholder dates remaining; timeline section was removed by request).
- **iOS-specific findings.** We discovered iOS app sends form-encoded bodies (Android sends JSON) but didn't reverse the iOS app in detail. Probably not needed unless the vendor specifically denies the iOS attack surface.

## Things that surprised us along the way

- The MintID APK uses Retrofit with **JSON body**; the iOS app uses **form-urlencoded**. Both go to the same endpoint. Server accepts both. Worth a sentence in the disclosure — "no per-client validation."
- Coin 1's chip is an 8-byte UID NON-NXP clone (manufacturer code 0xAD), not a real NTAG 213. Yet the official app verifies it as Genuine. So MintID's chip-supplier discipline has slipped. Documented as finding 10.
- "On-metal" + "magic UID-changeable" is **not a single off-the-shelf product**. To embed a clone into a fake coin you stack: ferrite disc → magic chip → silver/aluminum.
- macOS PC/SC framework filters native NXP commands (FAST_READ, PWD_AUTH, READ_SIG NAK uniformly via wrappers). Doesn't matter for the disclosure but cost time during chip characterization.
- PM3 `hf mfu dump` writes a 56-byte header before the page data in its .bin output. Use `hf mfu rdbl -b N` per-page for verification to sidestep this.
- Iceman PM3 client spawns Qt windows briefly even for non-graph commands. Set `QT_QPA_PLATFORM=offscreen` in subprocess env to suppress.
- LoginJSONResponse has these fields the app's POJO expects: `Status`, `Message`, `Description`, `UpdatedSyncTime`, plus `Result` containing `AccountID`, `AuthorizationKey`, `FirstName`, `LastName`, `OrgAccessID`, `OrganizationID`, `SessionToken`. Initial Login stub was missing several of these.

## Repo state

```
mintid_interop_toolkit/
├── mintid_simulate.py           ─┐
├── mintid_oracle.py              │
├── mintid_oracle_cli.py          │  Active demo chain
├── mintid_chip_summary.py        │  (everything you need to
├── mintid_pm3_clone.py           │   reproduce the demo)
├── mintid_capture_and_clone.py   │
├── mintid_fake_server.py         │
├── mintid_dns_spoof.py           │
├── mintid_apk_repoint.py         │
├── mintid_oracle.db              │  Three coin records
├── fake_server_images/           │  HAND_POURED_BAR JPEG
├── README.md                     │
├── HANDOFF.md                    │  this file
├── DISCLOSURE_DRAFT.md           ─┘  the deliverable
│
└── archive/                       Investigative scripts. One-time use.
    ├── mintid_probe.py            5 hard-capped server probes
    ├── mintid_explore.py          Endpoint-discovery scanner
    ├── mintid_chip_interrogate.py Deeper active chip probes
    ├── Harness.java               Jackson 2.14 byte-equivalence harness
    ├── ProductRequestBody.java    Android POJO for the harness
    ├── compare_java_vs_python.py  Python-vs-Java byte diff
    └── README.md                  What's in archive and why
```

## Style notes for future Claude

- User values directness. No moralising about scope.
- **Don't speculate when bytecode is available.** User has called this out twice. Use androguard.core.dex to inspect rather than guessing.
- When findings contradict previous claims, say so plainly. We made several wrong calls during chip characterization (lock-byte interpretation, layout assumptions, magic variant detection) — all caught by running real analysis instead of pattern-matching to expectations.
- Hard-cap and rate-limit anything that hits the live API. The 50-request budget across all probe scripts hasn't been exceeded.
- User has DMCA §1201(f) standing on coins they own, conducts disclosure research professionally. Treat them as a peer.
- **Standing redaction rule**: the user's DeviceID (the iOS UUID captured during the Login-form DNS-spoof test) must be FULLY redacted everywhere it appears in the disclosure, bundle, or any output — not partially. Use `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` as the placeholder. Same rule applies to any captured credential, password, or session token: full redaction, never partial. The real values are retained only in the researcher's own working notes and may be supplied to vendors privately on request.
