# Architectural vulnerabilities in MintID NFC verification for precious metals

**Date**: 2026-05
**Affected systems**: MintID Android app v1.8 and earlier (analysed via APK disassembly); MintID iOS app (analysed via empirical traffic capture and DNS-spoof end-to-end testing on stock iPhone); the production verification API at `mintidapi.droisys.info`; all NFC-tagged precious-metal products marketed by MintID/Highland Mint/Identiv as "AES-128 encrypted tamper-proof" since 2018.
**Research basis**: DMCA §1201(f) interoperability research on coins owned by the researcher. Static analysis of the publicly distributed Android APK, traffic to the public-facing verification API, and physical-layer interrogation of three coins purchased at retail.
**Status**: Disclosed to MintID/Highland Mint/Identiv on [DATE] via [CHANNEL]. Public release scheduled for [DATE+90] absent vendor request for extension.
**Use of vendor-published material**: This document quotes from Identiv- and MintID-published marketing materials for the purpose of critical commentary, criticism, and security research. Such quotation constitutes fair use under 17 U.S.C. §107 and analogous provisions in other jurisdictions. All quoted material is attributed to its source with full URL.

---

## Executive summary

MintID markets NFC-tagged precious-metal products with the published claim that "MintID chips cannot be copied or cloned" (Identiv–MintID case study PDF, December 2021). The implemented verification system does not deliver on that claim. Specifically:

The chip stores a static 128-bit identifier in plaintext NDEF format. The server transmits responses over plaintext HTTP using a credential pair shared by every install of the app. The server does not perform AES decryption during verification — it treats the cryptogram as an opaque database key. The server response is fully deterministic for a given (UID, cryptogram) tuple, with no nonce, timestamp, or per-tap freshness. The chip has no tamper-evidence circuit; physical tamper-evident packaging on the coins is decorative.

These properties combine to enable a complete bypass of the authentication system. **An attacker with brief physical access to any genuine MintID coin — long enough for a single NFC tap — can clone its identity onto a $5 commodity NFC chip. The cloned chip authenticates against MintID's server identically to the genuine coin, returning the same product information and the same TagNumber.**

The researcher demonstrated this end-to-end against MintID's production system. Total reproduction cost was under $100 in hardware (Proxmark 3 Easy + magic NFC chip + a PC/SC NFC reader). Total time per clone is approximately 30 seconds.

The remainder of this document details the architectural failures, the empirical demonstration, and recommendations for remediation.

---

## Marketing claims vs. observed behaviour

### Published vendor sources

The vendor relationship and product positioning are documented in the following Identiv-published sources, which the researcher has reviewed in full:

- **Identiv MintID Case Study (web page)**, December 6, 2021 — https://identiv.com/case-study/mintid-case-study/
- **Identiv MintID Case Study (PDF)** — https://files.identiv.com/case-studies/identiv-mintID-caseStudy.pdf
- **"Meet TOM: Introducing the Industry's Most Dynamic On-Metal RFID Solution"** (Identiv blog), February 10, 2022 — https://identiv.com/blog/meet-tom-introducing-the-industrys-most-dynamic-on-metal-rfid-solution/

Additional public marketing material exists (NFC Forum listings, RFID-industry trade press, social-media announcements). Recipients of this disclosure are encouraged to review the broader corpus; the three sources above are sufficient on their own to establish the marketed claims this disclosure refutes.

### Founder-attributed claims

The Identiv case study attributes a statement to MintID's founder Corey Maita describing the Identiv partnership as a way to "guarantee the authenticity of each product" and "prevent counterfeiting of some of the world's most valuable items." (The web and PDF versions of the case study differ slightly in tense around the anti-counterfeiting promise, but the substance is the same.) The full statement is reproduced in the cited source.

### Marketed technical properties

The PDF case study describes the deployed solution using language summarised here in paraphrase, with the source URL provided above for verbatim review:

- The product is positioned as an AES-128-encrypted NFC anti-counterfeiting ecosystem
- The supplied NFC tags are described as highly secure, anti-counterfeit, brand-protection-grade, with tamper-proof functionality
- Each product is described as outfitted with a custom-designed NFC chip carrying a unique encrypted, tamper-proof digital certificate, instantaneously authenticated and "guaranteed genuine" by an ISO-9001-certified minting facility via the MintID mobile app
- The chips are described as not copyable or cloneable, with locked encryption tying the physical product to a cloud-based digital record
- Both Android and iOS mobile apps are described as offering real-time authentication
- Scope figures cited in the case study include "Over 80,000 registered authentications" and a sales figure of approximately 200,000 ounces of silver moved in a five-month window

The Identiv "Meet TOM" blog post describes the Tag On Metal label line as the physical-layer foundation enabling on-coin NFC anti-counterfeiting, marketing the labels for performance on metal surfaces.

### Findings vs. claims

The findings in this disclosure directly contradict each of the marketed claims:

| Marketed claim (verbatim from PDF case study) | Observed reality | Finding(s) |
|---|---|---|
| "tamper-proof NFC tags" / "tamper-proof functionality" | Chips have no tamper-evidence circuit. The visible label is decorative; peeling it off, or severing the Y-shaped die-cut notches that are designed to deform on removal, does not change chip behavior or the server's verification result. | 8 |
| "AES-128 bit encryption with NFC technologies" | The server does not decrypt the chip cryptogram during verification. Bit-flipping the cryptogram changes the response from "in DB" to "not in DB" — proving the server does string-matching, not decryption. | 3 |
| "MintID chips cannot be copied or cloned" | A genuine coin's UID and NDEF cryptogram were captured via a $30 NFC reader and written to a $5 magic chip. The cloned chip produced byte-equal server responses to the genuine coin. Demonstrated end-to-end in approximately 30 seconds. | 4, 5, 6, 9, 10, 11 |
| "locked encrypted microchips" | The chip's NDEF area is readable without authentication. The chip transmits the same cryptogram bytes on every read with no challenge-response mechanism. | 3, 5, 6 |
| "custom-designed NFC chip [with] a unique encrypted, tamper-proof digital certificate" | Two distinct chip-supplier families were observed for the same SKU (1SBUFFR-New): genuine NXP NTAG 213 (UID prefix `04...`) and 8-byte UID non-NXP clones (UID prefix `AD...`). Both authenticate as Genuine. The "digital certificate" is a 32-character ASCII string in plaintext NDEF, with no signature, no chain of trust, and no cryptographic verification. | 3, 10, 11 |
| "instantaneously be authenticated and guaranteed genuine by the ISO: 9001 facility that minted it" | Authentication does not depend on facility-of-origin verification. The server compares (UID, cryptogram) against a database lookup with no provenance check. The same architecture would authenticate any (UID, cryptogram) tuple ingested through any path, including operator data-entry, leaks, or compromise. | 1, 2, 3, 4, 5, 6, 7, 9, 12 |

Most consequentially, the case study's published assertion that "MintID chips cannot be copied or cloned" is the principal anti-counterfeit promise made to investors. The empirical demonstration in this document refutes it. The cloning operation requires neither cryptographic key material, nor insider access, nor specialized equipment beyond commodity research hardware; it requires only brief NFC-tap proximity to any genuine coin, which is an everyday occurrence in the secondary precious-metals market.

The 80,000-registered-authentications figure cited in the case study indicates non-trivial deployment of the affected products. Coins issued under this program are presently in circulation in the secondary precious-metals market, where the MintID app verification result is the principal authenticity signal communicated to end purchasers.

---

## Findings

### 1. Plaintext HTTP, no TLS

The verification endpoint is served over HTTP, not HTTPS:

```
POST http://mintidapi.droisys.info/api/ProductAuthentication/SecuredScanProduct
```

The path contains the word "Secured" and the endpoint suffix is "Secured." Neither word is technically defensible. Every (UID, cryptogram) tuple traverses the network in plaintext, every response with TagNumber and product details traverses back as plaintext JSON. Anyone on the same wifi network as a MintID app user, or on any upstream ISP path, can passively log every coin verification happening.

### 2. Hardcoded shared credentials in every install

Every APK ships with the same authentication pair:

```
OrgAccessID:      000000000000000000000000  (24 ASCII zeros)
AuthorizationKey: 2I0mGELp                  (8 ASCII chars)
```

Both values are baked into the OkHttp interceptor in `HelperTagReader$1/$2/$4/$5` and sent in the HTTP body of every guest verification request. Extracting them takes approximately 10 seconds with `apktool` and `grep`. There is no rotation mechanism. Every install of the MintID app uses the same credential pair, and any party who has ever extracted them retains permanent access to the verification API.

The OrgAccessID being 24 zeros suggests either a default/uninitialized organisation bucket or an explicit "guest" channel. Either interpretation is operationally indistinguishable: the credentials function as authentication for an anyone-allowed bucket.

### 3. The cryptogram is not decrypted server-side

The product is marketed as using AES-128 encryption. The researcher empirically tested whether the server actually performs AES decryption during verification.

A "cryptogram-bit-flip" experiment was conducted: send the server a known-good cryptogram with one bit of byte 0 flipped, paired with the corresponding genuine UID. AES is an avalanching cipher; flipping a single ciphertext bit produces uniformly random plaintext. If the server were decrypting and validating the cryptogram, it would return `NTAGTTStatus: 2` (the status code observed for clearly junk values, e.g., all-zeros).

Observed result across 8 single-bit mutations: the server returned `NTAGTTStatus: 0, Product: null` — the same status code observed when the cryptogram is in the database but the (UID, crypto) tuple doesn't match. This indicates the server is doing string-matching on opaque identifiers, not AES decryption.

Conclusion: AES is used at personalisation time to generate cryptograms with a random-looking distribution, but the verification path does not involve any decryption. The cryptogram is functionally a static 128-bit identifier — equivalent to a UUID stored on the chip.

### 4. Server response is fully deterministic per tuple

Across 50+ verification requests for the same (UID, cryptogram) tuple, spanning at least 12 seconds and multiple HTTP connections: the response body was byte-identical. SHA-256 of the response body matched across all replays.

There is no nonce in the request, no timestamp, no challenge-response, no session token, no per-tap entropy of any kind. Every successful authentication of a given coin produces the same response forever.

### 5. No replay protection

The combination of findings 1, 2, and 4 means an attacker who passively observes a single legitimate verification can replay the captured request indefinitely. The server cannot distinguish a replay from a fresh scan because the request body contains no time-varying or freshness data.

### 6. The (UID, crypto) tuple is required, but nothing else is

Tested via "uid-bit-flip" and "objectid-nearby-batch" probes: the server requires both halves of the (UID, cryptogram) tuple to match a database record. Neither half alone is sufficient. This is appropriate. However, both halves of the tuple are captured together in a single legitimate verification — there's no security benefit from requiring both when both are equally exposed.

### 7. Three-state response oracle leaks DB membership

The server returns three distinguishable response states:

| Server returns | Interpretation |
|---|---|
| `NTAGTTStatus: 2, Product: null` | Cryptogram value not in the MintID database |
| `NTAGTTStatus: 0, Product: null` | Cryptogram value IS in the database, but tuple mismatch |
| `NTAGTTStatus: 0, Product: <record>` | Tuple match, full record returned |

This means an attacker who obtains a candidate list of cryptograms from any source (manufacturing leak, supply-chain insider, scraped from a personalisation tool) can use the API to filter the list down to MintID-issued values, without needing the corresponding UIDs. With 350,000+ chips currently issued (per the highest TagNumber observed) and no rate limiting on the server side, this filtering is feasible in minutes for any candidate list.

Defense-in-depth failure: the server should return a uniform "auth failed" response in all failure modes, eliminating the membership oracle.

### 8. Tamper evidence is decorative

One of the three coins examined had its visible foil/scallop "tamper-evident" label peeled off prior to scanning. The official MintID app verified the coin as Genuine and rendered the GenuineProductDetail screen with full product information.

In a separate test, the Y-shaped die-cut notches on the visible label of a second coin were intentionally severed before scanning. These notches are the destructive-removal feature of the security label — they are designed to tear and deform when the label is lifted, providing the visible "tamper-evident" signature that gives the label its anti-counterfeit value. After breaking the notches, the chip authenticated normally; the official MintID app rendered the GenuineProductDetail screen with no tamper indication of any kind.

The chip has no tamper-detection circuit. There is no conductive tamper loop wired through the label substrate, no destruct-on-removal trace, and no electrical pathway through the Y-notches that would change chip state when severed. The label is a printed adhesive sticker whose only "anti-tamper" property is human-visible deformation when removed — and that deformation is invisible to the chip, the app, and the server. The cryptogram does not encode tamper state. The server has no signal of physical tampering.

This means the tamper-evident packaging functions only as a visual cue to a human inspecting the coin in person. It does not gate digital authentication in any way. A clone of the chip's data into a fresh, unbroken label substrate produces a coin that is digitally indistinguishable from a genuine one *and* visually indistinguishable as well — defeating both the technical and visual layers of the marketed anti-counterfeit story simultaneously.

### 9. NXP originality signatures are not used

The genuine coins use NXP NTAG 213 chips, which support the NXP Originality Signature feature: NXP signs each chip's UID with NXP's private key at fab time, and verifying parties can check the signature with NXP's published public key via the `READ_SIG` (`0x3C`) command. This is a free chip-attestation primitive — proof that a chip is from NXP and not from a clone.

Bytecode analysis of the MintID Android app confirms it never sends the `READ_SIG` command. The originality signature is never read by the app, never included in the request body, and never verified against NXP's public key. The chip's ability to attest its own genuineness is unused.

This single design decision is the difference between an authentication system that resists cloning and one that does not. NXP provides the primitive specifically to prevent the kind of clone-and-tap attack demonstrated in this disclosure. MintID's app does not invoke it.

### 10. Two chip-supplier families used for the same SKU

Of the three coins examined under the same SKU (`1SBUFFR-New`, "1oz Silver MintID Buffalo"), two used genuine NXP NTAG 213 chips (UIDs starting `04...`, 7-byte UIDs, FF FF lock bytes) and one used a non-NXP clone chip (UID starting `AD...`, 8-byte UID, no spec-compliant lock bytes). All three were verified as Genuine by the official MintID app.

The server's response identifies the manufacturer of these 1oz Silver MintID Buffalo Round coins as **Highland Mint** (`Manufacturer: "Highland Mint"`, SKU `1SBUFFR-New`). Highland Mint is a U.S.-based bullion mint headquartered in Melbourne, Florida (https://www.highlandmint.com/), and the named mint in MintID's product database for this SKU regardless of which underlying chip family the coin shipped with.

A separate SKU examined — the 5oz MintID Silver Buffalo Bar (`5MINTBUFF`) — uses a real NXP NTAG 213 chip (UID `04C83E12087484`) and its server-side product record lists `Manufacturer: "Cut Saw"`. Cut Saw is a Texas-based custom-bullion mint (https://cutsaw.com) that markets specifically to precious-metals dealers seeking to leverage their own branding or custom dies on contract-minted bullion. So the manufacturer field is correct, just unfamiliar — different SKUs in MintID's product line are physically minted by different contract mints (Highland Mint for the Buffalo Round, Cut Saw for the Buffalo Bar).

This means MintID's chip-supplier discipline is loose enough that customers cannot rely on the underlying silicon being NXP — but the manufacturer-field heterogeneity itself is documented production data, not a data-quality issue. From a verification standpoint the chip-supplier point is consistent with finding 9 — since the app doesn't verify NXP originality signatures anyway, the chip supplier doesn't matter to the authentication flow. The supply-chain transparency is a positive, but the authentication system fails to use it.

### 11. App accepts non-spec-compliant chip layouts

The clone coin (Coin 1, UID `AD...`) does not follow the NFC Forum Type 2 Tag spec at the byte layout level. Specifically: the Capability Container is at offset 0 instead of offset 12 (a "cc_at_origin" layout); there are no lock bytes in the spec-required position; the chip claims an unusual NDEF Forum version `0x40` that does not exist in any released spec. Despite this, both Android's NFC stack and Apple's CoreNFC parse the chip successfully and the MintID app accepts it as Genuine.

Implication: clones do not need to even pretend to be spec-compliant NFC tags. Any chip that produces the right (UID, cryptogram) bytes through any reasonable read path will be accepted.

### 12. No request signing or HMAC

The request body (TagUID, TagCrypto, OrgAccessID, AuthorizationKey, plus device metadata fields like DeviceId, Latitude, Longitude, BatteryStatus) is not signed. The server has no way to verify the request originated from the MintID app rather than a `curl` one-liner. Combined with the static credentials, anyone can construct a valid request body in any HTTP client.

### 13. No observed rate limiting

The researcher's probe runs sent 43+ requests in rapid succession (with self-imposed 0.5s spacing for ethical reasons). No 429 responses, no captcha challenges, no IP blocks were observed at any point. The server appears to have no rate limiting on the verification endpoint.

A motivated attacker could probably run thousands of requests per minute. Combined with finding 7 (the membership oracle), this enables bulk database membership testing if any cryptogram candidates are obtained.

### 14. Production IIS leaks detailed error messages

`MessageDetail` field present in 404 responses, with route-resolution details that revealed which legacy endpoints have been retired server-side. Minor on its own; suggests `customErrors mode="Off"` or equivalent in the production deployment, which is a defense-in-depth misconfiguration.

### 15. Image references are server-controlled with no client-side validation

The product photo displayed on the app's GenuineProductDetail screen is fetched via `GET /api/Document/GetImage?documentID=<id>`, with `<id>` a 24-character ObjectID supplied by the server in the previous `SecuredScanProduct` response (`Result.Product.ProductImages[].ProductImageDocumentID`). The official iOS app fetches and renders whatever bytes the server returns at that documentID, with no cross-check against product type, SKU, or any expected content hash. A network attacker (see finding 1) who controls responses can substitute arbitrary image content. Empirically demonstrated 2026-05-02: the official iOS app rendered a hand-poured silver bar photograph as the "product image" for an item labeled "1oz Silver MintID Buffalo Round" without any visual indication of the substitution.

### 16. App accepts dual content-type encodings interchangeably

The Android app uses Retrofit's JSON converter and posts request bodies as `application/json; charset=UTF-8`. The iOS app posts the same fields as `application/x-www-form-urlencoded; charset=utf-8`. The production verification endpoint accepts both encodings transparently — the server's model binder deserializes from whichever encoding is presented. Combined with finding 12 (no request signing), this means an attacker writing a custom client has no encoding or framing constraints to satisfy beyond providing the right field names. Documented through differential observation of Android (`okhttp/3.14.9` user-agent, JSON body) and iOS clients against the same endpoint.

### 17. Plaintext credentials trivially captured by network position

The login endpoint `POST /api/AccountAccess/Login` accepts the same plaintext-HTTP transport as verification. A user-supplied iCloud-Keychain-generated password was captured cleartext by the researcher 2026-05-02 by configuring an iPhone's wifi DNS to point at the researcher's laptop, redirecting `mintidapi.droisys.info` to a local Flask server, and waiting for the official iOS app's login form to be submitted. No app modification, no jailbreak, no certificate-pinning bypass — the credential was sent in plaintext over HTTP and captured at the application layer. The same exposure applies to the Logout endpoint, and to any other authenticated endpoint, including session token retrieval. This is a downstream consequence of finding 1 (plaintext HTTP) but rises to its own finding because:

- It is empirically demonstrated against the production app, not theoretical
- The captured credential was a strong, unique, password-manager-generated value (i.e., not weakened by user choice) — finding 1's transport-layer vulnerability negates user-side password hygiene entirely
- It implicates not just the verification flow but every account-related operation in the app
- The threat model (rogue wifi AP, compromised home router, ISP-level interception, hostile coffee-shop network) is realistic for a consumer-facing app frequently used outside the home

The architectural failure is the absence of TLS, request signing, and certificate pinning — any one of which would have prevented this capture.

Captured request, abridged and with the user's email and password replaced by **synthetic placeholders of the same shape and length**:

```
POST /api/AccountAccess/Login HTTP/1.1
Host: mintidapi.droisys.info
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Content-Length: 130
User-Agent: MintID/1.8 CFNetwork/...

DeviceID=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
&DeviceType=iOS
&UserName=example-relay-9x%40icloud.com
&Password=fxqpiv-2nujte-Cabzyk
```

The placeholder values `example-relay-9x@icloud.com` and `fxqpiv-2nujte-Cabzyk` are synthetic; the actual captured values were of the same form and length (Apple's iCloud Keychain hide-my-email alias format and 20-character three-block password format respectively) and have been retained for evidentiary purposes but are not reproduced in this disclosure. MintID is encouraged to identify the affected account from server-side logs and notify the user to rotate.

### 18. Production system history and supply chain visible from server responses

Server responses to verification requests include MongoDB ObjectID values for the Product, Organization, and Brand records. The first 4 bytes of a MongoDB ObjectID encode the document creation timestamp as a 32-bit Unix epoch — a documented and stable property of the ObjectID format. Decoding the ObjectIDs returned by the production verification API yields a clear timeline of the system's operational history, plus visible supply-chain information:

**Two SKUs queried, two different contract mints producing them.**

| SKU | ProductName | Manufacturer field | Product ObjectID | Decoded creation date |
|---|---|---|---|---|
| `1SBUFFR-New` | 1oz Silver MintID Buffalo (round) | `Highland Mint` | `5e94daa5fb7f1d05904fdb2f` | **2020-04-13 21:33:25 UTC** |
| `5MINTBUFF` | 5oz MintID Silver Buffalo Bar | `Cut Saw` | `5f723876fb7f1d0cd8779f21` | **2020-09-29 06:46:14 UTC** |

Both manufacturer values name real, identifiable bullion mints — Highland Mint (Melbourne, Florida) and Cut Saw Custom Minting (Texas, https://cutsaw.com), the latter explicitly catering to precious-metals dealers who contract out branded bullion production. This is documented supply-chain transparency: MintID is a brand and software-and-NFC-provenance layer; physical minting is contracted to multiple specialist mints depending on the SKU. Useful context for a buyer, and for a disclosure recipient understanding the multi-party scope.

**System has been operating since at least 2017.**

Decoding the OrganizationID and BrandID ObjectIDs returned by the production server:

| Field | ObjectID | Decoded creation date |
|---|---|---|
| OrganizationID (MintID/Droisys org) | `594b66c071945a30d03d28bf` | **2017-06-21 17:49:36 UTC** |
| BrandID (MintID brand record) | `5c268bb659a43d0d34ddc5ae` | **2018-12-28 21:50:14 UTC** |
| Product._id (1oz Silver Buffalo Round) | `5e94daa5fb7f1d05904fdb2f` | **2020-04-13 21:33:25 UTC** |
| Product._id (5oz Silver Buffalo Bar) | `5f723876fb7f1d0cd8779f21` | **2020-09-29 06:46:14 UTC** |

The 2020-04-13 date for the Buffalo Round product record places its creation about three weeks before the May 2020 NFC-Forum-published joint Identiv/MintID press release announcing the product line — i.e., products were being staged in the production database in advance of public announcement, consistent with normal product-launch cadence.

**System is actively maintained as of 2026.**

The `Product.UpdatedDate` fields returned by the production server show that records continue to be edited:

| Product | Most recent UpdatedDate observed |
|---|---|
| 1oz Silver Buffalo Round | `2025-10-24T16:53:55.168Z` |
| 5oz Silver Buffalo Bar | `2026-03-23T17:17:44.757Z` |

The system is therefore not abandoned. Records continue to be edited within weeks of disclosure preparation. This is operationally relevant for the impact assessment: the architectural vulnerabilities documented in findings 1-9 affect a live, maintained, growing deployment — not a legacy or pilot system.

**TotalNFCCount reveals deployment scale.**

The `Result.Product.TotalNFCCount` field returned by the verification API is a per-SKU counter of issued chips. Observed values:

| SKU | TotalNFCCount | Material | Implied troy-ounce volume issued |
|---|---|---|---|
| `1SBUFFR-New` (1oz Round) | 156,638 | 1 Troy Ounce | ~156,638 troy oz |
| `5MINTBUFF` (5oz Bar) | 98,491 | 5 Troy Ounces | ~492,455 troy oz |

For just these two SKUs out of MintID's broader catalog, the system has authenticated approximately 255,000 NFC-tagged precious-metal items representing roughly 649,000 troy ounces of silver. The highest `TagNumber` (a separate global serial counter) observed during this research was 349,418 from the Buffalo Bar coin, suggesting that across all SKUs combined MintID has issued at least ~350,000 NFC-tagged items if numbering started near 1, or substantially more if numbering started higher. The marketing claim cited in section "Marketing claims vs. observed behaviour" referencing "200,000 ounces of silver in the last five months" is therefore broadly consistent with the deployment scale visible from the production database, though the disclosure-time totals are several multiples higher.

This finding is included because it materially affects the impact assessment: the cloning vulnerability documented in findings 1-9 affects an installed base that is large, growing, and being actively maintained — not a small pilot or legacy deployment.

---

## Empirical demonstration

The researcher demonstrated end-to-end clone-and-tap against MintID's production system using the following procedure:

1. **Capture**: Place a genuine 1oz Silver MintID Buffalo Round (UID `04C3434A9E7384`) on a PC/SC NFC reader (ACS ACR1552). A small Python script reads the chip's NDEF stream, extracts the cryptogram (`adf9dc538aa58f88dd444b875a255d15`), and POSTs to MintID's verification API. Server returns `Product: 1oz Silver MintID Buffalo, TagNumber: 301949, NTAGTTStatus: 0`. Baseline genuine confirmed.

2. **Write**: Place a magic Gen 2 / CUID Ultralight-C UID Modifiable chip (a Chinese commodity chip purchased for under $5) on a Proxmark 3 RFID research tool. Issue a `setuid` command to write the genuine coin's UID, then issue 12 `wrbl` commands to write the captured NDEF stream verbatim (Capability Container, NDEF TLV header, Text record, 32-character ASCII cryptogram, terminator).

3. **Test**: Move the cloned magic chip to the ACR1552 reader. Run the same capture script. Result: chip reports UID `04C3434A9E7384`, cryptogram extracts as `adf9dc538aa58f88dd444b875a255d15`, server returns `Product: 1oz Silver MintID Buffalo, TagNumber: 301949, NTAGTTStatus: 0`. **The response from the server is byte-equal to the genuine coin's response. SHA-256 hashes match.**

4. **App verification**: Tap the cloned magic chip with the official MintID app on iPhone. The app renders the GenuineProductDetail screen identically to the tap of the genuine coin: same product image, same TagNumber, same authenticity declaration.

5. **Server impersonation via DNS spoofing**: Configure the iPhone's wifi DNS to point at the researcher's laptop. Run a small DNS server that resolves `mintidapi.droisys.info` to the laptop's LAN IP and forwards everything else upstream. Run a Flask server on port 80 that responds to `POST /api/ProductAuthentication/SecuredScanProduct` and `GET /api/Document/GetImage?documentID=<id>`. Tap any chip with the official MintID app. Result: the app's GenuineProductDetail screen renders with operator-controlled values for ProductName, ProductDescription, Material ("Metal Content"), TagNumber ("Serial Number"), and the product image. No app modification was performed; the iPhone was running an unmodified MintID build from the App Store. The screen displayed `1.82 Troy Oz MintID Imperial Credit / Hand crafted elite pwnage pour / 1.82 Troy Ounce, and a splash of Unobtainium / Serial 31337` next to a hand-poured silver bar photo, all under the standard "GENUINE / MintID Certified" banner.

6. **Credential capture via the same DNS-spoof position**: With the same DNS-spoof setup, navigate to the app's Login screen and submit a login form. Result: the researcher's Flask server received `POST /api/AccountAccess/Login` with body `DeviceID=<UUID>&DeviceType=iOS&UserName=<email>&Password=<plaintext>` and logged the cleartext credentials. The captured password was a 20-character iCloud-Keychain-generated value, demonstrating that even strong, unique passwords offer no protection against this transport-layer exposure. Returning a synthesized successful Login response (`SessionToken: fake-session-<uuid>`, `Status: 1`) drove the app into its post-login state without any further authentication challenge.

End-to-end time: approximately 30 seconds from genuine-coin capture to clone-tap verification. Cost of materials: approximately $5 for the magic chip plus ~$60 for the Proxmark 3 (or $30-40 for an NFC-write-capable smartphone with appropriate magic-chip software).

The chip used for the clone is materially different from the genuine NXP chip: it has no NXP originality signature, it does not implement NXP-specific commands (`GET_VERSION`, `READ_SIG`, `FAST_READ`, `PWD_AUTH`), and it exposes 256 bytes of memory rather than NTAG 213's 180. None of these differences are detected by the MintID app or server, because the verification path queries only anticollision (UID) and READ commands (NDEF stream) — both of which the magic chip implements identically to the genuine NTAG.

### Physical reproduction notes

Two practical observations from the empirical demonstration are worth documenting, both because they constitute the *only* meaningful friction an attacker encounters and because they help characterize the chip-on-metal antenna's real-world behaviour:

- **Smartphone NFC alignment is finicky.** The researcher's iPhone 16 Pro initially failed to read the chips on multiple attempts. The iPhone 16 Pro's NFC antenna is in a small region near the top edge of the device, and finding it relative to a coin-embedded sticker-form-factor chip requires deliberate alignment. After the antenna's exact location was identified through repeated attempts, scanning became reliable — but the first-time experience for an everyday user is one of "tap, fail, retry, eventually succeed." This is consistent with the user-experience reports for any consumer NFC-on-metal product and is not a security feature; an attacker simply experiences the same friction once and then knows where to tap.

- **Reader detuning when chip is on a metal coin is significant.** The researcher's ACR1252U PC/SC NFC reader has trouble reading the chip while it is mounted to the metal coin substrate. The same chip, lifted off the metal (off-coin, in free air), reads cleanly without alignment effort. On-coin reads succeed only with the coin in very specific physical orientations relative to the reader's antenna. This is the classic detuning behaviour caused by eddy-current losses in the metal substrate, which the Identiv "TOM" (Tag-On-Metal) ferrite shielding partially compensates for but does not eliminate. For an attacker, this means the *capture* step (reading the genuine coin's UID and NDEF cryptogram) requires patience or removing the chip from the coin; the *clone-write* step uses a free-standing magic chip and has no such issues, and the *cloned-chip read* by the official MintID app on a smartphone is then unencumbered by the metal substrate (because the magic chip can be carried in a sticker, card, or any non-metal substrate of the attacker's choice).

Importantly: neither of these frictions limits the attack. They are present even for legitimate scans of genuine coins by their owners. The attacker's experience reproducing the attack is no worse than a legitimate owner's experience using the product as marketed.

---

## Threat model

The minimum capability required to mount the demonstrated attack is:

- Brief physical proximity (NFC tap range, < 5 cm) to a genuine MintID coin, ONCE
- An NFC reader capable of reading Type 2 NDEF tags (any NFC-capable smartphone, any USB PC/SC reader)
- A magic NFC chip ($1-5)
- An NFC writer capable of UID modification (Proxmark 3, Chameleon, or an Android phone with appropriate software)

The attacker does **not** need:

- Knowledge of any cryptographic key
- Persistent access to the genuine coin
- Network access to MintID's infrastructure
- Insider information about MintID's manufacturing or personalisation process
- Access to the genuine coin during verification

The attack scenarios this enables include:

- **Resale fraud**: An attacker who briefly handles a genuine coin (e.g., during a sale negotiation, at a coin show, or as a friend/family member borrowing it for inspection) can subsequently produce arbitrary clones that authenticate as the original.
- **Inventory shrinkage**: A retail employee with access to coins in inventory can clone every coin they handle, then sell the clones as genuine.
- **Counterfeit precious-metal substitution**: An attacker can produce a clone of a genuine coin's NFC chip and embed it into a base-metal counterfeit. The counterfeit coin will scan as genuine via the official MintID app — which is the primary authenticity check most buyers will perform. Combined with reasonable visual replication of the coin face, this defeats the principal anti-counterfeit feature MintID markets.
- **Bulk-scale cloning**: A wholesale attacker who obtains a list of valid (UID, cryptogram) tuples — through the membership oracle, an insider leak, or any other source — can produce arbitrary numbers of authenticating clones without ever touching a genuine coin.
- **Credential interception**: An attacker on the network path between the user's device and MintID's API (rogue wifi AP, compromised home router, ISP-level interception, hostile coffee-shop network, malicious DNS) can intercept user passwords and session tokens in plaintext. Demonstrated empirically; iCloud-Keychain-generated passwords offered no protection because the exposure is in the transport, not the credential. An attacker who captures a session token can subsequently impersonate the user against MintID's account-management endpoints without ever needing the password.
- **Phishing redirection**: The same network-path attacker can redirect the app to attacker-controlled infrastructure. Combined with the missing TLS, the app has no way to detect that responses are not coming from MintID. An attacker can render attacker-controlled product information, attacker-controlled images, and attacker-controlled "tampered" warnings, including warnings designed to drive users toward fraudulent contact channels.

---

## Remediation recommendations

In rough order of impact, with effort indication:

1. **Migrate to chip-attested cryptography (high effort, definitive fix).** Replace NTAG 213 with NTAG 424 DNA or equivalent in future production runs. NTAG 424 DNA is made by NXP, costs approximately $0.15-0.20 more per chip than NTAG 213, and supports per-tap challenge-response signed by a chip-resident secret. The standard SUN (Secure Unique NFC) message format with rotating MAC is well-documented and supported by Android, iOS, and most NFC SDKs. This is the only fix that addresses the architectural failure rather than mitigating its symptoms.

2. **Verify NXP originality signatures (low effort, partial fix for currently-deployed inventory).** Add `READ_SIG` to the app's chip-read flow, transmit the signature in the request body, verify server-side against NXP's published public key. This makes clone-on-magic-chip attacks fail (because magic chips cannot produce a signature that verifies against NXP's public key). Does not fix the static-cryptogram and replay issues, but raises the cost of cloning significantly — attackers would need to source genuine NXP NTAG 213 chips with attacker-controlled UIDs, which require substantial scale and supply-chain access. This change can be deployed retroactively to all currently-deployed coins (assuming they're all on real NXP NTAG 213 chips — see finding 10 for the caveat about clone-chip coins already in the wild).

3. **TLS / HTTPS with certificate pinning (table stakes, immediate, urgent).** Should have been there from day one. The "Secured" in the endpoint name is technically false until this is done. With finding 17 (empirically captured plaintext credentials), this is no longer a defense-in-depth concern; it is the active attack surface that exposes user passwords to anyone on the network path. Certificate pinning prevents downgrade and trusted-CA attacks; without pinning, even properly-deployed TLS can be defeated by an attacker who can install a profile, root cert, or proxy on the user's device.

4. **Per-install authentication tokens (medium effort).** Replace the hardcoded shared credentials with per-install tokens issued via Play Integrity API or App Attest. Tokens can be rotated and revoked.

5. **Uniform failure response (immediate).** Server should return identical `Product: null` (or equivalent) responses for both "cryptogram not in DB" and "tuple mismatch" cases. Eliminates the membership oracle.

6. **Server-side rate limiting (immediate).** Per-IP and per-token rate limiting on the verification endpoint, with bursts permitted to allow normal user behaviour but bulk enumeration prevented.

7. **Request signing (medium effort).** HMAC the request body using the per-install token from #4. Server verifies signature before processing. Combined with #4, prevents anyone from constructing arbitrary requests with stolen credentials.

8. **Suppress IIS detail messages in production.** `customErrors mode="On"` or equivalent. Defense-in-depth.

The deepest fix is #1 — moving from "static identifier lookup" to "cryptographic verification per tap." Without #1, the system is fundamentally vulnerable to clone-on-capture regardless of what else is fixed. With #1, all the other findings become defense-in-depth concerns rather than primary vulnerabilities.

If the cost of #1 is prohibitive for currently-deployed inventory, #2 (originality signature verification) is a meaningful retroactive partial fix that can be deployed via app update without requiring chip changes.

---

## App vendor identification

The MintID Android and iOS apps are developed by **Droisys**, a software-development services firm headquartered in Fremont, California, with delivery offices in India (Noida, Ahmedabad, Nagpur, Hyderabad) and Poland (Julianów). This is corroborated by the production verification API hostname (`mintidapi.droisys.info`), which is on the Droisys-owned `droisys.info` domain rather than on a MintID-owned domain.

Droisys's public-facing materials are at:

- https://droisys.com/about-us/ — corporate about page, leadership, office locations
- https://www.linkedin.com/company/droisys/ — LinkedIn company page

The Droisys About-us page lists the company's executive leadership, including President Sanjiv Goyal, CEO Amit Goel, CIO Dean Lane, and a number of VP- and Director-level roles. The page does not mention MintID or the precious-metals-authentication product line specifically; Droisys appears to operate as a contracted development house with multiple unrelated app and platform products in their portfolio (e.g., "Player 360," "Account360.ai," gaming-industry tooling).

### Identified developer

Public professional profiles identify **Vishal Mishra** as one of the developers who worked on the MintID Android app while employed at Droisys India Pvt. Ltd. as Sr. Software Engineer:

- Bold profile listing the MintID Play Store URL (`com.mintid.production`) among his projects: https://in.bold.pro/my/vishal-mishra-240724000031
- LinkedIn (Sr. Software Engineer at Droisys, Noida): https://www.linkedin.com/in/vishal-mishra-673342105/
- The Org corroboration of role and tenure (at Droisys since January 2021): https://theorg.com/org/droisys/org-chart/vishal-mishra
- GitHub (`luckvishal`), self-described "Mobile Application Developer" at Droisys, Noida: https://github.com/luckvishal — repositories include `NFC-Reader`, `RetrofitSample` ("json parsing through Retrofit and Jackson library"), and `VolleySample`. The public-portfolio toolset (Retrofit + Jackson + NFC) matches the libraries observed in the disassembled MintID APK.

This is included as a routing aid for Droisys to identify the relevant internal team. The disclosure is not directed at any individual developer; the architectural failures documented above (no TLS, hardcoded shared credentials, no chip-attestation verification, no request signing, etc.) are organisation-level and product-management-level decisions, not the responsibility of any single contributor. Implementing AES-128 client-side, deploying TLS, requiring per-install authentication, and verifying NXP originality signatures are all decisions that get made above the IC engineering level. The developer-name reference here exists solely so Droisys's internal triage can identify the correct team owner and route this disclosure efficiently.

### Suggested disclosure recipients

- **MintID / Bullion Works Inc.** (the brand and product owner) — primary recipient
- **Droisys, Inc.** (the app developer and API operator) — primary recipient; sales@droisys.com is the only published contact
- **Identiv, Inc.** (the NFC tag / TOM Label supplier whose case study makes the marketed claims this disclosure refutes) — primary recipient; sales@identiv.com is the only published contact
- **Highland Mint** (named manufacturer of one SKU per the production server's response) — secondary recipient
- The retailer ecosystem currently distributing affected products — secondary recipient, as appropriate

---

## Acknowledgements

Research conducted under the DMCA §1201(f) interoperability exemption. Coins examined were owned by the researcher; production verification API was queried only for coins owned by the researcher, with hard-capped probe runs to avoid impact on the service.

Thanks to the open-source community behind Proxmark 3 / Iceman fork, androguard, and the documented research on chip-attested NFC authentication (NXP NTAG 424 DNA SUN messages, NFC Forum Type 4 Tag spec).

---

End of disclosure.
