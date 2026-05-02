# archive/

Investigative scripts kept here for **provenance** — they're how the empirical findings in `DISCLOSURE_DRAFT.md` were produced, but you don't need them for the demo or for ongoing work.

If you're packaging this toolkit for someone else (a vendor's IR team responding to the disclosure, a journalist verifying claims, a future researcher repeating the analysis), the contents of this directory are the audit trail.

## What's here

- `mintid_probe.py` — Five hard-capped server probes that produced findings 3-7 (replay-baseline, cryptogram-bit-flip, uid-bit-flip, etc). Total budget across the whole script: ≤ 50 requests.
- `mintid_explore.py` — Endpoint-discovery scanner. Walked the URL namespace and found the four endpoints we now use. No value going forward.
- `mintid_chip_interrogate.py` — Deeper active chip probes (FAST_READ, PWD_AUTH, hidden-page detection, magic-clone fingerprinting). Findings 9-11 derived from this. Conditionally invoked by `mintid_simulate.py --deeper-probes`.
- `Harness.java` + `ProductRequestBody.java` + `compare_java_vs_python.py` — Java program using Jackson 2.14 (the version Retrofit ships in the MintID APK) that builds the same request body Python builds, so we could byte-diff the two and confirm faithfulness.

## How to run any of these (if you really need to)

```bash
# From inside mintid_interop_toolkit/, NOT inside archive/:
PYTHONPATH=archive python3 archive/mintid_probe.py
PYTHONPATH=archive python3 archive/mintid_explore.py

# Java harness (needs JDK and Jackson on classpath):
cd archive
javac -cp jackson-databind-2.14.jar:jackson-core-2.14.jar:jackson-annotations-2.14.jar \
      Harness.java ProductRequestBody.java
java -cp .:jackson-databind-2.14.jar:jackson-core-2.14.jar:jackson-annotations-2.14.jar \
      Harness > java_output.bin
python3 ../mintid_simulate.py --dry-run > python_output.bin
python3 compare_java_vs_python.py java_output.bin python_output.bin
```

## Why these aren't in the main toolkit

The disclosure already states the findings these scripts produced. Re-running them isn't necessary unless the vendor disputes a specific finding and we need to re-demonstrate.
