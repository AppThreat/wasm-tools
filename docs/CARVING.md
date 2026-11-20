# Embedded wasm carving

Wasm ships embedded in containers it was never meant to ship in, and every
documented channel needs the same first step: find the `\0asm` magic and
parse what follows. LRQA Cyber Labs documented wasm as an HTML-smuggling
payload in phishing pages (March 2025); AndroWasm (arXiv 2602.18082) is a
systematic study of Android malware shipping wasm payloads inside APKs;
CrowdStrike reported eCriminals hiding malware logic in wasm (December
2024); the wasm-JS extension-attack literature (Electronics 2026) shows
bundled wasm invisible to JS-only scanners.

## Usage

```bash
wasm-tools page.html --carve
wasm-tools page.html --carve --carve-full      # embed full parse reports
wasm-tools page.html --carve --carve-decode    # also decode base64 runs
wasm-tools page.html --carve --extract ./blobs # write bounded blobs to disk
```

The output is a JSON carve report (its own contract, separate from the
standard parse report):

```json
{
  "file": "page.html",
  "blob_count": 1,
  "blobs": [
    {
      "offset": 48192, "size": 51283, "truncated": false,
      "is_component": false, "preamble": {"version": 1, "layer": 0},
      "quick": {"function_count": 90, "import_count": 14,
                "export_count": 3, "parse_errors": []}
    }
  ]
}
```

`quick` comes from running the real parser on the bounded blob with the
heavy blocks off. `--extract` writes each bounded blob as
`blob-<offset>.wasm` for follow-up analysis with the regular tool.

## How bounding works

A wasm module's end is not length-prefixed, so the scanner bounds blobs
with a read-only section-framing walk plus two ordering rules: canonical
section positions only move forward inside a module (DataCount sits between
element and code), and the next embedded module's magic at a boundary ends
the current one. Back-to-back modules yield two blobs; a data segment
carrying another module's bytes stays one blob. A section whose declared
size exceeds the buffer accepts the blob as trailing-truncated, because
smuggled blobs are frequently cut or padded.

## Ceilings and limits

The scan is read-only and ceiling-bounded: at most 32 blobs, 64 MB per
blob, and 100000 sections per blob. A crafted framing storm (hundreds of
fake magics with invalid preambles) returns quickly and empty.

Deflate-compressed containers (zip entries, gzip) are out of scope for the
raw scan: extract the layers first, then carve the entries. Base64-encoded
payloads need `--carve-decode`, which decodes base64 runs of 1024 bytes or
more, rescans the decoded buffer, and records each hit's source span.
