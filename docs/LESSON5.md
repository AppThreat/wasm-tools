# Lesson 5: Strings, secrets, and IoCs

WebAssembly has no strings in its type system, so everything a module prints, matches, or transmits lives as raw bytes in data segments, waiting for the module to copy it into linear memory. That makes data segments the richest source of embedded evidence: error messages, endpoints, configuration, and, when a module is naughty, credentials and command-and-control indicators. This lesson extracts and screens them.

## The sample

`tests/fixtures/strings_secrets.wasm` contains six data segments planted for this exercise:

```bash
wasm-tools tests/fixtures/strings_secrets.wasm --strings
```

```text

Strings:

 segment[0] mem[0x00000000] +0x0 len=32 utf-8 "https://evil.example.com/payload"
 segment[1] mem[0x00000040] +0x0 len=20 utf-8 "AKIAIOSFODNN7EXAMPLE"
 segment[2] mem[0x00000080] +0x0 len=31 utf-8 "-----BEGIN RSA PRIVATE KEY-----"
 segment[3] mem[0x00000100] +0x0 len=108 utf-8 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
 segment[4] mem[0x00000200] +0x0 len=48 utf-8 "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5"
 segment[5] mem[0x00000280] +0x0 len=50 utf-8 "just a plain harmless string for baseline coverage"

6 strings shown
```

Read one line closely; the fields repeat for every entry:

```text
 segment[1] mem[0x00000040] +0x0 len=20 utf-8 "AKIAIOSFODNN7EXAMPLE"
```

`segment[1]` is the data segment index, `mem[0x40]` is the absolute linear-memory address the segment initializes (so this string lives at address 64 at runtime), `+0x0` is the offset within the segment, `len=20` is the byte length, and the value follows. With the address in hand you can find the bytes in the file or in a runtime memory dump:

```bash
xxd -s 0x40 -l 32 tests/fixtures/strings_secrets.wasm
```

(The file offset differs from the memory address; the `-x` details view shows each segment's file location and the init expression that maps it into memory.)

## The screening layer

Extraction is mechanical; screening is where the tool earns its keep. The analysis layer pattern-matches every string against secret and indicator shapes:

```bash
wasm-tools tests/fixtures/strings_secrets.wasm --json --analysis-only | jq '.detections.strings | {detected, signals, counts, samples}'
```

```json
{
  "detected": true,
  "signals": [
    "aws_access_key",
    "base64_blob",
    "high_entropy",
    "jwt_token",
    "pem_private_key",
    "url"
  ],
  "counts": {
    "aws_access_key": 1,
    "base64_blob": 2,
    "high_entropy": 1,
    "jwt_token": 1,
    "pem_private_key": 1,
    "url": 1
  },
  "samples": {
    "aws_access_key": "AKIAIOSF...",
    "base64_blob": "eyJhbGciOiJIUzI1NiIsInR5...",
    "high_entropy": "QUJDREVGR0hJSktMTU5PUFFS...",
    "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpX...",
    "pem_private_key": "-----BEGIN PRIVATE KEY-----",
    "url": "https://evil.example.com/payload"
  }
}
```

Note the masking. The AWS key is cut after its prefix, the JWT and blobs are truncated, and the PEM keeps only its header. Samples travel through findings and into whatever log system consumes them, so reports stay safe to paste into tickets. The full values remain available in `strings[]` for the analyst who needs them.

The corresponding finding weighs the signals:

```bash
wasm-tools tests/fixtures/strings_secrets.wasm --json --analysis-only | jq '.findings[] | select(.id == "WASM-STR-007") | {severity, confidence, evidence: .evidence.signals}'
```

```json
{
  "severity": "high",
  "confidence": "medium",
  "evidence": ["aws_access_key", "jwt_token", "pem_private_key", "url"]
}
```

The severity split is deliberate and documented in [findings and signals](FINDINGS.md): key, token, PEM, and mining shapes are `high`; bare URLs and domains are `medium`, because real Rust and Emscripten binaries routinely embed documentation links, license hosts, and crate metadata URLs. A medium URL finding is a prompt to look, not a verdict.

## Memory layout

The provenance fields let you reconstruct where strings sit in linear memory:

```text
linear memory
0x0000  +--------------------------------------+
        | "https://evil.example.com/payload"   |  segment[0]
0x0040  +--------------------------------------+
        | "AKIAIOSFODNN7EXAMPLE"               |  segment[1]
0x0080  +--------------------------------------+
        | "-----BEGIN RSA PRIVATE KEY-----"    |  segment[2]
0x0100  +--------------------------------------+
        | <JWT, 108 bytes>                     |  segment[3]
0x0200  +--------------------------------------+
        | <base64 blob, 48 bytes>              |  segment[4]
0x0280  +--------------------------------------+
        | "just a plain harmless string..."    |  segment[5]
        +--------------------------------------+
```

Gaps between segments are normal; the linker packs them. Clusters of high-entropy strings adjacent to networking code paths are the pattern worth escalating.

## Thresholds and encodings

Two dials matter in practice. First, short strings: the default minimum length is 5, and it applies at extraction time, so lowering it changes what the tool sees, not just what it prints:

```bash
wasm-tools tests/fixtures/strings_secrets.wasm --strings --strings-min-len 3
```

Second, encodings. Both UTF-8 and UTF-16LE are extracted, which matters because obfuscated payloads often store their strings as UTF-16 to dodge casual scans. Here is a minimal module whose only content is a UTF-16LE URL:

```python
# /tmp/make_utf16.py
def leb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def section(sid, payload):
    return bytes([sid]) + leb(len(payload)) + payload

payload = "https://stage2.example.net/x".encode("utf-16le")
data = section(11, leb(1) + b"\x00" + b"\x41\x00\x0b" + leb(len(payload)) + payload)
memory = section(5, leb(1) + b"\x00" + leb(1))
module = b"\x00asm\x01\x00\x00\x00" + memory + data
open("/tmp/utf16.wasm", "wb").write(module)
```

```bash
python3 /tmp/make_utf16.py
wasm-tools /tmp/utf16.wasm --strings --strings-min-len 8
```

```text

Strings:

 segment[0] mem[0x00000000] +0x0 len=28 utf-16le "https://stage2.example.net/x"

1 strings shown
```

The UTF-16 string surfaces with its memory address, exactly as a UTF-8 one would. The data segment encodes `flags 0x00` (active, memory 0), the init expression `i32.const 0` (`41 00 0b`), then the byte vector, which is why the string lands at memory address 0.

## Where to go from a hit

A screening hit is a starting point, not a conclusion. The follow-ups that matter:

1. Map the string's memory address to code: search the disassembly for `i32.const <address>` operands, which is how code typically gets a pointer to the string.
2. Check who reaches that code with `--calls` and the call graph.
3. For network indicators, check whether the module actually imports sockets (`sock_*`) or JS fetch paths before treating a URL as live infrastructure.
4. Rotate and report real secrets through your normal process; the binary is now evidence.
