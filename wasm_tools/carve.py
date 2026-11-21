"""Embedded WebAssembly carving: find and bound wasm blobs inside containers.

Every documented smuggling channel needs the same first step: locate the
``\\0asm`` magic and parse what follows. LRQA Cyber Labs documented wasm as
an HTML-smuggling payload in phishing pages (March 2025), AndroWasm
(arXiv 2602.18082) is a systematic study of Android malware shipping wasm
payloads inside APKs, CrowdStrike reported eCriminals hiding malware logic
in wasm (December 2024), and the wasm-JS extension-attack literature
(Electronics 2026) shows bundled wasm invisible to JS-only scanners.

The scanner is read-only and ceiling-bounded: ``max_blobs`` caps the count,
``max_size`` caps each blob's bounded size, and the structural walk consumes
at least the section framing per step so hostile input cannot loop it.
Bounding uses the section framing itself (id byte + LEB size + payload), so
a genuine module's end is exact; when a section extends past the buffer the
blob is accepted as trailing-truncated and marked, because smugglers' blobs
are frequently cut or padded.

Deflate-compressed containers (zip entries, gzip) are out of scope for the
raw scan; extract them first. Base64-encoded payloads need the decode pass
(``--carve-decode``), which scans for long base64 runs, decodes them, and
rescans the decoded buffer while reporting the source span.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Optional

from .component import detect_component
from .parser import BinaryReader
from .visitor import BinaryReaderObjdumpPrepass

WASM_MAGIC = b"\x00asm"

_DEFAULT_MAX_BLOBS = 32
_DEFAULT_MAX_SIZE = 64 * 1024 * 1024
_MAX_SECTIONS_PER_BLOB = 100_000
_MIN_SIZE = 8  # magic + version/layer preamble

# Canonical section order: DataCount (id 12) sits between element (9) and
# code (10) in the binary, so ordering uses positions, not raw ids.
_CANONICAL_ORDER = {
    1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 12: 10, 10: 11, 11: 12,
}

_BASE64_RUN_RE = re.compile(rb"[A-Za-z0-9+/]{1024,}={0,2}")
_BASE64_MIN_DECODED = 1024


class _BlobWalkError(Exception):
    """A blob walk hit a ceiling; ``offset`` is how far the walk got."""

    def __init__(self, message: str, offset: int) -> None:
        super().__init__(message)
        self.offset = offset


def _bound_blob(data: bytes, start: int) -> tuple[int, bool]:
    """Return (end_offset, truncated) using the section framing walk.

    Mirrors read_module's framing loop read-only: id byte, LEB size, payload.
    Two rules end a blob at its true boundary instead of bleeding into the
    container's trailing bytes or into the next embedded module: canonical
    section ids must be strictly increasing within a module (custom sections,
    id 0, may appear anywhere), and any other byte at a section boundary is
    not a section. A section whose declared size exceeds the remaining
    buffer ends the blob at the buffer end and marks it truncated.
    """
    offset = start + 8  # past magic + version/layer
    size = len(data)
    sections = 0
    last_canonical_id = -1  # position space
    while offset < size:
        sections += 1
        if sections > _MAX_SECTIONS_PER_BLOB:
            raise _BlobWalkError("section count ceiling exceeded", offset)
        section_id = data[offset]
        if data[offset : offset + 4] == WASM_MAGIC:
            # The next embedded module starts here (a bare 0x00 would
            # otherwise read as a custom section and swallow it).
            return offset, False
        if section_id > 13:
            # Not a section id: the module ended cleanly.
            return offset, False
        if section_id != 0:
            position = _CANONICAL_ORDER.get(section_id)
            if position is None:
                return offset, False
            if position <= last_canonical_id:
                # Canonical positions only move forward; a smaller position
                # here is the start of the next embedded module.
                return offset, False
            last_canonical_id = position
        offset += 1
        section_size = 0
        shift = 0
        while True:
            if offset >= size:
                return size, True
            byte = data[offset]
            offset += 1
            section_size |= (byte & 0x7F) << shift
            shift += 7
            if shift > 35:
                return size, True
            if not (byte & 0x80):
                break
        if offset + section_size > size:
            return size, True
        offset += section_size
    return offset, False


def find_wasm_blobs(
    data: bytes,
    max_blobs: int = _DEFAULT_MAX_BLOBS,
    min_size: int = _MIN_SIZE,
    max_size: Optional[int] = None,
) -> list[dict[str, Any]]:
    """Scan ``data`` for embedded wasm modules and components.

    Returns blob records with source spans and preamble facts; parsing the
    blobs is left to :func:`carve_wasm_bytes`. Overlapping hits collapse
    (a magic inside an already-bounded module is that module's data, and
    nested components are part of their outer component), so back-to-back
    modules yield two blobs and a data segment carrying another module's
    magic yields one.
    """
    blobs: list[dict[str, Any]] = []
    cursor = 0
    ceiling = max_size if max_size is not None else _DEFAULT_MAX_SIZE
    while len(blobs) < max_blobs:
        hit = data.find(WASM_MAGIC, cursor)
        if hit < 0:
            break
        cursor = hit + 1
        if len(data) - hit < _MIN_SIZE:
            break
        # Layer byte 4 discriminates components from core modules; versions
        # are u16 little-endian at offsets 4-5 (core) or 4-5/6-7 split.
        version = data[hit + 4] | (data[hit + 5] << 8)
        layer = data[hit + 6] | (data[hit + 7] << 8)
        if layer == 0 and version != 1:
            continue
        if layer == 1 and version < 0x0A:
            # Pre-standard component versions started at 0x0a; anything
            # lower is not a plausible preamble.
            continue
        if layer not in (0, 1):
            continue
        try:
            end, truncated = _bound_blob(data, hit)
        except _BlobWalkError as exc:
            # A crafted framing storm: skip the framing already walked, so
            # a magic inside it is not walked again (which made a storm of
            # magics quadratic), and keep scanning.
            cursor = max(cursor, exc.offset)
            continue
        if end <= hit or hit + min_size > end:
            # Too small to report; a magic inside the walked framing is part
            # of this candidate, so the scan resumes past it.
            cursor = max(cursor, end)
            continue
        blob_size = end - hit
        if blob_size > ceiling:
            blobs.append(
                {
                    "offset": hit,
                    "size": None,
                    "truncated": True,
                    "is_component": layer == 1,
                    "preamble": {"version": version, "layer": layer},
                    "error": "blob exceeds the size ceiling; not bounded",
                }
            )
            cursor = end
            continue
        blobs.append(
            {
                "offset": hit,
                "size": blob_size,
                "truncated": truncated,
                "is_component": layer == 1,
                "preamble": {"version": version, "layer": layer},
            }
        )
        cursor = end
    return blobs


def _quick_summary(blob_bytes: bytes, is_component: bool) -> dict[str, Any]:
    """Run the real parser on the blob with heavy blocks off."""
    from .api import parse_wasm_bytes

    report = parse_wasm_bytes(
        blob_bytes,
        filename="<blob>",
        include_strings=False,
        include_call_graph=False,
        include_instructions=False,
        include_features=False,
        include_demangled=False,
    )
    quick: dict[str, Any] = {
        "function_count": report.get("function_count", 0),
        "import_count": len(report.get("imports", [])),
        "export_count": len(report.get("exports", [])),
        "parse_errors": report.get("errors", []),
    }
    wasi = report.get("analysis", {}).get("detections", {}).get("wasi", {})
    if wasi.get("detected"):
        quick["wasi"] = ",".join(wasi.get("variants", []))
    if is_component:
        component = report.get("component", {})
        quick["interface_count"] = len(component.get("interfaces", []))
    return quick


def carve_wasm_bytes(
    data: bytes,
    max_blobs: int = _DEFAULT_MAX_BLOBS,
    decode_base64: bool = False,
    max_size: Optional[int] = None,
) -> dict[str, Any]:
    """Find, bound, and quickly parse embedded wasm blobs.

    Returns a carve report: one record per blob with source span, preamble,
    truncation marking, and a quick summary from the real parser. With
    ``decode_base64``, long base64 runs in the container are decoded and
    rescanned, and each hit records the run's source span.
    """
    found = find_wasm_blobs(data, max_blobs=max_blobs, max_size=max_size)
    blobs: list[dict[str, Any]] = []
    for record in found:
        blob_record = dict(record)
        offset = record["offset"]
        size = record.get("size")
        if size is None:
            blob_record["quick"] = None
            blobs.append(blob_record)
            continue
        blob_bytes = data[offset : offset + size]
        blob_record["quick"] = _quick_summary(
            blob_bytes, bool(record.get("is_component"))
        )
        blobs.append(blob_record)

    decoded_hits: list[dict[str, Any]] = []
    if decode_base64:
        for match in _BASE64_RUN_RE.finditer(data):
            run = match.group(0)
            try:
                decoded = base64.b64decode(run, validate=True)
            except Exception:
                continue
            if len(decoded) < _BASE64_MIN_DECODED:
                continue
            inner = find_wasm_blobs(decoded, max_blobs=max_blobs, max_size=max_size)
            for record in inner:
                blob_record = dict(record)
                blob_record["base64_span"] = [match.start(), match.end()]
                blob_bytes = decoded[
                    record["offset"] : record["offset"] + (record.get("size") or 0)
                ]
                if blob_bytes:
                    blob_record["quick"] = _quick_summary(
                        blob_bytes, bool(record.get("is_component"))
                    )
                decoded_hits.append(blob_record)

    return {
        "blob_count": len(blobs) + len(decoded_hits),
        "blobs": blobs,
        "decoded_blobs": decoded_hits,
    }
