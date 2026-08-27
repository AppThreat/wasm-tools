"""String and secret/IoC extraction from wasm data segments.

Analysts triaging unknown ``.wasm`` binaries routinely start by extracting
readable strings and looking for URLs, credential-like blobs, and other
indicators inside linear-memory data segments.  The parser already retains
data segment bytes in :class:`wasm_tools.models.DataEntry`; this module turns
those bytes into provenance-carrying string records plus heuristic detections.

Everything here is pure post-processing over decoded segments; no parser
behavior is involved.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Sequence, Tuple

# Cap applied when strings are embedded into the JSON report so a multi-MiB
# data segment cannot balloon report size unboundedly.
DEFAULT_MAX_STRINGS = 1000

# Bytes treated as "printable" for ASCII run extraction. High-bit bytes are
# excluded to keep provenance simple; UTF-16LE is detected separately.
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09}

# Curated TLD set for lightweight domain IoC matching (deliberately small;
# this is a triage hint, not a URL parser).
_TLDS = {
    "com", "net", "org", "io", "dev", "app", "xyz", "top", "info", "biz",
    "ru", "su", "cn", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "onion",
}

_RE_URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s\"'<>]{4,}", re.IGNORECASE)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(" + "|".join(sorted(_TLDS)) + r")\b",
    re.IGNORECASE,
)
_RE_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_RE_PEM = re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")
_RE_BASE64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_RE_HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}){16,}\b")
_RE_MINING = re.compile(
    r"\b(?:stratum\+tcp://|cryptonight|monero|miner|xmr)[^\s]*", re.IGNORECASE
)

# Signals whose presence always counts as "high interest".
_ALWAYS_SIGNALS = {
    "aws_access_key",
    "jwt_token",
    "pem_private_key",
    "url",
    "mining_indicator",
}


@dataclass
class StringHit:
    """One extracted printable string with linear-memory provenance."""

    segment_index: int
    byte_offset: int  # offset within the segment payload
    memory_offset: Optional[int]  # segment offset value + byte_offset, if known
    length: int
    encoding: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment_index": self.segment_index,
            "byte_offset": self.byte_offset,
            "memory_offset": self.memory_offset,
            "length": self.length,
            "encoding": self.encoding,
            "value": self.value,
        }


def _scan_ascii_runs(data: bytes) -> Iterable[Tuple[int, int]]:
    """Yield (start, length) for printable ASCII runs of 2+ bytes."""
    start: Optional[int] = None
    for i, b in enumerate(data):
        if b in _PRINTABLE:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= 2:
                yield start, i - start
            start = None
    if start is not None and len(data) - start >= 2:
        yield start, len(data) - start


def _scan_utf16le_runs(data: bytes, min_chars: int) -> Iterable[Tuple[int, int]]:
    """Yield (start, char_count) for ASCII text stored as UTF-16LE."""
    i = 0
    n = len(data)
    while i + 1 < n:
        if data[i] in _PRINTABLE and data[i + 1] == 0x00:
            start = i
            chars = 0
            while i + 1 < n and data[i] in _PRINTABLE and data[i + 1] == 0x00:
                chars += 1
                i += 2
            if chars >= min_chars:
                yield start, chars
        else:
            i += 1


def extract_strings(
    segments: Sequence[Tuple[int, Optional[int], bytes]],
    min_len: int = 5,
    max_entries: Optional[int] = DEFAULT_MAX_STRINGS,
) -> Tuple[List[dict[str, Any]], bool]:
    """Extract printable strings from data segments.

    ``segments`` is a sequence of ``(segment_index, offset_value, payload)``
    tuples; ``offset_value`` is the segment's constant linear-memory offset
    when decodable (else ``None``).  Returns ``(entries, truncated)``.
    """
    hits: List[StringHit] = []
    for seg_index, offset_value, payload in segments:
        for start, length in _scan_ascii_runs(payload):
            if length < min_len:
                continue
            mem = None
            if offset_value is not None:
                mem = offset_value + start
            hits.append(
                StringHit(seg_index, start, mem, length, "utf-8",
                          payload[start : start + length].decode("ascii"))
            )
        for start, chars in _scan_utf16le_runs(payload, max(2, min_len)):
            mem = None
            if offset_value is not None:
                mem = offset_value + start
            raw = payload[start : start + chars * 2]
            hits.append(
                StringHit(seg_index, start, mem, chars, "utf-16le",
                          raw.decode("utf-16-le"))
            )

    hits.sort(key=lambda h: (h.segment_index, h.byte_offset))
    truncated = False
    if max_entries is not None and len(hits) > max_entries:
        hits = hits[:max_entries]
        truncated = True
    return [h.to_dict() for h in hits], truncated


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze_strings(entries: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Classify extracted strings into secret/IoC signals for triage.

    Heuristic by design: matches are evidence for review, not proof.
    """
    signals: set[str] = set()
    counts: dict[str, int] = {}
    samples: dict[str, str] = {}

    def record(signal: str, sample: str) -> None:
        signals.add(signal)
        counts[signal] = counts.get(signal, 0) + 1
        # Keep the first sample per signal for stable output.
        samples.setdefault(signal, sample)

    for entry in entries:
        value = str(entry.get("value", ""))
        m = _RE_URL.search(value)
        if m:
            record("url", m.group(0))
        m = _RE_MINING.search(value)
        if m:
            record("mining_indicator", m.group(0))
        m = _RE_AWS_KEY.search(value)
        if m:
            # Mask like JWTs: keep the recognizable prefix, never the full key.
            record("aws_access_key", m.group(0)[:8] + "...")
        m = _RE_JWT.search(value)
        if m:
            record("jwt_token", m.group(0)[:32] + "...")
        if _RE_PEM.search(value):
            record("pem_private_key", "-----BEGIN PRIVATE KEY-----")
        m = _RE_IPV4.search(value)
        if m and not _RE_URL.search(value):
            record("ipv4", m.group(0))
        m = _RE_DOMAIN.search(value)
        if m and not _RE_URL.search(value):
            record("domain", m.group(0))
        m = _RE_BASE64.search(value)
        if m and len(m.group(0)) >= 32:
            record("base64_blob", m.group(0)[:24] + "...")
        m = _RE_HEX_BLOB.search(value)
        if m:
            record("hex_blob", m.group(0)[:24] + "...")
        # High-entropy printable runs: key-material-shaped strings.
        if (
            len(value) >= 24
            and value.isprintable()
            and not value.isspace()
            and re.fullmatch(r"[A-Za-z0-9+/=_-]+", value)
            and _shannon_entropy(value) >= 4.5
        ):
            record("high_entropy", value[:24] + "...")

    return {
        "detected": bool(signals),
        "signals": sorted(signals),
        "counts": {k: counts[k] for k in sorted(counts)},
        "samples": {k: samples[k] for k in sorted(samples)},
        "string_count": len(entries),
    }
