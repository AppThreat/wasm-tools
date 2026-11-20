"""Pure-Python demangling for Rust symbols in wasm name sections.

Scope: a deliberate subset with zero dependencies (the consumer-side
multi-demangle package stays authoritative where it exists):

- Rust legacy ``_ZN...E`` names: run-length segments rendered as
  ``crate::module::func``. Real legacy names are hash-terminated
  (``17h`` followed by 16 hex digits, where the run length 17 covers the
  ``h`` and the 16 digits); the hash is uninformative and dropped. C++
  Itanium names are not hash-terminated and are left untouched rather
  than misrendered (their full grammar is a compiler-sized job).
- Rust v0 ``_R`` names for the crate-path shapes: ``C<ident>`` crate
  roots and ``N <ns> <path> <identifier>`` nesting, with value/type
  namespaces hidden, closures and shims rendered with their
  disambiguator index. ``M``/``X``/``Y``/``I``/``B`` path forms and
  Punycode identifiers return the input unchanged.

Grammar references: rust-lang/rfcs 2603 (v0) for the identifier encoding
(``[s<base62>_] [u] <decimal> [_] <bytes>``) and namespace tags; the v0
hash/segment shapes match the RFC's ``_ZN9demo_write4main17h...E`` style
examples. Anything unparseable returns the input unchanged, never raises,
and never invents a wrong demangle.
"""

from __future__ import annotations

import re
from typing import Optional

# str.isdigit accepts characters such as "²" that int() rejects, so the
# length prefixes are matched against the ASCII digits only.
_ASCII_DIGITS = frozenset("0123456789")

#: Deepest v0 path nesting rendered; deeper names are returned unchanged.
_MAX_V0_DEPTH = 64

# Legacy Rust hash segment: 17 chars, "h" plus 16 hex digits.
_LEGACY_HASH_RE = re.compile(r"^h[0-9a-f]{16}$")


def _iter_legacy_segments(body: str) -> Optional[list[str]]:
    """Split the ``_ZN`` body into length-prefixed segments, or None."""
    segments: list[str] = []
    pos = 0
    size = len(body)
    while pos < size:
        digits = ""
        while pos < size and body[pos] in _ASCII_DIGITS:
            digits += body[pos]
            pos += 1
        if not digits:
            return None  # not a run-length segment: outside the subset
        length = int(digits)
        if length <= 0 or pos + length > size:
            return None  # malformed
        segments.append(body[pos : pos + length])
        pos += length
    return segments


def demangle(name: str) -> str:
    """Demangle one symbol name, returning the input unchanged when unsure."""
    if not name:
        return name
    if name.startswith("_ZN") and name.endswith("E"):
        segments = _iter_legacy_segments(name[3:-1])
        if segments and _LEGACY_HASH_RE.match(segments[-1]):
            return "::".join(segments[:-1])
        return name
    if name.startswith("_R") and len(name) > 2:
        try:
            rendered = _demangle_v0(name[2:])
        except ValueError:
            return name
        return rendered or name
    return name


def _parse_v0_identifier(text: str) -> tuple[str, int]:
    """Parse one v0 identifier; return (value, chars consumed).

    Grammar (RFC 2603): ``[s<base62>_] [u] <decimal-length> [_] <bytes>``.
    The optional separator is mandatory only when the bytes start with a
    decimal digit or underscore; it is consumed whenever present. Punycode
    identifiers raise ValueError (outside the subset).
    """
    pos = 0
    if text.startswith("s"):
        underscore = text.find("_")
        if underscore < 0:
            raise ValueError("missing disambiguator terminator")
        if _base62_decode(text[pos + 1 : underscore + 1]) is None:
            raise ValueError("malformed disambiguator")
        pos = underscore + 1
    if pos < len(text) and text[pos] == "u":
        raise ValueError("punycode identifiers unsupported")
    digits = ""
    while pos < len(text) and text[pos] in _ASCII_DIGITS:
        digits += text[pos]
        pos += 1
    if not digits:
        raise ValueError("identifier without length")
    length = int(digits)
    if pos < len(text) and text[pos] == "_":
        pos += 1
    if pos + length > len(text):
        raise ValueError("identifier longer than the remaining bytes")
    return text[pos : pos + length], pos + length


def _base62_decode(text: str) -> Optional[int]:
    if not text:
        return None
    value = 0
    for char in text:
        if char == "_":
            return value
        if "0" <= char <= "9":
            digit = ord(char) - ord("0")
        elif "a" <= char <= "z":
            digit = ord(char) - ord("a") + 10
        elif "A" <= char <= "Z":
            digit = ord(char) - ord("A") + 36
        else:
            return None
        value = value * 62 + digit
    return None  # base-62 numbers terminate with the underscore


def _parse_v0_path(body: str, pos: int, depth: int = 0) -> tuple[list[str], int]:
    """Parse one v0 path; return (rendered components, end position).

    Supported: ``C <identifier>`` crate roots and ``N <ns> <path>
    <identifier>`` nesting per RFC 2603. Namespace tags v/t and lowercase
    implementation categories render as plain identifiers; ``C`` renders as
    ``{closure#<index>}`` and ``S`` as ``{shim#<index>}``.
    """
    if pos >= len(body):
        raise ValueError("truncated v0 path")
    if depth >= _MAX_V0_DEPTH:
        raise ValueError("v0 path nested too deeply")
    char = body[pos]
    if char == "C":
        ident, end = _parse_v0_identifier(body[pos + 1 :])
        return [ident], pos + 1 + end
    if char == "N":
        if pos + 1 >= len(body):
            raise ValueError("truncated namespace tag")
        tag = body[pos + 1]
        sub_parts, pos2 = _parse_v0_path(body, pos + 2, depth + 1)
        ident, pos3 = _parse_v0_identifier(body[pos2:])
        if tag == "C":
            rendered = "{closure#" + (ident or "0") + "}"
        elif tag == "S":
            rendered = "{shim#" + (ident or "0") + "}"
        elif tag in ("v", "t") or (tag.isalpha() and tag.islower()):
            rendered = ident
        else:
            raise ValueError(f"unsupported namespace tag {tag!r}")
        return sub_parts + [rendered], pos2 + pos3
    raise ValueError(f"v0 path form {char!r} unsupported")


def _demangle_v0(body: str) -> Optional[str]:
    parts, pos = _parse_v0_path(body, 0)
    # Tolerate the optional trailing E/G terminators; anything else means
    # the input is outside the subset.
    if pos < len(body) and body[pos] not in ("E", "G"):
        raise ValueError("trailing bytes after v0 path")
    if not parts:
        return None
    return "::".join(parts)


def demangle_best_effort(names: list[str]) -> dict[str, str]:
    """Demangle a batch, mapping only the names that changed."""
    out: dict[str, str] = {}
    for name in names:
        demangled = demangle(name)
        if demangled != name:
            out[name] = demangled
    return out
