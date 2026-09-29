"""Canonical JSON and SHA-256 hashing.

Canonical form (identical in the Python and TypeScript SDKs, so hashes match across languages):
  - object keys sorted by UTF-16 code units (JavaScript's default sort order)
  - no insignificant whitespace; separators "," and ":"
  - strings escaped as JSON.stringify does (non-ASCII kept as UTF-8)
  - numbers formatted as ECMAScript Number.prototype.toString (integral floats print as integers)
  - NaN / Infinity rejected; only JSON types allowed (dict with str keys, list, str, int, float, bool, None)
"""
from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal

from .exceptions import RequestError

MAX_DEPTH = 32


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def format_number(n) -> str:
    if isinstance(n, bool):
        raise RequestError("boolean is not a number")
    if isinstance(n, int):
        if abs(n) > 2**53 - 1:
            raise RequestError("integer exceeds the safe JSON range (2^53 - 1)")
        return str(n)
    if not isinstance(n, float):
        raise RequestError(f"unsupported number type {type(n).__name__}")
    if math.isnan(n) or math.isinf(n):
        raise RequestError("NaN and Infinity are not valid JSON")
    if n == 0:
        return "0"
    if n.is_integer():
        if abs(n) > 2**53 - 1:
            raise RequestError("number exceeds the safe JSON integer range (2^53 - 1)")
        return str(int(n))
    a = abs(n)
    r = repr(n)
    if 1e-6 <= a < 1e21:
        if "e" in r or "E" in r:  # Python used exponent notation where JS would not
            r = format(Decimal(r), "f")
            if "." in r:
                r = r.rstrip("0").rstrip(".")
        return r
    # exponent notation, JS style: 1e-7, 1.5e+21
    mant, exp = r.split("e")
    e = int(exp)
    return f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"


def _enc(v, depth: int, out: list) -> None:
    if depth > MAX_DEPTH:
        raise RequestError(f"nesting deeper than {MAX_DEPTH}")
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, str):
        out.append(json.dumps(v, ensure_ascii=False))
    elif isinstance(v, (int, float)):
        out.append(format_number(v))
    elif isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise RequestError("object keys must be strings")
        out.append("{")
        for i, k in enumerate(sorted(v, key=_utf16_key)):
            if i:
                out.append(",")
            out.append(json.dumps(k, ensure_ascii=False))
            out.append(":")
            _enc(v[k], depth + 1, out)
        out.append("}")
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _enc(item, depth + 1, out)
        out.append("]")
    else:
        raise RequestError(f"value of type {type(v).__name__} is not JSON")


def canonical_json(value) -> str:
    out: list[str] = []
    _enc(value, 0, out)
    return "".join(out)


def sha256_hex(text: str) -> str:
    try:
        data = text.encode("utf-8")
    except UnicodeEncodeError as e:  # lone surrogates
        raise RequestError("string contains invalid Unicode (lone surrogate)") from e
    return hashlib.sha256(data).hexdigest()


def hash_value(value) -> str:
    """'sha256:<hex>' of the canonical JSON of value."""
    return "sha256:" + sha256_hex(canonical_json(value))


def to_plain(value):
    """Deep-copy into plain dict/list JSON types (unwraps frozen records)."""
    if isinstance(value, dict) or hasattr(value, "items") and not isinstance(value, (str, bytes)):
        return {k: to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(v) for v in value]
    return value
