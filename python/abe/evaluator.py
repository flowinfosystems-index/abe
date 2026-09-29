"""Deterministic condition evaluation. No eval(), no executable policy code.

A condition is one of:
  {field, op, value}         leaf
  {all: [cond, ...]}         every sub-condition matches
  {any: [cond, ...]}         at least one matches
  {not: cond}                negation

Missing fields never match (except `not_exists`). A type mismatch on a comparison raises
EvaluationError, which the Gate turns into ESCALATE / EVALUATION_FAILURE (fail closed).
"""
from __future__ import annotations

from .exceptions import EvaluationError

OPS = ("eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in", "exists", "not_exists", "contains")
ROOTS = ("actor", "action", "context", "evidence", "risk", "irreversibility", "confidence", "metadata")


class _Missing:
    __slots__ = ()

    def __repr__(self):
        return "<missing>"


MISSING = _Missing()


def resolve(doc, path: str):
    cur = doc
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return MISSING
    return cur


def present(v) -> bool:
    return v is not MISSING and v is not None


def _is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _json_eq(a, b) -> bool:
    """Strict JSON equality: true != 1, "1" != 1, 1 == 1.0."""
    if _is_num(a) and _is_num(b):
        return a == b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_eq(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_eq(x, y) for x, y in zip(a, b))
    return False


def _order(a, b, field: str, op: str) -> int:
    if _is_num(a) and _is_num(b):
        return (a > b) - (a < b)
    if isinstance(a, str) and isinstance(b, str):
        # Compare by UTF-16 code units so Python and JavaScript agree on every string.
        ka, kb = a.encode("utf-16-be", "surrogatepass"), b.encode("utf-16-be", "surrogatepass")
        return (ka > kb) - (ka < kb)
    raise EvaluationError(f"{field} {op}: cannot compare {type(a).__name__} with {type(b).__name__}")


def _leaf(doc, cond: dict) -> bool:
    field, op = cond["field"], cond["op"]
    v = resolve(doc, field)
    if op == "exists":
        return present(v)
    if op == "not_exists":
        return not present(v)
    if not present(v):
        return False
    target = cond.get("value")
    if op == "eq":
        return _json_eq(v, target)
    if op == "neq":
        return not _json_eq(v, target)
    if op in ("gt", "gte", "lt", "lte"):
        c = _order(v, target, field, op)
        return {"gt": c > 0, "gte": c >= 0, "lt": c < 0, "lte": c <= 0}[op]
    if op in ("in", "not_in"):
        hit = any(_json_eq(v, t) for t in target)
        return hit if op == "in" else not hit
    if op == "contains":
        if isinstance(v, str):
            if not isinstance(target, str):
                raise EvaluationError(f"{field} contains: string field needs a string value")
            return target in v
        if isinstance(v, list):
            return any(_json_eq(x, target) for x in v)
        raise EvaluationError(f"{field} contains: field must be a string or list, got {type(v).__name__}")
    raise EvaluationError(f"unknown operator {op!r}")


def matches(doc, cond: dict) -> bool:
    if "all" in cond:
        return all(matches(doc, c) for c in cond["all"])
    if "any" in cond:
        return any(matches(doc, c) for c in cond["any"])
    if "not" in cond:
        return not matches(doc, cond["not"])
    return _leaf(doc, cond)
