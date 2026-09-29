"""FJP-CONF v0.1 checks, vendored from github.com/flowinfosystems-index/fjp-conformance (Apache-2.0).

Unmodified check logic (schema constants + L0-L3 checks), merged into one stdlib-only module so the
Gate can self-verify offline. See NOTICE in the repository root.
"""
from __future__ import annotations

SPEC_VERSION = "0.1.0"

VALID_STATUSES = ("open", "triggered", "expired")

# Heuristic vacuity blocklist for L2 falsifier checks (case-insensitive substring).
# A first filter to catch trivially non-falsifiable conditions, not a full review.
VACUITY_BLOCKLIST = (
    "circumstances change",
    "things change",
    "the world changes",
    "the situation changes",
    "conditions change",
    "new information",
    "it becomes clear",
    "anything changes",
    "something changes",
    "market changes",  # too broad without a threshold
    "sentiment changes",
)

# Tokens that signal a concrete, checkable falsifier condition.
# Two families: (a) threshold/quantity/date comparators, (b) discrete,
# externally observable events. Stems are intentional ("cancel" catches
# cancels/cancelled/cancellation) — matching is case-insensitive substring.
CONCRETENESS_MARKERS = (
    # comparators / quantities / bounds
    "exceeds", "falls", "drops", "rises", "above", "below", "reaches",
    "within", "by ", "before", "after", "greater than", "less than",
    "more than", "fewer than", "at least", "at most", "declines", "increases",
    "%", "$", "per ", "no later than", "if not", "unless",
    # discrete observable events
    "announces", "files", "confirms", "denies", "misses", "beats",
    "resign", "cancel", "reject", "approv", "closes", "terminat",
    "withdraw", "delay", "acquir", "launch", "recall", "default",
    "downgrade", "upgrade", "steps down", "departs", "reaffirm", "raises",
    "cuts", "suspend", "rules", "votes", "signs", "expires", "settle",
)


def canonical_signal_id(signal: dict) -> str:
    """Identity of a signal: explicit `id` if present, else its description."""
    if not isinstance(signal, dict):
        return ""
    return str(signal.get("id") or signal.get("description") or "").strip()


def canonical_judgment_id(judgment: dict) -> str:
    """Identity of a judgment: explicit `id` if present, else its assessment."""
    if not isinstance(judgment, dict):
        return ""
    return str(judgment.get("id") or judgment.get("assessment") or "").strip()



import datetime as _dt
import re
from typing import List, NamedTuple




class Result(NamedTuple):
    check_id: str
    level: int
    passed: bool
    detail: str


# ----------------------------------------------------------------------------- #
# helpers
# ----------------------------------------------------------------------------- #

def _is_nonempty_str(v) -> bool:
    return isinstance(v, str) and v.strip() != ""


def _valid_iso8601(v) -> bool:
    if not isinstance(v, str) or not v.strip():
        return False
    s = v.strip().replace("Z", "+00:00")
    try:
        _dt.datetime.fromisoformat(s)
        return True
    except ValueError:
        return False


def _obj(record: dict, key: str) -> dict:
    v = record.get(key)
    return v if isinstance(v, dict) else {}


# ----------------------------------------------------------------------------- #
# L0 — structural
# ----------------------------------------------------------------------------- #

def check_l0(record: dict) -> List[Result]:
    r: List[Result] = []
    add = lambda cid, ok, msg: r.append(Result(cid, 0, ok, msg))

    # Defensive: a record must be a JSON object. Guard here so every caller
    # (CLI, tests, and any future hosted verifier) fails cleanly instead of
    # crashing on adversarial or malformed input.
    if not isinstance(record, dict):
        add("L0.record.is_object", False,
            f"record must be a JSON object (got {type(record).__name__})")
        return r

    add("L0.record_id", _is_nonempty_str(record.get("record_id")),
        "record_id must be a non-empty string")
    add("L0.timestamp", _valid_iso8601(record.get("timestamp")),
        "timestamp must be valid ISO 8601")

    for comp in ("signal", "judgment", "action", "falsifier"):
        add(f"L0.{comp}.present", isinstance(record.get(comp), dict),
            f"{comp} must be present and an object")

    sig, jud, act, fal = (_obj(record, k) for k in
                          ("signal", "judgment", "action", "falsifier"))

    add("L0.signal.description", _is_nonempty_str(sig.get("description")),
        "signal.description must be a non-empty string")
    add("L0.signal.observed_at", _valid_iso8601(sig.get("observed_at")),
        "signal.observed_at must be valid ISO 8601")

    add("L0.judgment.assessment", _is_nonempty_str(jud.get("assessment")),
        "judgment.assessment must be a non-empty string")
    conf = jud.get("confidence")
    add("L0.judgment.confidence",
        isinstance(conf, (int, float)) and not isinstance(conf, bool)
        and 0.0 <= float(conf) <= 1.0,
        "judgment.confidence must be a number in [0, 1]")

    add("L0.action.directive", _is_nonempty_str(act.get("directive")),
        "action.directive must be a non-empty string")

    add("L0.falsifier.condition", _is_nonempty_str(fal.get("condition")),
        "falsifier.condition must be a non-empty string")
    return r


# ----------------------------------------------------------------------------- #
# L1 — grounded
# ----------------------------------------------------------------------------- #

def check_l1(record: dict) -> List[Result]:
    r: List[Result] = []
    add = lambda cid, ok, msg: r.append(Result(cid, 1, ok, msg))

    sig, jud, act = (_obj(record, k) for k in ("signal", "judgment", "action"))

    sources = sig.get("sources")
    add("L1.signal.sources",
        isinstance(sources, list) and any(_is_nonempty_str(s) for s in sources),
        "signal.sources must be a non-empty list of identifiers")

    sig_id = canonical_signal_id(sig)
    add("L1.judgment.signal_ref",
        _is_nonempty_str(jud.get("signal_ref")) and jud.get("signal_ref") == sig_id,
        "judgment.signal_ref must match the signal's canonical identity")

    jud_id = canonical_judgment_id(jud)
    add("L1.action.judgment_ref",
        _is_nonempty_str(act.get("judgment_ref")) and act.get("judgment_ref") == jud_id,
        "action.judgment_ref must match the judgment's canonical identity")
    return r


# ----------------------------------------------------------------------------- #
# L2 — falsifiable
# ----------------------------------------------------------------------------- #

# Source-citation parentheticals such as "(per Reuters)" or "(per FJP signal
# architecture)" attribute a claim; they do not make it checkable. Strip them
# before the concreteness test so a citation's "per " cannot satisfy the
# "per " quantity marker (e.g. "Conditions may change. (per X)" is still vacuous).
_CITATION_PAREN = re.compile(r"\(\s*per\s[^)]*\)", re.IGNORECASE)


def _is_vacuous(condition: str) -> bool:
    c = _CITATION_PAREN.sub(" ", condition).lower()
    if any(bad in c for bad in VACUITY_BLOCKLIST):
        return True
    has_marker = any(m in c for m in CONCRETENESS_MARKERS)
    has_digit = any(ch.isdigit() for ch in c)
    # Concrete if it has a comparison/event marker OR a number.
    return not (has_marker or has_digit)


def check_l2(record: dict) -> List[Result]:
    r: List[Result] = []
    add = lambda cid, ok, msg: r.append(Result(cid, 2, ok, msg))

    fal = _obj(record, "falsifier")
    cond = fal.get("condition", "")

    add("L2.falsifier.checkable", fal.get("checkable") is True,
        "falsifier.checkable must be exactly true")
    add("L2.falsifier.status", fal.get("status") in VALID_STATUSES,
        f"falsifier.status must be one of {VALID_STATUSES}")
    add("L2.falsifier.concrete",
        _is_nonempty_str(cond) and not _is_vacuous(cond),
        "falsifier.condition must be concrete (references a threshold, quantity, "
        "dated bound, or event) and not a vacuous catch-all")
    return r


# ----------------------------------------------------------------------------- #
# L3 — accountable (requires an adapter; see adapter.py)
# ----------------------------------------------------------------------------- #

def check_l3(adapter, record_id: str) -> List[Result]:
    """L3 validates the agent can retrieve a record and re-evaluate its falsifier.

    `adapter` must implement get_record(record_id) -> dict and
    evaluate_falsifier(record_id) -> str. See conformance/adapter.py.
    """
    r: List[Result] = []
    add = lambda cid, ok, msg: r.append(Result(cid, 3, ok, msg))

    try:
        rec = adapter.get_record(record_id)
    except Exception as e:  # noqa: BLE001 - conformance must not crash on impl errors
        add("L3.get_record", False, f"get_record raised: {e!r}")
        return r

    add("L3.get_record.returns_record",
        isinstance(rec, dict) and rec.get("record_id") == record_id,
        "get_record must return the JGR with the requested record_id")

    # The retrieved record must itself still be structurally valid.
    l0_ok = all(res.passed for res in check_l0(rec)) if isinstance(rec, dict) else False
    add("L3.get_record.valid_jgr", l0_ok,
        "retrieved record must still be a valid (L0) JGR")

    try:
        status = adapter.evaluate_falsifier(record_id)
        add("L3.evaluate_falsifier", status in VALID_STATUSES,
            f"evaluate_falsifier must return one of {VALID_STATUSES}")
    except Exception as e:  # noqa: BLE001
        add("L3.evaluate_falsifier", False, f"evaluate_falsifier raised: {e!r}")
    return r


# ----------------------------------------------------------------------------- #
# aggregation
# ----------------------------------------------------------------------------- #

def evaluate(record: dict, level: int) -> List[Result]:
    """Run all checks up to and including `level` (0-2) on a JSON record."""
    results = check_l0(record)
    # If the record isn't even an object, higher-level checks can't run safely.
    if not isinstance(record, dict):
        return results
    if level >= 1:
        results += check_l1(record)
    if level >= 2:
        results += check_l2(record)
    return results


def conforms(results: List[Result]) -> bool:
    return all(res.passed for res in results)
