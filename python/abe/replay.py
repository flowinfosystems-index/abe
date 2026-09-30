"""Replay saved requests through a policy: test rule changes before an agent touches real money.

    abe replay cases.jsonl --policy new.yaml --baseline current.yaml

A case is a request object, or {"id": ..., "request": {...}, "expected": "ACT|BLOCK|ESCALATE"}.
`expected` is what your people decided (or should decide); a case whose decision differs is a mismatch.
Input: a .jsonl file (one case per line), a .json file (one case or an array), or a directory of those.

Nothing is stored, signed, or sent anywhere: no store, no signer, no resolver. Pin context.current_time in
requests that use time-based rules, so replays are repeatable.
"""
from __future__ import annotations

import json
import os

from .gate import Gate

MAX_CASES = 100_000
MAX_FILE_BYTES = 64 * 1_048_576
DECISIONS = ("ACT", "BLOCK", "ESCALATE")


class ReplayInputError(ValueError):
    pass


def _read(path: str) -> list[tuple[str, object]]:
    if os.path.getsize(path) > MAX_FILE_BYTES:
        raise ReplayInputError(f"{path}: larger than 64 MiB")
    name = os.path.basename(path)
    with open(path, encoding="utf-8") as fh:
        if path.endswith(".jsonl"):
            out = []
            for n, line in enumerate(fh, 1):
                if line.strip():
                    try:
                        out.append((f"{name}:{n}", json.loads(line)))
                    except json.JSONDecodeError as e:
                        raise ReplayInputError(f"{name}:{n}: invalid JSON ({e.msg})") from e
            return out
        try:
            data = json.load(fh)
        except json.JSONDecodeError as e:
            raise ReplayInputError(f"{name}: invalid JSON ({e.msg})") from e
    if isinstance(data, list):
        return [(f"{name}[{i}]", x) for i, x in enumerate(data)]
    return [(name, data)]


def load_cases(path: str) -> list[dict]:
    if os.path.isdir(path):
        files = sorted(os.path.join(path, f) for f in os.listdir(path) if f.endswith((".json", ".jsonl")))
        if not files:
            raise ReplayInputError(f"{path}: no .json or .jsonl files")
        raw = [x for f in files for x in _read(f)]
    else:
        raw = _read(path)
    if len(raw) > MAX_CASES:
        raise ReplayInputError(f"more than {MAX_CASES} cases")
    cases, seen = [], set()
    for where, item in raw:
        if not isinstance(item, dict):
            raise ReplayInputError(f"{where}: a case must be a JSON object")
        wrapped = isinstance(item.get("request"), dict) and "action" not in item
        req = item["request"] if wrapped else item
        expected = item.get("expected") if wrapped else None
        if expected is not None and expected not in DECISIONS:
            raise ReplayInputError(f"{where}: expected must be one of {list(DECISIONS)}")
        cid = (item.get("id") if wrapped else None) or req.get("request_id") or where
        cid = str(cid)
        if cid in seen:
            cid = f"{cid} ({where})"
        seen.add(cid)
        cases.append({"id": cid, "request": req, "expected": expected})
    return cases


def replay(cases: list[dict], policy, baseline=None) -> dict:
    gate = Gate(policy)
    base = Gate(baseline) if baseline is not None else None
    counts = {d: 0 for d in DECISIONS}
    results, changed, mismatches = [], [], []
    for c in cases:
        r = gate.check(c["request"])
        counts[r.decision] += 1
        row = {"id": c["id"], "decision": r.decision, "reason_code": r.reason_code,
               "matched_rules": list(r.matched_rules)}
        if base is not None:
            b = base.check(c["request"])
            row["baseline_decision"] = b.decision
            if b.decision != r.decision:
                changed.append({"id": c["id"], "from": b.decision, "to": r.decision,
                                "matched_rules": list(r.matched_rules)})
        if c.get("expected") is not None:
            row["expected"] = c["expected"]
            if c["expected"] != r.decision:
                mismatches.append({"id": c["id"], "expected": c["expected"], "decision": r.decision,
                                   "matched_rules": list(r.matched_rules)})
        results.append(row)
    expected_n = sum(1 for c in cases if c.get("expected") is not None)
    return {
        "cases": len(cases),
        "policy": gate.policy.describe(),
        "baseline_policy": base.policy.describe() if base is not None else None,
        "decisions": counts,
        "changed": changed,
        "expected_cases": expected_n,
        "mismatches": mismatches,
        "agreement": round((expected_n - len(mismatches)) / expected_n, 4) if expected_n else None,
        "results": results,
    }


def format_report(rep: dict, limit: int = 50) -> str:
    d = rep["decisions"]
    label = " ".join(str(x) for x in (rep["policy"].get("id"), rep["policy"].get("version")) if x) or "policy"
    lines = [f"Replayed {rep['cases']} case(s) against {label} ({rep['policy']['hash'][:19]})",
             f"  ACT {d['ACT']}   BLOCK {d['BLOCK']}   ESCALATE {d['ESCALATE']}"]
    if rep["baseline_policy"] is not None:
        lines.append(f"Changed vs baseline ({rep['baseline_policy']['hash'][:19]}): {len(rep['changed'])}")
        for c in rep["changed"][:limit]:
            lines.append(f"  {c['id']}: {c['from']} -> {c['to']}  [{', '.join(c['matched_rules']) or 'no rule'}]")
    if rep["expected_cases"]:
        lines.append(f"Agreement with expected: {rep['expected_cases'] - len(rep['mismatches'])}/"
                     f"{rep['expected_cases']} ({rep['agreement']:.1%})")
        for m in rep["mismatches"][:limit]:
            lines.append(f"  {m['id']}: expected {m['expected']}, got {m['decision']}  "
                         f"[{', '.join(m['matched_rules']) or 'no rule'}]")
    shown = max(len(rep["changed"]), len(rep["mismatches"]))
    if shown > limit:
        lines.append(f"  ... {shown - limit} more (use --json for all)")
    return "\n".join(lines)
