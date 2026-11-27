"""Replay saved requests through a policy: test rule changes before an agent touches real money.

    abe replay cases.jsonl --policy new.yaml --baseline current.yaml

A case is a request object, or {"id": ..., "request": {...}, "expected": "ACT|BLOCK|ESCALATE"}.
`expected` is what your people decided (or should decide); a case whose decision differs is a mismatch.
Input: a .jsonl file (one case per line), a .json file (one case or an array), or a directory of those.

Raw agent logs work too, so you can ask "what would Abe have done with what my agent did last month?":

    abe replay agent-log.jsonl --policy abe-policy.yaml --action-type issue_refund=refund

Tool calls are recognized in OpenAI Chat Completions messages (tool_calls), OpenAI Responses items
(type function_call), Anthropic messages and content blocks (type tool_use), LangChain AIMessages
(tool_calls with name/args), Claude Code hook events (tool_name/tool_input), and plain {"tool": ..., "args": ...}
lines. A file holding {"messages": [...]} is read as one conversation. Other messages (user text, tool results)
are skipped. Each tool call becomes a request the same way the framework integrations build one: its arguments
become action fields and action.type is the tool name, or the type you map it to with --action-type.

Nothing is stored, signed, or sent anywhere: no store, no signer, no resolver. Pin context.current_time in
requests that use time-based rules, so replays are repeatable.
"""
from __future__ import annotations

import json
import os

from .gate import Gate
from .integrations.claude_agent_sdk import tool_to_action

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


_SKIP = object()   # a log line that is not a tool call (user text, tool result, ...)


def _args(raw, where: str) -> dict:
    if raw is None or raw == "":
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ReplayInputError(f"{where}: tool arguments are not valid JSON ({e.msg})") from e
    if not isinstance(raw, dict):
        raise ReplayInputError(f"{where}: tool arguments must be a JSON object")
    return raw


def tool_calls(item: dict, where: str):
    """[(name, args, call_id), ...] for a recognized agent-log item, _SKIP for a log item with no tool call,
    or None when the item is not an agent-log shape (it is then treated as an FJP request)."""
    if "action" in item or (isinstance(item.get("request"), dict)):
        return None
    out = []
    # OpenAI Chat Completions message / LangChain AIMessage
    if isinstance(item.get("tool_calls"), list):
        for tc in item["tool_calls"]:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else None
            if fn is not None:
                out.append((fn.get("name"), _args(fn.get("arguments"), where), tc.get("id")))
            elif "name" in tc:
                out.append((tc.get("name"), _args(tc.get("args", tc.get("arguments")), where), tc.get("id")))
        return out or _SKIP
    t = item.get("type")
    # OpenAI Responses item
    if t == "function_call":
        return [(item.get("name"), _args(item.get("arguments"), where), item.get("call_id") or item.get("id"))]
    # Anthropic content block
    if t == "tool_use":
        return [(item.get("name"), _args(item.get("input"), where), item.get("id"))]
    # Anthropic message (content is a list of blocks)
    if "role" in item:
        content = item.get("content")
        if isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    out.append((b.get("name"), _args(b.get("input"), where), b.get("id")))
        return out or _SKIP
    # Claude Code hook event
    if "tool_name" in item:
        return [(item.get("tool_name"), _args(item.get("tool_input"), where), item.get("tool_use_id"))]
    # plain {"tool": ..., "args": ...}
    if isinstance(item.get("tool"), str):
        raw = next((item[k] for k in ("args", "arguments", "input", "parameters") if k in item), None)
        return [(item["tool"], _args(raw, where), item.get("id") or item.get("call_id"))]
    if t in ("message", "function_call_output", "tool_result", "text", "reasoning"):
        return _SKIP
    return None


def _flatten(raw: list) -> list:
    """Expand {"messages": [...]} conversation files into their messages."""
    out = []
    for where, item in raw:
        if isinstance(item, dict) and isinstance(item.get("messages"), list) and "action" not in item:
            out.extend((f"{where}.messages[{i}]", m) for i, m in enumerate(item["messages"]))
        else:
            out.append((where, item))
    return out


def load_cases(path: str, action_types: dict | None = None, agent_id: str = "replay") -> list[dict]:
    if os.path.isdir(path):
        files = sorted(os.path.join(path, f) for f in os.listdir(path) if f.endswith((".json", ".jsonl")))
        if not files:
            raise ReplayInputError(f"{path}: no .json or .jsonl files")
        raw = [x for f in files for x in _read(f)]
    else:
        raw = _read(path)
    raw = _flatten(raw)
    expanded = []
    for where, item in raw:
        calls = tool_calls(item, where) if isinstance(item, dict) else None
        if calls is _SKIP:
            continue
        if calls is None:
            expanded.append((where, item))
            continue
        for n, (name, args, call_id) in enumerate(calls):
            if not isinstance(name, str) or not name:
                raise ReplayInputError(f"{where}: tool call has no name")
            ctx = {"agent_id": agent_id, "framework": "replay"}
            if isinstance(call_id, str) and call_id:
                ctx["tool_use_id"] = call_id
            cid = call_id if isinstance(call_id, str) and call_id else (where if len(calls) == 1 else f"{where}#{n}")
            expanded.append((where, {"id": cid, "request": {"action": tool_to_action(name, args, action_types),
                                                              "context": ctx}}))
    raw = expanded
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
    results, changed, mismatches, stopped = [], [], [], []
    exposure = {"BLOCK": 0, "ESCALATE": 0}
    reasons: dict[str, int] = {}
    for c in cases:
        r = gate.check(c["request"])
        counts[r.decision] += 1
        row = {"id": c["id"], "decision": r.decision, "reason_code": r.reason_code,
               "matched_rules": list(r.matched_rules)}
        action = c["request"].get("action") if isinstance(c.get("request"), dict) else None
        if isinstance(action, dict):
            if isinstance(action.get("type"), str):
                row["action_type"] = action["type"]
            amt = action.get("amount")
            if isinstance(amt, (int, float)) and not isinstance(amt, bool):
                row["amount"] = amt
                if r.decision in exposure:
                    exposure[r.decision] += amt
        reasons[r.reason_code] = reasons.get(r.reason_code, 0) + 1
        if r.decision != "ACT":
            stopped.append(row)
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
        "stopped": stopped,
        "exposure": {k: round(v, 2) for k, v in exposure.items()},
        "reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
        "results": results,
    }


def _money(x) -> str:
    return f"${x:,.0f}" if float(x).is_integer() else f"${x:,.2f}"


def format_report(rep: dict, limit: int = 50, stop_limit: int = 20) -> str:
    d = rep["decisions"]
    label = " ".join(str(x) for x in (rep["policy"].get("id"), rep["policy"].get("version")) if x) or "policy"
    lines = [f"Replayed {rep['cases']} case(s) against {label} ({rep['policy']['hash'][:19]})",
             f"  ACT {d['ACT']}   BLOCK {d['BLOCK']}   ESCALATE {d['ESCALATE']}"]
    ex = rep.get("exposure") or {}
    if ex.get("BLOCK") or ex.get("ESCALATE"):
        lines.append(f"  Amounts held back: {_money(ex.get('BLOCK', 0))} blocked, "
                     f"{_money(ex.get('ESCALATE', 0))} escalated (sum of action.amount)")
    stopped = rep.get("stopped") or []
    if stopped:
        lines.append(f"Would have stopped: {len(stopped)}")
        for row in stopped[:stop_limit]:
            what = row.get("action_type") or "?"
            if "amount" in row:
                what += f" {_money(row['amount'])}"
            rules = ", ".join(row["matched_rules"]) or "no rule matched"
            lines.append(f"  {row['id']}: {row['decision']} {what}  {row['reason_code']}  [{rules}]")
        if len(stopped) > stop_limit:
            lines.append(f"  ... {len(stopped) - stop_limit} more (use --json --all for every case)")
        unmatched = sum(1 for row in stopped if not row["matched_rules"])
        if unmatched:
            lines.append(f"  {unmatched} escalated only because no rule matched them: add rules for those tools, "
                         "or map them with --action-type TOOL=TYPE")
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
