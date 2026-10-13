"""MCP adapter (stdio):  abe mcp --policy ./abe-policy.yaml

Requires:  pip install "abe-ai[mcp]"

Add to an MCP client (Claude Desktop, Claude Code, Cursor, ...):
    {"mcpServers": {"abe": {"command": "abe", "args": ["mcp", "--policy", "/abs/path/abe-policy.yaml",
                                                             "--store", "sqlite:/abs/path/abe-records.db"]}}}

Send escalations to Flow (pip install "abe-ai[mcp,flow]"): add "--resolver", "flow" to args and
"env": {"FLOW_API_KEY": "fjp_live_..."}. Only ESCALATE results leave the machine.
"""
from __future__ import annotations

from typing import Any, Literal

from .gate import Gate

REFILL_URL = "https://fjp.flowinfo.co/credits"
KEY_RESET_URL = "https://fjp.flowinfo.co/credits#lost-key"

WHAT_TO_DO = {"ACT": "Execute the action exactly as evaluated.",
              "BLOCK": "Do not execute. Tell the user why.",
              "ESCALATE": "Do not execute now. Show the user the reason and let them decide."}


def _resolver_help(resolution: dict | None) -> dict | None:
    """When the resolver could not answer, say why in words the user can act on."""
    if not resolution or resolution.get("status") != "unavailable":
        return None
    err = str(resolution.get("error") or "")
    if "(402)" in err:
        return {"problem": "Flow account is out of credits; this action stayed ESCALATE.", "fix_url": REFILL_URL}
    if "(401)" in err:
        return {"problem": "Flow rejected the API key; this action stayed ESCALATE.", "fix_url": KEY_RESET_URL}
    if "(429)" in err:
        return {"problem": "Flow rate limit reached; this action stayed ESCALATE. Try again shortly."}
    return {"problem": "Flow could not be reached; this action stayed ESCALATE."}


def _what_to_do(out: dict) -> str:
    text = WHAT_TO_DO[out["decision"]]
    res = out.get("resolution") or {}
    if res.get("status") == "resolved" and res.get("reason"):
        text += f" Flow's judgment: {res['reason']}"
        if res.get("falsifiers"):
            text += f" It would be wrong if: {res['falsifiers'][0]}"
    help_ = out.get("resolver_help")
    if help_:
        text += f" ({help_['problem']}" + (f" Fix: {help_['fix_url']})" if help_.get("fix_url") else ")")
    return text

INSTRUCTIONS = """Abe is the pre-action control point for this agent.
Before executing any consequential action (spending money, sending external messages, changing production
systems or data, booking, deleting, moving physical equipment), call fjp_check_action with the proposed action
and any evidence you have, then follow the decision:
- ACT: you may execute the action exactly as evaluated.
- BLOCK: do not execute. Tell the user why (reason_code).
- ESCALATE: do not execute now. Follow the configured escalation path: show the user the reason and ask them
  to decide, or wait for the resolver.
After executing (or abandoning) an action that was checked, call fjp_report_outcome with the record_id."""


def build_server(gate: Gate):
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover
        raise SystemExit('the MCP adapter needs the "mcp" package: pip install "abe-ai[mcp]"') from e

    mcp = FastMCP("abe", instructions=INSTRUCTIONS)

    @mcp.tool()
    def fjp_check_action(action: dict[str, Any], context: dict[str, Any] | None = None,
                         evidence: dict[str, Any] | None = None, actor: dict[str, Any] | None = None,
                         confidence: float | None = None, risk: str | None = None,
                         irreversibility: str | None = None) -> dict:
        """Check a proposed action before executing it. action.type is required (e.g. "purchase", "send_email").
        Returns decision ACT | BLOCK | ESCALATE, reason_code and record_id. Never execute on BLOCK or ESCALATE."""
        req: dict[str, Any] = {"action": action, "context": context or {}, "evidence": evidence or {}}
        if actor:
            req["actor"] = actor
        if confidence is not None:
            req["confidence"] = confidence
        if risk:
            req["risk"] = {"level": risk}
        if irreversibility:
            req["irreversibility"] = {"level": irreversibility}
        r = gate.check(req)
        out = r.to_dict()
        help_ = _resolver_help(out.get("resolution"))
        if help_:
            out["resolver_help"] = help_
        out["what_to_do"] = _what_to_do(out)
        return out

    @mcp.tool()
    def fjp_report_outcome(record_id: str,
                           status: Literal["executed", "failed", "reverted", "cancelled", "approved", "rejected"],
                           details: dict[str, Any] | None = None) -> dict:
        """Report what happened after a checked action. Appends a linked record; never changes the original."""
        rec = gate.record_outcome(record_id, status, details or {})
        return {"record_id": rec.record_id, "parent_record_id": rec.parent_record_id, "status": status}

    @mcp.tool()
    def fjp_get_record(record_id: str) -> dict:
        """Return a stored Judgment-Grounded Record with its falsifier status re-evaluated now."""
        rec = gate.get_record(record_id).to_dict()
        rec["falsifier"]["status"] = gate.evaluate_falsifier(record_id)
        return rec

    return mcp


def run_stdio(gate: Gate):
    build_server(gate).run("stdio")
