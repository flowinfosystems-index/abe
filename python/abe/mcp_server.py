"""MCP adapter (stdio):  abe mcp --policy ./abe-policy.yaml

Requires:  pip install "abe-ai[mcp]"

Add to an MCP client (Claude Desktop, Claude Code, Cursor, ...):
    {"mcpServers": {"abe": {"command": "abe", "args": ["mcp", "--policy", "/abs/path/abe-policy.yaml",
                                                             "--store", "sqlite:/abs/path/abe-records.db"]}}}
"""
from __future__ import annotations

from typing import Any, Literal

from .gate import Gate

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
        out["what_to_do"] = {"ACT": "Execute the action exactly as evaluated.",
                             "BLOCK": "Do not execute. Tell the user why.",
                             "ESCALATE": "Do not execute now. Show the user the reason and let them decide."}[r.decision]
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
