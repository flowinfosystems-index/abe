"""Shared plumbing for the framework integrations: request building and outcome bookkeeping.

Imports no agent framework, so every integration module stays importable without its framework installed.
"""
from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any, Mapping

from ..gate import Gate
from .claude_agent_sdk import _reason as reason_line, tool_to_action

log = logging.getLogger("abe")

_MAX_PENDING = 10_000


def check_gate(gate: Any) -> None:
    if not callable(getattr(gate, "check", None)):
        raise TypeError("gate must be an abe.Abe / abe.Gate")


def build_request(tool_name: str, tool_input: Mapping[str, Any] | None, *, framework: str, agent_id: str,
                  principal_id: str | None = None, action_types: Mapping[str, str] | None = None,
                  tool_call_id: str | None = None, evidence: Mapping[str, Any] | None = None,
                  confidence: float | None = None, extra_context: Mapping[str, Any] | None = None) -> dict:
    """The FJP request for one tool call. Tool inputs become action fields (see tool_to_action)."""
    context: dict[str, Any] = {"agent_id": agent_id, "framework": framework}
    if principal_id:
        context["principal_id"] = principal_id
    if isinstance(tool_call_id, str) and tool_call_id:
        context["tool_use_id"] = tool_call_id
    for k, v in dict(extra_context or {}).items():
        context.setdefault(k, v)
    req: dict[str, Any] = {"action": tool_to_action(tool_name, tool_input, action_types), "context": context}
    if evidence:
        req["evidence"] = dict(evidence)
    if confidence is not None:
        req["confidence"] = confidence
    return req


class Outcomes:
    """Remembers allowed calls until they finish, then appends a linked OUTCOME record."""

    def __init__(self, gate: Gate, enabled: bool = True):
        self.gate, self.enabled = gate, enabled
        self._pending: OrderedDict[str, Any] = OrderedDict()

    def hold(self, key: str | None, result) -> None:
        if not self.enabled or not isinstance(key, str) or not key:
            return
        self._pending[key] = result
        while len(self._pending) > _MAX_PENDING:
            self._pending.popitem(last=False)

    def finish(self, key: str | None, status: str, extra: Mapping[str, Any] | None = None) -> None:
        result = self._pending.pop(key, None) if isinstance(key, str) else None
        if result is not None:
            record(self.gate, result, status, extra)


def record(gate: Gate, result, status: str, extra: Mapping[str, Any] | None = None) -> None:
    """Append an outcome to the call's DECISION record. Never breaks the agent."""
    if not getattr(gate, "record_outcome", None) or not getattr(result, "records", None):
        return
    try:
        gate.record_outcome(result.records[0], status,
                            {"request_hash": result.records[0].request_hash, **dict(extra or {})})
    except Exception as e:  # noqa: BLE001 - outcome bookkeeping never breaks the agent
        log.warning("abe: could not record outcome: %s", e)


__all__ = ["build_request", "check_gate", "Outcomes", "record", "reason_line", "tool_to_action"]
