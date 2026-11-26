"""Abe for LangChain and LangGraph agents: one middleware gates every tool call.

    from langchain.agents import create_agent
    from abe import Abe
    from abe.integrations.langchain import AbeMiddleware

    agent = create_agent(model, tools, middleware=[AbeMiddleware(Abe("abe-policy.yaml"), agent_id="ops-agent")])

Each tool call becomes an FJP request (tool arguments become action fields; action.type is the tool name,
or action_types[tool name]) and Abe's decision decides whether the tool runs:

    ACT       -> the tool runs; a linked OUTCOME record says "executed" or "failed"
    BLOCK     -> the tool does not run; the model gets an error ToolMessage with Abe's reason and record id,
                 so it can choose another approach
    ESCALATE  -> escalate="deny" (default, fail closed): same as BLOCK.
                 escalate="interrupt": pauses the graph with langgraph.types.interrupt() so a person can
                 decide. Resume with Command(resume=True) / "approve" to run the tool, anything else to
                 refuse. Needs a checkpointer. (On resume LangGraph re-runs the tool step, so the call gets a
                 second, identical DECISION record; the approval is linked to that one.)
                 A resolver on the Gate (e.g. Flow) runs first; its ACT / BLOCK is used instead.

Shadow mode (Abe(policy, mode="shadow")) records every decision and never changes what the agent does.

Requires LangChain 1.0+ (`pip install "abe-ai[langchain]"`). `import abe` never imports LangChain.
"""
from __future__ import annotations

import asyncio
from typing import Any, Iterable, Mapping

from ..gate import Gate
from ._common import build_request, check_gate, reason_line, record

try:  # only this module needs LangChain; `import abe` does not
    from langchain.agents.middleware import AgentMiddleware as _Base
    _HAVE_LANGCHAIN = True
except ImportError:  # pragma: no cover - exercised when LangChain is absent
    _Base = object  # type: ignore[assignment,misc]
    _HAVE_LANGCHAIN = False

ESCALATE_MODES = ("deny", "interrupt")
_APPROVE = {"approve", "approved", "allow", "yes", "act"}


def _approved(answer: Any) -> bool:
    if answer is True:
        return True
    if isinstance(answer, str):
        return answer.strip().lower() in _APPROVE
    if isinstance(answer, Mapping):
        if answer.get("approved") is True:
            return True
        d = answer.get("decision") or answer.get("type")
        return isinstance(d, str) and d.strip().lower() in _APPROVE
    return False


class AbeMiddleware(_Base):  # type: ignore[valid-type,misc]
    """LangChain agent middleware that puts Abe in front of every tool call."""

    def __init__(self, gate: Gate, *, agent_id: str = "langchain-agent", principal_id: str | None = None,
                 action_types: Mapping[str, str] | None = None, escalate: str = "deny",
                 record_outcomes: bool = True, tools: Iterable[str] | None = None,
                 evidence: Mapping[str, Any] | None = None, confidence: float | None = None):
        if not _HAVE_LANGCHAIN:
            raise ImportError('AbeMiddleware needs LangChain 1.0+: pip install "abe-ai[langchain]"')
        super().__init__()
        check_gate(gate)
        if escalate not in ESCALATE_MODES:
            raise ValueError(f"escalate must be one of {ESCALATE_MODES}")
        self.gate, self.agent_id, self.principal_id = gate, agent_id, principal_id
        self.action_types = dict(action_types or {})
        self.escalate, self.record_outcomes = escalate, record_outcomes
        self.only = frozenset(tools) if tools is not None else None   # None: gate every tool
        self.evidence, self.confidence = dict(evidence or {}), confidence

    @property
    def name(self) -> str:  # LangChain uses this to tell middleware apart
        return "AbeMiddleware"

    # ------------------------------------------------------------------ helpers

    def _request(self, call: Mapping[str, Any]) -> dict | None:
        tool = str(call.get("name") or "unknown")
        if self.only is not None and tool not in self.only:
            return None
        args = call.get("args")
        return build_request(tool, args if isinstance(args, Mapping) else {}, framework="langchain",
                             agent_id=self.agent_id, principal_id=self.principal_id,
                             action_types=self.action_types, tool_call_id=call.get("id"),
                             evidence=self.evidence, confidence=self.confidence)

    @staticmethod
    def _refusal(call: Mapping[str, Any], reason: str):
        from langchain_core.messages import ToolMessage
        return ToolMessage(content=reason, tool_call_id=str(call.get("id") or ""),
                           name=str(call.get("name") or ""), status="error")

    def _pre(self, request) -> tuple[Any, Any]:
        """(result, refusal). refusal is None when the tool may run."""
        call = request.tool_call
        try:
            req = self._request(call)
        except Exception as e:  # noqa: BLE001 - a broken mapping must not let the call through
            return None, self._refusal(call, f"Abe ESCALATE: EVALUATION_FAILURE | could not map tool call: {e}")
        if req is None:
            return None, None
        return req, None

    def _decide(self, call, result):
        """None to run the tool; otherwise the ToolMessage to return instead."""
        if not result.enforced or result.decision == "ACT":
            return None
        reason = reason_line(result)
        if result.decision == "ESCALATE" and self.escalate == "interrupt":
            from langgraph.types import interrupt
            answer = interrupt({"abe": "ESCALATE", "tool": call.get("name"), "args": call.get("args"),
                                "reason_code": result.reason_code, "reason": reason,
                                "record_id": result.record_id})
            if _approved(answer):
                record(self.gate, result, "approved", {"by": "human"})
                return None
            record(self.gate, result, "rejected", {"by": "human"})
            return self._refusal(call, reason + " | refused by a person")
        return self._refusal(call, reason)

    def _finish(self, result, out=None, error: Exception | None = None):
        if not self.record_outcomes or result is None or not result.enforced:
            return
        failed = error is not None or getattr(out, "status", None) == "error"
        extra = {"tool_use_id": str(getattr(out, "tool_call_id", "") or "")} if out is not None else {}
        if error is not None:
            extra["error"] = str(error)[:500]
        record(self.gate, result, "failed" if failed else "executed", extra)

    # ------------------------------------------------------------------ middleware hooks

    def wrap_tool_call(self, request, handler):
        req, refusal = self._pre(request)
        if refusal is not None:
            return refusal
        if req is None:
            return handler(request)
        result = self.gate.check(req)
        refusal = self._decide(request.tool_call, result)
        if refusal is not None:
            return refusal
        try:
            out = handler(request)
        except Exception as e:
            self._finish(result, error=e)
            raise
        self._finish(result, out)
        return out

    async def awrap_tool_call(self, request, handler):
        req, refusal = self._pre(request)
        if refusal is not None:
            return refusal
        if req is None:
            return await handler(request)
        result = await asyncio.to_thread(self.gate.check, req)
        refusal = self._decide(request.tool_call, result)
        if refusal is not None:
            return refusal
        try:
            out = await handler(request)
        except Exception as e:
            self._finish(result, error=e)
            raise
        self._finish(result, out)
        return out


__all__ = ["AbeMiddleware", "ESCALATE_MODES"]
