"""Abe for the Claude Agent SDK: one PreToolUse hook gates every tool call.

    from claude_agent_sdk import ClaudeAgentOptions, query
    from abe import Abe
    from abe.integrations.claude_agent_sdk import abe_hooks

    abe = Abe("abe-policy.yaml")
    options = ClaudeAgentOptions(hooks=abe_hooks(abe, agent_id="ops-agent"))

Each tool call becomes an FJP request:

    action  = {"type": <tool name, or your mapping>, **tool_input}
    context = {"agent_id": ..., "session_id": ..., "cwd": ..., "tool_use_id": ...}

and Abe's decision becomes the SDK's permission decision:

    ACT       -> no override (the SDK's normal permissions still apply), or "allow" with act="allow"
    BLOCK     -> "deny", with Abe's reason shown to Claude so it can choose another approach
    ESCALATE  -> "deny" by default (fail closed). escalate="ask" sends it to your permission prompt /
                 can_use_tool; escalate="defer" stops the run and returns the call on
                 ResultMessage.deferred_tool_use so a person can approve it and resume.
                 A resolver on the Gate (e.g. Flow) runs first; its ACT / BLOCK is used instead.

Every call writes a Judgment-Grounded Record. With record_outcomes=True (default), a tool call Abe allowed
gets a linked OUTCOME record: "executed" after it runs, "failed" if it errors.

Harness tools with no outside effect (ToolSearch, TodoWrite, AskUserQuestion) are not gated by default;
pass ungated=() to gate them too. Task (sub-agents) is gated like any tool, and each sub-agent's own tool calls
go through the same hook with context.subagent_id set.

Shadow mode (Abe(policy, mode="shadow")) records every decision and never changes what the agent does.

This module does not import claude_agent_sdk except inside abe_hooks(), so `import abe` stays offline and
dependency-free. The hook callables themselves need nothing from the SDK.
"""
from __future__ import annotations

import asyncio
import logging
from collections import OrderedDict
from typing import Any, Callable, Iterable, Mapping

from ..gate import RESERVED_ACTION_KEYS, Gate

log = logging.getLogger("abe")

ACT_MODES = ("passthrough", "allow")
# Harness tools with no side effects outside the conversation. Gating them under a fail-closed policy only
# stops the agent from working (ToolSearch loads the schema of an MCP tool before Claude can call it).
# Pass ungated=() to send these through Abe too.
DEFAULT_UNGATED = ("ToolSearch", "TodoWrite", "AskUserQuestion")
ESCALATE_MODES = ("deny", "ask", "defer")
_MAX_PENDING = 10_000

# map_request(tool_name, tool_input, hook_input) -> FJP request dict, or None to leave the call ungated
RequestMapper = Callable[[str, dict, dict], "dict | None"]


def tool_to_action(tool_name: str, tool_input: Mapping[str, Any] | None,
                   action_types: Mapping[str, str] | None = None) -> dict:
    """Default mapping: the tool's input fields become action fields, so policies can test
    action.amount, action.command, action.file_path, ...

    action.type is the tool name ("Bash", "Write", "mcp__stripe__create_payment"), or action_types[tool_name]
    when given, so an existing policy written for "purchase" can gate a payments tool unchanged.
    action.tool is always the raw tool name. An input field called "type" is kept as action.input_type.
    Fields FJP reserves for records (directive, judgment_ref) are dropped.
    """
    action: dict[str, Any] = {}
    for k, v in dict(tool_input or {}).items():
        if not isinstance(k, str) or k in RESERVED_ACTION_KEYS or k in ("tool", "input_type"):
            continue
        action["input_type" if k == "type" else k] = v
    action["type"] = (action_types or {}).get(tool_name, tool_name)
    action["tool"] = tool_name
    return action


def _reason(result) -> str:
    """One line Claude can act on: decision, reason code, the rule that fired, and the record id."""
    parts = [f"Abe {result.decision}: {result.reason_code}"]
    if result.resolution and result.resolution.get("reason"):
        parts.append(str(result.resolution["reason"]))
    else:
        gate_rec = result.records[0] if result.records else result.record
        findings = getattr(gate_rec, "rule_results", None) or ()
        descs = [f.get("description") for f in findings
                 if isinstance(f, Mapping) and f.get("description")
                 and f.get("decision") == (result.gate_decision or result.decision)]
        if descs:
            parts.append(str(descs[0]))
    parts.append(f"record {result.record_id}")
    return " | ".join(parts)


def _output(decision: str, reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": reason}}


class AbeHooks:
    """The hook callables. Use abe_hooks() to get them wired into ClaudeAgentOptions(hooks=...)."""

    def __init__(self, gate: Gate, *, agent_id: str = "claude-agent", principal_id: str | None = None,
                 action_types: Mapping[str, str] | None = None, map_request: RequestMapper | None = None,
                 act: str = "passthrough", escalate: str = "deny", record_outcomes: bool = True,
                 evidence: Mapping[str, Any] | None = None, confidence: float | None = None,
                 ungated: Iterable[str] = DEFAULT_UNGATED):
        if not callable(getattr(gate, "check", None)):
            raise TypeError("gate must be an abe.Abe / abe.Gate")
        if act not in ACT_MODES:
            raise ValueError(f"act must be one of {ACT_MODES}")
        if escalate not in ESCALATE_MODES:
            raise ValueError(f"escalate must be one of {ESCALATE_MODES}")
        self.gate, self.agent_id, self.principal_id = gate, agent_id, principal_id
        self.action_types = dict(action_types or {})
        self.map_request = map_request
        self.act, self.escalate, self.record_outcomes = act, escalate, record_outcomes
        self.evidence = dict(evidence or {})
        self.confidence = confidence
        self.ungated = frozenset(ungated or ())
        self._pending: OrderedDict[str, Any] = OrderedDict()   # tool_use_id -> GateResult awaiting an outcome

    # ------------------------------------------------------------------ request

    def build_request(self, hook_input: Mapping[str, Any], tool_use_id: str | None) -> dict | None:
        tool_name = str(hook_input.get("tool_name") or "unknown")
        if tool_name in self.ungated:
            return None
        tool_input = hook_input.get("tool_input")
        tool_input = dict(tool_input) if isinstance(tool_input, Mapping) else {}
        if self.map_request is not None:
            return self.map_request(tool_name, tool_input, dict(hook_input))
        context: dict[str, Any] = {"agent_id": self.agent_id, "framework": "claude-agent-sdk"}
        if self.principal_id:
            context["principal_id"] = self.principal_id
        for src, dst in (("session_id", "session_id"), ("cwd", "cwd"), ("permission_mode", "permission_mode"),
                         ("agent_id", "subagent_id"), ("agent_type", "subagent_type")):
            v = hook_input.get(src)
            if isinstance(v, str) and v:
                context[dst] = v
        tid = tool_use_id or hook_input.get("tool_use_id")
        if isinstance(tid, str) and tid:
            context["tool_use_id"] = tid
        req: dict[str, Any] = {"action": tool_to_action(tool_name, tool_input, self.action_types),
                               "context": context}
        if self.evidence:
            req["evidence"] = dict(self.evidence)
        if self.confidence is not None:
            req["confidence"] = self.confidence
        return req

    # ------------------------------------------------------------------ hooks

    async def pre_tool_use(self, hook_input: dict, tool_use_id: str | None, context: Any = None) -> dict:
        try:
            req = self.build_request(hook_input, tool_use_id)
        except Exception as e:  # noqa: BLE001 - a broken mapper must not let the call through
            log.warning("abe: request mapping failed; denying tool call: %s", e)
            return _output("deny", f"Abe ESCALATE: EVALUATION_FAILURE | could not map tool call: {e}")
        if req is None:
            return {}   # the mapper chose not to gate this tool
        # check() is CPU-only unless a resolver (e.g. Flow) is attached; run it off the event loop either way.
        result = await asyncio.to_thread(self.gate.check, req)
        if not result.enforced:   # shadow mode: recorded, never enforced
            return {}
        reason = _reason(result)
        if result.decision == "ACT":
            tid = tool_use_id or hook_input.get("tool_use_id")
            if self.record_outcomes and isinstance(tid, str) and tid:
                self._pending[tid] = result
                while len(self._pending) > _MAX_PENDING:
                    self._pending.popitem(last=False)
            return _output("allow", reason) if self.act == "allow" else {}
        if result.decision == "BLOCK":
            return _output("deny", reason)
        return _output(self.escalate, reason)

    def _outcome(self, hook_input: Mapping[str, Any], tool_use_id: str | None, status: str, extra: dict) -> None:
        tid = tool_use_id or hook_input.get("tool_use_id")
        result = self._pending.pop(tid, None) if isinstance(tid, str) else None
        if result is None:
            return
        try:
            self.gate.record_outcome(result.records[0], status,
                                     {"request_hash": result.records[0].request_hash, "tool_use_id": tid, **extra})
        except Exception as e:  # noqa: BLE001 - outcome bookkeeping never breaks the agent
            log.warning("abe: could not record outcome for %s: %s", tid, e)

    async def post_tool_use(self, hook_input: dict, tool_use_id: str | None, context: Any = None) -> dict:
        self._outcome(hook_input, tool_use_id, "executed", {})
        return {}

    async def post_tool_use_failure(self, hook_input: dict, tool_use_id: str | None, context: Any = None) -> dict:
        err = hook_input.get("error")
        self._outcome(hook_input, tool_use_id, "failed", {"error": str(err)[:500]} if err else {})
        return {}


def abe_hooks(gate: Gate, *, matcher: str | None = None, timeout: float | None = None,
              tools: Iterable[str] | None = None, **kwargs) -> dict:
    """Hooks for ClaudeAgentOptions(hooks=...).

    matcher: SDK tool-name pattern to gate (e.g. "Bash|Write|mcp__stripe__.*"); default gates every tool.
    tools: shorthand for matcher="A|B|C" with exact names.
    Other keyword arguments go to AbeHooks (agent_id, action_types, escalate, act, map_request, ...).

    To merge with hooks you already have:  {**my_hooks, **abe_hooks(abe)} won't merge per event;
    use AbeHooks directly and add its methods to your own HookMatcher lists.
    """
    try:
        from claude_agent_sdk import HookMatcher   # imported here so `import abe` never needs the SDK
    except ImportError as e:
        raise ImportError('abe_hooks() needs the Claude Agent SDK: pip install "abe-ai[claude]"') from e

    if tools is not None:
        if matcher is not None:
            raise ValueError("pass matcher or tools, not both")
        names = [t for t in tools if t]
        if not names:
            raise ValueError("tools must name at least one tool")
        matcher = "|".join(names)
    h = AbeHooks(gate, **kwargs)
    return {
        "PreToolUse": [HookMatcher(matcher=matcher, hooks=[h.pre_tool_use], timeout=timeout)],
        "PostToolUse": [HookMatcher(matcher=matcher, hooks=[h.post_tool_use])],
        "PostToolUseFailure": [HookMatcher(matcher=matcher, hooks=[h.post_tool_use_failure])],
    }


__all__ = ["AbeHooks", "abe_hooks", "tool_to_action", "ACT_MODES", "ESCALATE_MODES", "DEFAULT_UNGATED"]
