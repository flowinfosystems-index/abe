"""Abe for the OpenAI Agents SDK: tool guardrails gate every function tool call.

    from agents import Agent
    from abe import Abe
    from abe.integrations.openai_agents import gate_tools

    abe = Abe("abe-policy.yaml")
    agent = Agent(name="ops", tools=gate_tools(abe, [pay_invoice, delete_rows], agent_id="ops-agent"))

gate_tools() adds an Abe input guardrail (and an output guardrail that records outcomes) to each FunctionTool
and returns the same list. Use abe_guardrails() to attach them yourself:
function_tool(fn, tool_input_guardrails=[g.input], tool_output_guardrails=[g.output]).

Each call becomes an FJP request (tool arguments become action fields; action.type is the tool name, or
action_types[tool name]):

    ACT       -> the tool runs; a linked OUTCOME record says "executed" after it returns
    BLOCK     -> the tool does not run; the model gets Abe's reason and record id as the tool result
    ESCALATE  -> escalate="reject" (default, fail closed): same as BLOCK.
                 escalate="raise": stops the run with ToolInputGuardrailTripwireTriggered so your code can
                 hand the call to a person. A resolver on the Gate (e.g. Flow) runs first.

Only FunctionTools have tool guardrails in the SDK; hosted tools and MCP tools are passed through unchanged
(gate MCP servers with `abe mcp` instead).

Shadow mode (Abe(policy, mode="shadow")) records every decision and never changes what the agent does.
Requires `pip install "abe-ai[openai-agents]"`. `import abe` never imports the SDK.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..gate import Gate
from ._common import Outcomes, build_request, check_gate, reason_line

ESCALATE_MODES = ("reject", "raise")


@dataclass(frozen=True)
class AbeGuardrails:
    input: Any    # ToolInputGuardrail
    output: Any   # ToolOutputGuardrail


def _sdk():
    try:
        import agents
        from agents import ToolGuardrailFunctionOutput, ToolInputGuardrail, ToolOutputGuardrail
    except ImportError as e:
        raise ImportError('Abe for the OpenAI Agents SDK needs it installed: pip install "abe-ai[openai-agents]"') from e
    return agents, ToolGuardrailFunctionOutput, ToolInputGuardrail, ToolOutputGuardrail


def _arguments(raw: Any) -> dict:
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, str) and raw.strip():
        parsed = json.loads(raw)
        if not isinstance(parsed, Mapping):
            raise ValueError("tool arguments are not a JSON object")
        return dict(parsed)
    return {}


def abe_guardrails(gate: Gate, *, agent_id: str = "openai-agent", principal_id: str | None = None,
                   action_types: Mapping[str, str] | None = None, escalate: str = "reject",
                   record_outcomes: bool = True, evidence: Mapping[str, Any] | None = None,
                   confidence: float | None = None) -> AbeGuardrails:
    """A matched pair of tool guardrails: .input checks the call, .output records the outcome."""
    check_gate(gate)
    if escalate not in ESCALATE_MODES:
        raise ValueError(f"escalate must be one of {ESCALATE_MODES}")
    _, Out, InputGuardrail, OutputGuardrail = _sdk()
    outcomes = Outcomes(gate, enabled=record_outcomes)
    types = dict(action_types or {})

    async def check_call(data):
        ctx = data.context
        tool = str(getattr(ctx, "tool_name", None) or "unknown")
        call_id = getattr(ctx, "tool_call_id", None)
        try:
            req = build_request(tool, _arguments(getattr(ctx, "tool_arguments", None)), framework="openai-agents",
                                agent_id=agent_id, principal_id=principal_id, action_types=types,
                                tool_call_id=call_id, evidence=evidence, confidence=confidence)
        except Exception as e:  # noqa: BLE001 - unparseable arguments must not let the call through
            return Out.reject_content(f"Abe ESCALATE: EVALUATION_FAILURE | could not map tool call: {e}")
        result = await asyncio.to_thread(gate.check, req)
        info = {"decision": result.decision, "reason_code": result.reason_code, "record_id": result.record_id}
        if not result.enforced or result.decision == "ACT":
            if result.enforced:
                outcomes.hold(call_id, result)
            return Out.allow(output_info=info)
        reason = reason_line(result)
        if result.decision == "ESCALATE" and escalate == "raise":
            return Out.raise_exception(output_info={**info, "reason": reason})
        return Out.reject_content(reason, output_info=info)

    async def record_call(data):
        outcomes.finish(getattr(data.context, "tool_call_id", None), "executed")
        return Out.allow()

    return AbeGuardrails(input=InputGuardrail(guardrail_function=check_call, name="abe"),
                         output=OutputGuardrail(guardrail_function=record_call, name="abe_outcome"))


def gate_tools(gate: Gate, tools: Iterable[Any], **kwargs) -> list:
    """Attach Abe to every FunctionTool in tools (in place) and return them as a list."""
    agents, *_ = _sdk()
    g = abe_guardrails(gate, **kwargs)
    out = list(tools)
    for t in out:
        if isinstance(t, agents.FunctionTool):
            t.tool_input_guardrails = [*(t.tool_input_guardrails or []), g.input]
            t.tool_output_guardrails = [*(t.tool_output_guardrails or []), g.output]
    return out


__all__ = ["abe_guardrails", "gate_tools", "AbeGuardrails", "ESCALATE_MODES"]
