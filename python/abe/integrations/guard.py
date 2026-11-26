"""Abe for any Python function: one decorator gates every call.

Works with plain functions, and under framework tool decorators that read the function's name, docstring and
signature (LangChain's @tool, for one), because the wrapper keeps all three.

    from abe import Abe
    from abe.integrations.guard import guard

    abe = Abe("abe-policy.yaml")

    @guard(abe, action_type="purchase", agent_id="procurement-agent")
    def buy(item: str, amount: float, currency: str = "USD") -> str:
        ...

    buy("servers", 12500)   # Abe checks {"type": "purchase", "item": "servers", "amount": 12500, ...} first

The call's arguments (by parameter name) become action fields, so policies can test action.amount,
action.item, ... action.type is action_type, or the function's name. Arguments named like reserved FJP
fields are dropped, as in every integration.

    ACT       -> the function runs; a linked OUTCOME record says "executed" or "failed"
    BLOCK     -> on_deny="raise" (default): raises AbeBlocked, the function does not run
                 on_deny="return": returns Abe's one-line reason instead, so an LLM tool sees why
    ESCALATE  -> the same, with AbeEscalated. A resolver on the Gate (e.g. Flow) runs first and its
                 ACT / BLOCK is used instead.

Shadow mode (Abe(policy, mode="shadow")) records every decision and always runs the function.
Async functions are supported; check() runs off the event loop.
"""
from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable, Mapping

from ..gate import Gate
from ._common import build_request, check_gate, reason_line, record

ON_DENY = ("raise", "return")


class AbeDenied(Exception):
    """Abe did not allow the call. .result is the GateResult (decision, reason_code, record)."""

    def __init__(self, result, message: str):
        super().__init__(message)
        self.result = result

    @property
    def record_id(self) -> str | None:
        return self.result.record_id if self.result is not None else None


class AbeBlocked(AbeDenied):
    """Abe returned BLOCK: do not run this action."""


class AbeEscalated(AbeDenied):
    """Abe returned ESCALATE: hold this action for a person or a resolver."""


# map_args(func_name, arguments) -> FJP request dict, or None to run the call ungated
ArgsMapper = Callable[[str, dict], "dict | None"]


def guard(gate: Gate, *, action_type: str | None = None, agent_id: str = "agent", principal_id: str | None = None,
          on_deny: str = "raise", record_outcomes: bool = True, map_args: ArgsMapper | None = None,
          evidence: Mapping[str, Any] | None = None, confidence: float | None = None):
    """Decorator: check every call of the function with Abe before it runs."""
    check_gate(gate)
    if on_deny not in ON_DENY:
        raise ValueError(f"on_deny must be one of {ON_DENY}")

    def decorate(func: Callable) -> Callable:
        sig = inspect.signature(func)
        name = getattr(func, "__name__", "call")

        def request_for(args, kwargs) -> dict | None:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            arguments: dict[str, Any] = {}
            for k, v in bound.arguments.items():
                kind = sig.parameters[k].kind
                if kind is inspect.Parameter.VAR_KEYWORD and isinstance(v, Mapping):
                    arguments.update({str(kk): vv for kk, vv in v.items()})
                elif kind is inspect.Parameter.VAR_POSITIONAL:
                    arguments[k] = list(v)
                elif k not in ("self", "cls"):
                    arguments[k] = v
            if map_args is not None:
                return map_args(name, arguments)
            types = {name: action_type} if action_type else None
            return build_request(name, arguments, framework="python", agent_id=agent_id,
                                 principal_id=principal_id, action_types=types, evidence=evidence,
                                 confidence=confidence)

        def decide(result):
            """None to run the function, otherwise what to return / raise instead."""
            if not result.enforced or result.decision == "ACT":
                return None
            reason = reason_line(result)
            if on_deny == "return":
                return reason
            raise (AbeBlocked if result.decision == "BLOCK" else AbeEscalated)(result, reason)

        def _request_or_raise(args, kwargs):
            try:
                return request_for(args, kwargs)
            except TypeError:
                raise   # wrong arguments: same error the function itself would raise
            except Exception as e:  # noqa: BLE001 - a broken mapper must not let the call through
                raise AbeEscalated(None, f"Abe ESCALATE: EVALUATION_FAILURE | could not map call: {e}") from e

        async def _run_async(f, args, kwargs, g, result):
            try:
                out = await f(*args, **kwargs)
            except Exception as e:
                if record_outcomes and result.enforced:
                    record(g, result, "failed", {"error": str(e)[:500]})
                raise
            if record_outcomes and result.enforced:
                record(g, result, "executed")
            return out

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                req = _request_or_raise(args, kwargs)
                if req is None:
                    return await func(*args, **kwargs)
                result = await asyncio.to_thread(gate.check, req)
                denied = decide(result)
                if denied is not None:
                    return denied
                return await _run_async(func, args, kwargs, gate, result)
            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            req = _request_or_raise(args, kwargs)
            if req is None:
                return func(*args, **kwargs)
            result = gate.check(req)
            denied = decide(result)
            if denied is not None:
                return denied
            try:
                out = func(*args, **kwargs)
            except Exception as e:
                if record_outcomes and result.enforced:
                    record(gate, result, "failed", {"error": str(e)[:500]})
                raise
            if record_outcomes and result.enforced:
                record(gate, result, "executed")
            return out

        return wrapper

    return decorate


__all__ = ["guard", "AbeDenied", "AbeBlocked", "AbeEscalated", "ON_DENY"]
