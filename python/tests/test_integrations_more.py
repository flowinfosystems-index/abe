"""Abe for any function (guard), LangChain / LangGraph (AbeMiddleware) and the OpenAI Agents SDK (gate_tools)."""
import asyncio
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from abe import Abe
from abe.integrations.guard import AbeBlocked, AbeEscalated, guard
from abe.stores import MemoryStore

POLICY = """
version: "0.1"
policy_id: integrations-test
policy_version: "2026-11-26"
defaults: { unmatched: ESCALATE }
rules:
  - id: hard_limit
    description: Never spend more than $100,000
    when: { all: [ { field: action.type, op: eq, value: purchase }, { field: action.amount, op: gt, value: 100000 } ] }
    decision: BLOCK
    reason_code: HARD_POLICY_VIOLATION
  - id: review
    when: { all: [ { field: action.type, op: eq, value: purchase }, { field: action.amount, op: gt, value: 500 } ] }
    decision: ESCALATE
    reason_code: FINANCIAL_THRESHOLD_EXCEEDED
  - id: small
    when: { all: [ { field: action.type, op: eq, value: purchase }, { field: action.amount, op: lte, value: 500 } ] }
    decision: ACT
  - id: lookups
    when: { field: action.type, op: eq, value: lookup }
    decision: ACT
"""


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def abe(store):
    return Abe(POLICY, store=store)


def test_import_abe_stays_framework_free():
    # guard never imports a framework; the framework modules are opt-in, so check abe + guard only
    code = ("import sys, abe, abe.integrations.guard\n"
            "bad=[m for m in ('langchain','langgraph','agents') if m in sys.modules]\n"
            "assert not bad, bad\nprint('ok')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "ok" in out.stdout


# --------------------------------------------------------------------------- guard


def test_guard_act_runs_and_records_outcome(abe):
    calls = []

    @guard(abe, action_type="purchase", agent_id="buyer")
    def buy(item: str, amount: float, currency: str = "USD") -> str:
        calls.append((item, amount, currency))
        return "ok"

    assert buy("cable", 20) == "ok"
    assert calls == [("cable", 20, "USD")]
    assert buy.__name__ == "buy" and "amount" in str(__import__("inspect").signature(buy))


def test_guard_block_and_escalate_raise(abe):
    @guard(abe, action_type="purchase")
    def buy(item, amount):
        raise AssertionError("must not run")

    with pytest.raises(AbeBlocked) as e:
        buy("jet", 5_000_000)
    assert e.value.result.decision == "BLOCK"
    assert "HARD_POLICY_VIOLATION" in str(e.value) and e.value.record_id
    with pytest.raises(AbeEscalated) as e2:
        buy(item="servers", amount=12_500)
    assert e2.value.result.reason_code == "FINANCIAL_THRESHOLD_EXCEEDED"


def test_guard_on_deny_return_gives_reason_to_the_model(abe):
    @guard(abe, action_type="purchase", on_deny="return")
    def buy(item, amount):
        raise AssertionError("must not run")

    out = buy("jet", 5_000_000)
    assert out.startswith("Abe BLOCK: HARD_POLICY_VIOLATION") and "record jgr_" in out


def test_guard_failure_recorded_and_reraised(abe, store):
    @guard(abe, action_type="purchase")
    def buy(item, amount):
        raise RuntimeError("card declined")

    with pytest.raises(RuntimeError):
        buy("cable", 20)
    outs = [r for r in _iter(store) if getattr(r, "event_type", None) == "OUTCOME"]
    assert outs and outs[-1].get("status") == "failed"


def _iter(store):
    for name in ("all", "records", "list"):
        f = getattr(store, name, None)
        if callable(f):
            return list(f())
    return list(getattr(store, "_records", {}).values())


def test_guard_async(abe):
    @guard(abe, action_type="purchase", on_deny="return")
    async def buy(item, amount):
        return "bought"

    assert asyncio.run(buy("cable", 20)) == "bought"
    assert asyncio.run(buy("servers", 12_500)).startswith("Abe ESCALATE")


def test_guard_shadow_always_runs(store):
    abe = Abe(POLICY, store=store, mode="shadow")

    @guard(abe, action_type="purchase")
    def buy(item, amount):
        return "ran"

    assert buy("jet", 5_000_000) == "ran"


def test_guard_bad_mapper_fails_closed(abe):
    def boom(name, args):
        raise ValueError("nope")

    @guard(abe, map_args=boom)
    def f(x):
        raise AssertionError("must not run")

    with pytest.raises(AbeEscalated):
        f(1)


def test_guard_rejects_bad_options(abe):
    with pytest.raises(ValueError):
        guard(abe, on_deny="ignore")
    with pytest.raises(TypeError):
        guard(object())


# --------------------------------------------------------------------------- LangChain / LangGraph

def _fake_model(tool_calls_per_turn):
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    class Fake(GenericFakeChatModel):
        def bind_tools(self, tools, **kw):
            return self

    msgs = [AIMessage(content="", tool_calls=tc) for tc in tool_calls_per_turn] + [AIMessage(content="done")]
    return Fake(messages=iter(msgs))


def _purchase_tool(ran):
    from langchain_core.tools import tool

    @tool
    def purchase(item: str, amount: float) -> str:
        """Buy something."""
        ran.append((item, amount))
        return f"bought {item}"

    return purchase


def _tool_messages(result):
    return [m for m in result["messages"] if m.type == "tool"]


def test_langchain_middleware_act_block_escalate(abe):
    pytest.importorskip("langchain.agents")
    from langchain.agents import create_agent
    from abe.integrations.langchain import AbeMiddleware

    ran = []
    model = _fake_model([[{"name": "purchase", "args": {"item": "cable", "amount": 20}, "id": "c1"},
                          {"name": "purchase", "args": {"item": "jet", "amount": 5_000_000}, "id": "c2"},
                          {"name": "purchase", "args": {"item": "servers", "amount": 12_500}, "id": "c3"}]])
    agent = create_agent(model, [_purchase_tool(ran)],
                         middleware=[AbeMiddleware(abe, action_types={"purchase": "purchase"})])
    tms = {m.tool_call_id: m for m in _tool_messages(agent.invoke({"messages": [("user", "go")]}))}
    assert ran == [("cable", 20)]
    assert tms["c1"].content == "bought cable"
    assert tms["c2"].status == "error" and "Abe BLOCK: HARD_POLICY_VIOLATION" in tms["c2"].content
    assert tms["c3"].status == "error" and "Abe ESCALATE: FINANCIAL_THRESHOLD_EXCEEDED" in tms["c3"].content


def test_langchain_middleware_async(abe):
    pytest.importorskip("langchain.agents")
    from langchain.agents import create_agent
    from abe.integrations.langchain import AbeMiddleware

    ran = []
    model = _fake_model([[{"name": "purchase", "args": {"item": "jet", "amount": 5_000_000}, "id": "c1"}]])
    agent = create_agent(model, [_purchase_tool(ran)], middleware=[AbeMiddleware(abe)])
    result = asyncio.run(agent.ainvoke({"messages": [("user", "go")]}))
    assert ran == [] and "Abe BLOCK" in _tool_messages(result)[0].content


def test_langchain_middleware_interrupt_and_resume(abe):
    pytest.importorskip("langchain.agents")
    from langchain.agents import create_agent
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.types import Command
    from abe.integrations.langchain import AbeMiddleware

    ran = []
    model = _fake_model([[{"name": "purchase", "args": {"item": "servers", "amount": 12_500}, "id": "c1"}]])
    agent = create_agent(model, [_purchase_tool(ran)], checkpointer=InMemorySaver(),
                         middleware=[AbeMiddleware(abe, escalate="interrupt")])
    cfg = {"configurable": {"thread_id": "t1"}}
    first = agent.invoke({"messages": [("user", "go")]}, cfg)
    pending = first.get("__interrupt__")
    assert pending and pending[0].value["reason_code"] == "FINANCIAL_THRESHOLD_EXCEEDED"
    assert ran == []
    agent.invoke(Command(resume="approve"), cfg)
    assert ran == [("servers", 12_500)]


def test_langchain_middleware_options(abe):
    pytest.importorskip("langchain.agents")
    from abe.integrations.langchain import AbeMiddleware
    with pytest.raises(ValueError):
        AbeMiddleware(abe, escalate="ask")
    with pytest.raises(TypeError):
        AbeMiddleware(object())


# --------------------------------------------------------------------------- OpenAI Agents SDK


def _data(tool, args, call_id="call_1"):
    return SimpleNamespace(context=SimpleNamespace(tool_name=tool, tool_arguments=json.dumps(args),
                                                   tool_call_id=call_id), agent=None)


def _behavior(out):
    b = out.behavior
    return b.get("type") if isinstance(b, dict) else getattr(b, "type", b)


def test_openai_agents_guardrail_decisions(abe):
    pytest.importorskip("agents")
    from abe.integrations.openai_agents import abe_guardrails

    g = abe_guardrails(abe, action_types={"buy": "purchase"})
    ok = asyncio.run(g.input.guardrail_function(_data("buy", {"item": "cable", "amount": 20})))
    assert _behavior(ok) == "allow" and ok.output_info["decision"] == "ACT"
    blocked = asyncio.run(g.input.guardrail_function(_data("buy", {"item": "jet", "amount": 5_000_000})))
    assert _behavior(blocked) == "reject_content"
    assert "Abe BLOCK: HARD_POLICY_VIOLATION" in blocked.behavior["message"]
    esc = asyncio.run(g.input.guardrail_function(_data("buy", {"item": "servers", "amount": 12_500})))
    assert _behavior(esc) == "reject_content" and "ESCALATE" in esc.behavior["message"]
    bad = asyncio.run(g.input.guardrail_function(
        SimpleNamespace(context=SimpleNamespace(tool_name="buy", tool_arguments="not json", tool_call_id="x"))))
    assert _behavior(bad) == "reject_content" and "EVALUATION_FAILURE" in bad.behavior["message"]


def test_openai_agents_escalate_raise_and_outcome(abe, store):
    pytest.importorskip("agents")
    from abe.integrations.openai_agents import abe_guardrails

    g = abe_guardrails(abe, action_types={"buy": "purchase"}, escalate="raise")
    esc = asyncio.run(g.input.guardrail_function(_data("buy", {"item": "servers", "amount": 12_500})))
    assert _behavior(esc) == "raise_exception"
    asyncio.run(g.input.guardrail_function(_data("buy", {"item": "cable", "amount": 20}, "call_ok")))
    asyncio.run(g.output.guardrail_function(SimpleNamespace(context=SimpleNamespace(tool_call_id="call_ok"),
                                                            agent=None, output="bought")))
    outs = [r for r in _iter(store) if getattr(r, "event_type", None) == "OUTCOME"]
    assert outs and outs[-1].get("status") == "executed"


def test_openai_agents_gate_tools_attaches(abe):
    pytest.importorskip("agents")
    from agents import function_tool
    from abe.integrations.openai_agents import gate_tools

    @function_tool
    def buy(item: str, amount: float) -> str:
        """Buy something."""
        return "bought"

    tools = gate_tools(abe, [buy])
    assert [g.name for g in tools[0].tool_input_guardrails] == ["abe"]
    assert [g.name for g in tools[0].tool_output_guardrails] == ["abe_outcome"]


def test_guard_under_langchain_tool_decorator(abe):
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    @tool
    @guard(abe, action_type="purchase", on_deny="return")
    def buy(item: str, amount: float) -> str:
        """Buy something."""
        return "bought"

    assert set(buy.args) == {"item", "amount"} and buy.description == "Buy something."
    assert buy.invoke({"item": "cable", "amount": 20}) == "bought"
    assert buy.invoke({"item": "jet", "amount": 5_000_000}).startswith("Abe BLOCK")
