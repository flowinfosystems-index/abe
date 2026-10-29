"""Abe as a Claude Agent SDK PreToolUse hook (abe.integrations.claude_agent_sdk)."""
import asyncio
import subprocess
import sys

import pytest

from abe import Abe, Resolution
from abe.conformance import no_network
from abe.integrations.claude_agent_sdk import AbeHooks, abe_hooks, tool_to_action
from abe.stores import MemoryStore

POLICY = """
version: "0.1"
policy_id: claude-sdk-test
policy_version: "2026-10-29"
defaults: { unmatched: ESCALATE }
rules:
  - id: reads
    when: { field: action.type, op: in, value: [Read, Glob, Grep] }
    decision: ACT
  - id: rm_rf
    description: Never delete recursively
    when:
      all:
        - { field: action.type, op: eq, value: Bash }
        - { field: action.command, op: contains, value: "rm -rf" }
    decision: BLOCK
    reason_code: HARD_POLICY_VIOLATION
  - id: safe_bash
    when:
      all:
        - { field: action.type, op: eq, value: Bash }
        - { field: action.command, op: eq, value: "ls" }
    decision: ACT
  - id: small_purchase
    when:
      all:
        - { field: action.type, op: eq, value: purchase }
        - { field: action.amount, op: lte, value: 500 }
    decision: ACT
  - id: big_purchase
    description: Purchases above $10,000 require judgment
    when:
      all:
        - { field: action.type, op: eq, value: purchase }
        - { field: action.amount, op: gt, value: 10000 }
    decision: ESCALATE
    reason_code: FINANCIAL_THRESHOLD_EXCEEDED
"""


def _inp(tool, tool_input, tid="toolu_1", **extra):
    return {"hook_event_name": "PreToolUse", "session_id": "sess_1", "transcript_path": "/t", "cwd": "/w",
            "tool_name": tool, "tool_input": tool_input, "tool_use_id": tid, **extra}


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def abe(store):
    return Abe(POLICY, store=store)


def _decision(out):
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision")


def _reason(out):
    return (out.get("hookSpecificOutput") or {}).get("permissionDecisionReason", "")


def test_tool_to_action_maps_fields_and_reserved_keys():
    a = tool_to_action("mcp__stripe__pay", {"amount": 50, "type": "card", "directive": "x", "judgment_ref": "y"},
                       {"mcp__stripe__pay": "purchase"})
    assert a == {"amount": 50, "input_type": "card", "type": "purchase", "tool": "mcp__stripe__pay"}
    assert tool_to_action("Bash", None) == {"type": "Bash", "tool": "Bash"}


def test_act_passes_through_by_default(abe):
    h = AbeHooks(abe)
    assert run(h.pre_tool_use(_inp("Read", {"file_path": "/w/a.txt"}), "toolu_1", None)) == {}


def test_act_allow_mode(abe):
    out = run(AbeHooks(abe, act="allow").pre_tool_use(_inp("Grep", {"pattern": "x"}), "toolu_1", None))
    assert _decision(out) == "allow" and "Abe ACT" in _reason(out)


def test_block_denies_with_reason_and_record(abe, store):
    out = run(AbeHooks(abe).pre_tool_use(_inp("Bash", {"command": "rm -rf /"}), "toolu_1", None))
    assert _decision(out) == "deny"
    r = _reason(out)
    assert "Abe BLOCK: HARD_POLICY_VIOLATION" in r and "Never delete recursively" in r and "record jgr" in r
    rec_id = r.rsplit("record ", 1)[1]
    assert store.get(rec_id).decision == "BLOCK"


@pytest.mark.parametrize("mode", ["deny", "ask", "defer"])
def test_escalate_modes(abe, mode):
    out = run(AbeHooks(abe, escalate=mode).pre_tool_use(_inp("Write", {"file_path": "/w/x"}), "toolu_1", None))
    assert _decision(out) == mode and "Abe ESCALATE" in _reason(out)


def test_action_types_reuse_existing_policy(abe):
    h = AbeHooks(abe, action_types={"mcp__shop__buy": "purchase"})
    assert run(h.pre_tool_use(_inp("mcp__shop__buy", {"amount": 120}), "t1", None)) == {}
    out = run(h.pre_tool_use(_inp("mcp__shop__buy", {"amount": 12_500}), "t2", None))
    assert _decision(out) == "deny" and "FINANCIAL_THRESHOLD_EXCEEDED" in _reason(out)
    assert "Purchases above $10,000 require judgment" in _reason(out)


def test_context_carries_agent_session_and_subagent(abe, store):
    h = AbeHooks(abe, agent_id="ops-agent", principal_id="user_9")
    run(h.pre_tool_use(_inp("Write", {"file_path": "/w/x"}, agent_id="sub_1", agent_type="code-reviewer"),
                       "toolu_7", None))
    d = _all(store)[-1].to_dict()
    assert d["actor"]["agent_id"] == "ops-agent" and d["actor"]["principal_id"] == "user_9"
    assert d["action"]["tool"] == "Write"


def test_outcomes_executed_and_failed(abe, store):
    h = AbeHooks(abe)
    before = len(_all(store))
    run(h.pre_tool_use(_inp("Read", {"file_path": "/a"}, tid="ok"), "ok", None))
    run(h.post_tool_use(_inp("Read", {"file_path": "/a"}, tid="ok"), "ok", None))
    run(h.pre_tool_use(_inp("Read", {"file_path": "/b"}, tid="bad"), "bad", None))
    run(h.post_tool_use_failure({**_inp("Read", {"file_path": "/b"}, tid="bad"), "error": "ENOENT"}, "bad", None))
    outcomes = [r for r in _all(store)[before:] if r.event_type == "OUTCOME"]
    assert sorted(r.to_dict()["status"] for r in outcomes) == ["executed", "failed"]
    # a denied call never gets an outcome
    run(h.pre_tool_use(_inp("Bash", {"command": "rm -rf x"}, tid="no"), "no", None))
    run(h.post_tool_use(_inp("Bash", {"command": "rm -rf x"}, tid="no"), "no", None))
    assert not [r for r in _all(store)[before:] if r.event_type == "OUTCOME"][2:]


def test_shadow_mode_never_changes_behavior(store):
    abe = Abe(POLICY, store=store, mode="shadow")
    out = run(AbeHooks(abe).pre_tool_use(_inp("Bash", {"command": "rm -rf /"}), "t", None))
    assert out == {}
    assert _all(store)[-1].decision == "BLOCK"


def test_resolver_decides_escalations(store):
    class Approve:
        def resolve(self, request, gate_result):
            return Resolution(decision="ACT", reason="renewal matches last year's order", confidence=0.9)

    class Reject:
        def resolve(self, request, gate_result):
            return Resolution(decision="BLOCK", reason="duplicate of order 4411")

    buy = _inp("mcp__shop__buy", {"amount": 12_500})
    out = run(AbeHooks(Abe(POLICY, resolver=Approve(), store=store), action_types={"mcp__shop__buy": "purchase"})
              .pre_tool_use(buy, "t", None))
    assert out == {}
    out = run(AbeHooks(Abe(POLICY, resolver=Reject(), store=store), action_types={"mcp__shop__buy": "purchase"})
              .pre_tool_use(buy, "t", None))
    assert _decision(out) == "deny" and "duplicate of order 4411" in _reason(out)


def test_broken_mapper_fails_closed(abe):
    def boom(*a):
        raise RuntimeError("bad mapping")
    out = run(AbeHooks(abe, map_request=boom).pre_tool_use(_inp("Bash", {"command": "ls"}), "t", None))
    assert _decision(out) == "deny" and "EVALUATION_FAILURE" in _reason(out)


def test_mapper_none_leaves_tool_ungated(abe):
    out = run(AbeHooks(abe, map_request=lambda *a: None).pre_tool_use(_inp("Write", {}), "t", None))
    assert out == {}


def test_bad_options_rejected(abe):
    with pytest.raises(ValueError):
        AbeHooks(abe, escalate="maybe")
    with pytest.raises(ValueError):
        AbeHooks(abe, act="deny")
    with pytest.raises(TypeError):
        AbeHooks(object())


def test_hooks_make_no_network_calls(abe):
    h = AbeHooks(abe)
    with no_network() as attempts:
        for tool, ti in (("Read", {"file_path": "/a"}), ("Bash", {"command": "rm -rf /"}), ("Write", {})):
            run(h.pre_tool_use(_inp(tool, ti), "t", None))
    assert not attempts


def test_import_abe_does_not_import_sdk():
    code = "import sys, abe, abe.integrations.claude_agent_sdk; print('claude_agent_sdk' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"


def test_abe_hooks_wires_sdk_options(abe):
    sdk = pytest.importorskip("claude_agent_sdk")
    hooks = abe_hooks(abe, tools=["Bash", "Write"], agent_id="ops-agent", escalate="defer")
    assert set(hooks) == {"PreToolUse", "PostToolUse", "PostToolUseFailure"}
    m = hooks["PreToolUse"][0]
    assert isinstance(m, sdk.HookMatcher) and m.matcher == "Bash|Write"
    sdk.ClaudeAgentOptions(hooks=hooks)   # accepted by the real options type
    out = run(m.hooks[0](_inp("Write", {"file_path": "/w/x"}), "t", {"signal": None}))
    assert _decision(out) == "defer"
    with pytest.raises(ValueError):
        abe_hooks(abe, tools=["Bash"], matcher="Bash")


def _all(store):
    return store.all()


def test_harness_tools_ungated_by_default(abe, store):
    n = len(_all(store))
    assert run(AbeHooks(abe).pre_tool_use(_inp("ToolSearch", {"query": "select:mcp__shop__buy"}), "t", None)) == {}
    assert len(_all(store)) == n   # not evaluated, no record
    out = run(AbeHooks(abe, ungated=()).pre_tool_use(_inp("ToolSearch", {"query": "x"}), "t", None))
    assert _decision(out) == "deny"   # unmatched -> ESCALATE under this policy when gated
