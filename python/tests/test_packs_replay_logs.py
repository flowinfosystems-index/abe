"""Policy packs (abe init --pack) and replaying raw agent tool-call logs (abe replay agent-log.jsonl)."""
import json

import pytest

from abe import Abe
from abe.cli import main
from abe.packs import SAMPLES, PackError, build, list_packs
from abe.policy import load_policy
from abe.replay import ReplayInputError, format_report, load_cases, replay
from abe.yaml_safe import load_yaml

PACKS = [n for n, _ in list_packs()]

# What each pack's sample request must decide, and why: the first `abe check` after `abe init --pack` shows this.
SAMPLE_EXPECT = {
    "refunds": ("ESCALATE", "FINANCIAL_THRESHOLD_EXCEEDED"),
    "payments": ("ESCALATE", "FINANCIAL_THRESHOLD_EXCEEDED"),
    "purchasing": ("ESCALATE", "FINANCIAL_THRESHOLD_EXCEEDED"),
    "subscriptions": ("ESCALATE", "HUMAN_APPROVAL_REQUIRED"),
    "customer-email": ("ESCALATE", "HIGH_CONSEQUENCE_ACTION"),
    "deploys": ("ESCALATE", "HUMAN_APPROVAL_REQUIRED"),
    "data-changes": ("ESCALATE", "HIGH_IRREVERSIBILITY"),
}


def _check(policy_text, action):
    return Abe(policy_text).check({"action": action, "context": {"agent_id": "t"}})


def test_every_pack_is_listed_loads_and_has_a_sample():
    assert set(PACKS) == set(SAMPLES) == set(SAMPLE_EXPECT)
    for name, summary in list_packs():
        assert summary, name
        load_policy(load_yaml(build([name])))


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_pack_sample_decision(name):
    r = Abe(build([name])).check(SAMPLES[name])
    assert (r.decision, r.reason_code) == SAMPLE_EXPECT[name]


@pytest.mark.parametrize("name,action,decision", [
    ("refunds", {"type": "refund", "amount": 40}, "ACT"),
    ("refunds", {"type": "issue_refund", "amount": 9000}, "BLOCK"),
    ("refunds", {"type": "refund"}, "ESCALATE"),
    ("refunds", {"type": "lookup_order", "order_id": "A"}, "ACT"),
    ("payments", {"type": "pay_invoice", "amount": 900}, "ACT"),
    ("payments", {"type": "pay_invoice", "amount": 900, "bank_details_changed": True}, "ESCALATE"),
    ("payments", {"type": "wire_transfer", "amount": 300000}, "BLOCK"),
    ("payments", {"type": "update_bank_details"}, "ESCALATE"),
    ("purchasing", {"type": "checkout", "amount": 300}, "ACT"),
    ("purchasing", {"type": "checkout", "amount": 300, "new_vendor": True}, "ESCALATE"),
    ("purchasing", {"type": "purchase", "amount": 150000}, "BLOCK"),
    ("subscriptions", {"type": "subscribe", "amount": 20, "interval": "month"}, "ACT"),
    ("subscriptions", {"type": "subscribe", "amount": 20, "interval": "year"}, "ESCALATE"),
    ("subscriptions", {"type": "start_trial", "auto_renews": True}, "ESCALATE"),
    ("subscriptions", {"type": "start_trial"}, "ACT"),
    ("subscriptions", {"type": "cancel_subscription"}, "ESCALATE"),
    ("customer-email", {"type": "draft_email", "body": "refund"}, "ACT"),
    ("customer-email", {"type": "send_email", "recipient_count": 1, "body": "Thanks, see you Monday."}, "ACT"),
    ("customer-email", {"type": "send_email", "recipient_count": 400, "body": "Newsletter"}, "ESCALATE"),
    ("deploys", {"type": "deploy", "environment": "staging"}, "ACT"),
    ("deploys", {"type": "git_push", "branch": "main", "force": True}, "BLOCK"),
    ("deploys", {"type": "git_push", "branch": "feature/x"}, "ACT"),
    ("deploys", {"type": "merge_pull_request", "base": "main"}, "ESCALATE"),
    ("deploys", {"type": "deploy"}, "ESCALATE"),                        # no environment: fail closed
    ("data-changes", {"type": "execute_sql", "query": "SELECT * FROM users"}, "ACT"),
    ("data-changes", {"type": "execute_sql", "query": "DROP TABLE users"}, "BLOCK"),
    ("data-changes", {"type": "execute_sql", "query": "update users set x=1"}, "ESCALATE"),
    ("data-changes", {"type": "bulk_update", "count": 5000}, "ESCALATE"),
    ("data-changes", {"type": "update_records", "count": 3}, "ACT"),
    ("data-changes", {"type": "drop_table", "table": "users"}, "BLOCK"),
])
def test_pack_rules(name, action, decision):
    r = _check(build([name]), action)
    assert r.decision == decision, (r.reason_code, r.matched_rules)
    assert r.reason_code != "CONFLICTING_RULES"           # ACT rules are written not to overlap the others


def test_combined_packs_keep_every_rule_and_risk():
    text = build(["payments", "refunds", "customer-email", "payments"])   # repeats are dropped
    doc = load_yaml(text)
    assert doc["policy_id"] == "pack-payments-refunds-customer-email"
    single = sum(len(load_yaml(build([n]))["rules"]) for n in ("payments", "refunds", "customer-email"))
    assert len(doc["rules"]) == single
    assert doc["risk"]["mappings"] and doc["defaults"]["unmatched"] == "ESCALATE"
    assert _check(text, {"type": "refund", "amount": 9000}).decision == "BLOCK"
    assert _check(text, {"type": "wire_transfer", "amount": 500}).decision == "ACT"
    assert _check(text, {"type": "deploy", "environment": "production"}).decision == "ESCALATE"   # unmatched


def test_all_packs_combine():
    load_policy(load_yaml(build(PACKS)))


def test_unknown_pack():
    with pytest.raises(PackError):
        build(["nope"])
    with pytest.raises(PackError):
        build([])


def test_cli_init_pack(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--list-packs"]) == 0
    out = capsys.readouterr().out
    assert all(n in out for n in PACKS)
    assert main(["init", "--pack", "refunds"]) == 0
    assert (tmp_path / "abe-policy.yaml").read_text().startswith("# Abe pack: refunds.")
    assert json.loads((tmp_path / "request.json").read_text()) == SAMPLES["refunds"]
    assert main(["check", "request.json", "--policy", "abe-policy.yaml"]) == 20      # ESCALATE exit code
    assert main(["init", "--pack", "deploys", "--pack", "data-changes", "--force"]) == 0
    assert "packs: deploys, data-changes" in (tmp_path / "abe-policy.yaml").read_text()
    assert main(["validate-policy", "abe-policy.yaml"]) == 0
    assert main(["init", "--pack", "nope", "--force"]) == 2


# --------------------------------------------------------------------------- replaying agent logs

LOG = [
    {"role": "user", "content": "refund A-1 and A-2"},
    {"role": "assistant", "content": None, "tool_calls": [
        {"id": "call_1", "type": "function", "function": {"name": "issue_refund",
                                                          "arguments": "{\"order_id\": \"A-1\", \"amount\": 40}"}},
        {"id": "call_2", "type": "function", "function": {"name": "issue_refund",
                                                          "arguments": "{\"order_id\": \"A-2\", \"amount\": 1800}"}}]},
    {"role": "tool", "tool_call_id": "call_1", "content": "ok"},
    {"type": "function_call", "call_id": "call_3", "name": "wire_transfer",
     "arguments": "{\"amount\": 48000, \"new_payee\": true}"},
    {"type": "function_call_output", "call_id": "call_3", "output": "ok"},
    {"role": "assistant", "content": [{"type": "text", "text": "checking"},
                                      {"type": "tool_use", "id": "toolu_4", "name": "get_order",
                                       "input": {"order_id": "A-3"}}]},
    {"type": "tool_use", "id": "toolu_5", "name": "refund", "input": {"amount": 30}},
    {"tool_name": "mcp__stripe__create_refund", "tool_input": {"amount": 9000}, "tool_use_id": "toolu_6"},
    {"tool_calls": [{"name": "send_payment", "args": {"amount": 200}, "id": "lc_7"}]},       # LangChain AIMessage
    {"tool": "lookup_weather", "args": {"city": "SF"}},
]


@pytest.fixture
def policy():
    return build(["refunds", "payments"])


def _log(tmp_path, rows, name="agent.jsonl"):
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return str(p)


def test_agent_log_formats_become_cases(tmp_path):
    cases = load_cases(_log(tmp_path, LOG), action_types={"mcp__stripe__create_refund": "refund"})
    ids = [c["id"] for c in cases]
    assert ids == ["call_1", "call_2", "call_3", "toolu_4", "toolu_5", "toolu_6", "lc_7", "agent.jsonl:10"]
    by = {c["id"]: c["request"]["action"] for c in cases}
    assert by["call_2"] == {"order_id": "A-2", "amount": 1800, "type": "issue_refund", "tool": "issue_refund"}
    assert by["toolu_6"]["type"] == "refund" and by["toolu_6"]["tool"] == "mcp__stripe__create_refund"
    assert cases[0]["request"]["context"] == {"agent_id": "replay", "framework": "replay", "tool_use_id": "call_1"}


def test_agent_log_report(tmp_path, policy):
    cases = load_cases(_log(tmp_path, LOG), action_types={"mcp__stripe__create_refund": "refund"})
    rep = replay(cases, policy)
    d = {r["id"]: r["decision"] for r in rep["results"]}
    assert d == {"call_1": "ACT", "call_2": "ESCALATE", "call_3": "ESCALATE", "toolu_4": "ACT",
                 "toolu_5": "ACT", "toolu_6": "BLOCK", "lc_7": "ACT", "agent.jsonl:10": "ESCALATE"}
    assert rep["exposure"] == {"BLOCK": 9000, "ESCALATE": 49800}
    assert [s["id"] for s in rep["stopped"]] == ["call_2", "call_3", "toolu_6", "agent.jsonl:10"]
    text = format_report(rep)
    assert "Amounts held back: $9,000 blocked, $49,800 escalated" in text
    assert "toolu_6: BLOCK refund $9,000  HARD_POLICY_VIOLATION" in text
    assert "1 escalated only because no rule matched them" in text


def test_conversation_file_with_messages(tmp_path, policy):
    p = tmp_path / "conversation.json"
    p.write_text(json.dumps({"model": "gpt", "messages": LOG[:3]}))
    assert [c["id"] for c in load_cases(str(p))] == ["call_1", "call_2"]


def test_fjp_requests_still_replay_unchanged(tmp_path, policy):
    rows = [{"action": {"type": "refund", "amount": 10}}, {"id": "x", "request": {"action": {"type": "refund"}},
                                                         "expected": "ESCALATE"}]
    rep = replay(load_cases(_log(tmp_path, rows, "fjp.jsonl")), policy)
    assert rep["decisions"]["ACT"] == 1 and rep["mismatches"] == []


def test_bad_tool_arguments(tmp_path):
    rows = [{"type": "function_call", "call_id": "c", "name": "refund", "arguments": "{not json"}]
    with pytest.raises(ReplayInputError):
        load_cases(_log(tmp_path, rows))
    with pytest.raises(ReplayInputError):
        load_cases(_log(tmp_path, [{"type": "tool_use", "id": "t", "input": {}}]))    # no tool name


def test_cli_replay_agent_log(tmp_path, capsys, policy):
    pol = tmp_path / "p.yaml"
    pol.write_text(policy)
    log = _log(tmp_path, LOG)
    assert main(["replay", log, "--policy", str(pol), "--action-type", "mcp__stripe__create_refund=refund"]) == 0
    out = capsys.readouterr().out
    assert "Would have stopped: 4" in out and "toolu_6: BLOCK refund $9,000" in out
    assert main(["replay", log, "--policy", str(pol), "--action-type", "broken"]) == 2
    capsys.readouterr()
    assert main(["replay", log, "--policy", str(pol), "--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["exposure"]["ESCALATE"] == 58800 and "results" not in rep
