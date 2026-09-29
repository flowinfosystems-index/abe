"""Abe (Abe v0.1) — spec §33 golden tests plus safety, integrity and integration behavior."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest

from abe import Gate, PolicyError, RecordImmutableError, Resolution, verify_hash
from abe.canonical import canonical_json, hash_value
from abe.conformance import GateAdapter, fjp_conf, fixtures_dir, no_network
from abe.records import compute_record_hash
from abe.stores import FileStore, MemoryStore, SQLiteStore

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
STANDARD = os.path.join(fixtures_dir(), "policies", "standard.yaml")
STARTER = os.path.join(HERE, "..", "abe", "templates", "starter.yaml")


@pytest.fixture
def gate():
    return Gate(STANDARD, store=MemoryStore())


# ---------------------------------------------------------------- §45 definition of done

def test_definition_of_done_offline():
    with no_network() as attempts:
        gate = Gate(STARTER)
        result = gate.check(action={"type": "wire_transfer", "amount": 50000}, context={"agent_id": "finance-agent"})
    assert result.decision == "ESCALATE"
    assert result.reason_code == "FINANCIAL_THRESHOLD_EXCEEDED"
    assert result.record.protocol == "FJP"
    assert result.record.version == "0.1"
    assert verify_hash(result.record)
    assert attempts == []


def test_spec_section3_example_starter():
    r = Gate(policy=STARTER).check(action={"type": "purchase", "amount": 12500, "currency": "USD"},
                                   context={"agent_id": "procurement-agent", "principal_id": "user_123"})
    assert r.decision == "ESCALATE"
    assert r.record.actor.agent_id == "procurement-agent"


# ---------------------------------------------------------------- §33 golden tests 1-10

def test_01_explicit_act(gate):
    r = gate.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 100},
                   evidence={"vendor_approved": True}, confidence=0.95)
    assert (r.decision, r.reason_code) == ("ACT", "POLICY_SATISFIED")
    assert r.allowed


def test_02_explicit_block(gate):
    r = gate.check(actor={"agent_id": "procurement-agent"},
                   action={"type": "purchase", "amount": 100, "target": "vendor_blocked_1"}, confidence=0.99)
    assert (r.decision, r.reason_code) == ("BLOCK", "HARD_POLICY_VIOLATION")
    assert "blocked_vendor" in r.matched_rules and not r.allowed


def test_03_financial_escalation(gate):
    r = gate.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 25000}, confidence=0.99)
    assert (r.decision, r.reason_code) == ("ESCALATE", "FINANCIAL_THRESHOLD_EXCEEDED")


def test_04_missing_evidence(gate):
    r = gate.check(actor={"agent_id": "support-agent"}, action={"type": "refund", "amount": 20},
                   evidence={"customer_verified": True}, confidence=0.99)
    assert (r.decision, r.reason_code) == ("ESCALATE", "EVIDENCE_MISSING")
    assert r.missing_evidence == ("evidence.original_transaction", "evidence.refund_policy_loaded")
    assert r.to_dict()["missing_evidence"] == ["evidence.original_transaction", "evidence.refund_policy_loaded"]


def test_05_rule_conflict_and_block_override(gate):
    base = {"actor": {"agent_id": "procurement-agent"}, "evidence": {"vendor_approved": True}, "confidence": 0.99}
    r = gate.check({**base, "action": {"type": "purchase", "amount": 12500}})
    assert (r.decision, r.reason_code) == ("ESCALATE", "CONFLICTING_RULES")
    assert set(r.reason_codes) >= {"CONFLICTING_RULES", "FINANCIAL_THRESHOLD_EXCEEDED", "POLICY_SATISFIED"}
    r = gate.check({**base, "action": {"type": "purchase", "amount": 12500, "target": "vendor_blocked_2"}})
    assert r.decision == "BLOCK"


@pytest.mark.parametrize("request_obj", [
    {"actor": {"agent_id": "procurement-agent"}, "action": {"type": "purchase", "amount": "lots"}},  # type mismatch
    {"action": {"amount": 5}},                                   # no type
    {"action": "purchase"},                                      # not an object
    {"action": {"type": "purchase", "amount": float("nan")}},    # NaN
    {"action": {"type": "purchase", "amount": 2**60}},           # unsafe integer
    {"action": {"type": "x"}, "confidence": 7},                  # confidence out of range
    {"action": {"type": "x"}, "risk": {"level": "EXTREME"}},     # bad level
    {"action": {"type": "x"}, "context": {"current_time": 5}},   # bad time
    {"action": {"type": "x", "judgment_ref": "forged"}},         # reserved field
    {"action": {"type": "x", "blob": object()}},                 # non-JSON value
    {"protocol": "OTHER", "action": {"type": "x"}},
])
def test_06_fail_closed(gate, request_obj):
    r = gate.check(request_obj)
    assert (r.decision, r.reason_code) == ("ESCALATE", "EVALUATION_FAILURE")
    assert r.record.judgment.confidence == 0.0
    assert verify_hash(r.record)
    assert fjp_conf.conforms(fjp_conf.evaluate(r.record.to_dict(), 2))


def test_06_fail_closed_never_raises_on_garbage(gate):
    for junk in (None, 42, "x", [], {"action": None}):
        assert gate.check(junk if isinstance(junk, dict) or junk is None else junk).decision == "ESCALATE"


def test_06_oversized_request(gate):
    r = gate.check(action={"type": "x", "blob": "a" * 300_000})
    assert r.reason_code == "EVALUATION_FAILURE"


def test_06_deep_request(gate):
    deep = cur = {}
    for _ in range(40):
        cur["n"] = {}
        cur = cur["n"]
    r = gate.check(action={"type": "x", "deep": deep})
    assert r.reason_code == "EVALUATION_FAILURE"


def test_07_physical_consequence(gate):
    r = gate.check(actor={"agent_id": "robot-agent"},
                   action={"type": "robot_move_payload", "payload_kg": 1800, "destination": "zone_4"},
                   context={"humans_present": True, "operation_mode": "production"},
                   risk={"level": "CRITICAL"}, irreversibility={"level": "HIGH"}, confidence=0.99)
    assert (r.decision, r.reason_code) == ("ESCALATE", "HIGH_CONSEQUENCE_ACTION")
    assert r.risk_level == "CRITICAL"


def test_08_reproducibility(gate):
    req = {"actor": {"agent_id": "procurement-agent"}, "action": {"type": "purchase", "amount": 100},
           "context": {"current_time": "2026-09-29T16:00:00Z"}, "confidence": 0.95}
    a, b = gate.check(dict(req)), gate.check(json.loads(json.dumps(req)))
    assert a.record_id != b.record_id
    assert a.record.evaluation_content() == b.record.evaluation_content()
    # key order and integral floats do not change the request hash
    c = gate.check({"confidence": 0.95, "action": {"amount": 100.0, "type": "purchase"},
                    "context": {"current_time": "2026-09-29T16:00:00Z"}, "actor": {"agent_id": "procurement-agent"}})
    assert c.record.request_hash == a.record.request_hash


def test_09_record_immutability(gate):
    r = gate.check(action={"type": "purchase", "amount": 100}, actor={"agent_id": "procurement-agent"})
    rec = r.record
    with pytest.raises(RecordImmutableError):
        rec.decision = "ACT"
    with pytest.raises(RecordImmutableError):
        rec.action.amount = 1
    with pytest.raises((TypeError, RecordImmutableError)):
        rec["decision"] = "ACT"
    with pytest.raises((TypeError, RecordImmutableError)):
        del rec.decision
    d = rec.to_dict()
    d["decision"] = "ACT"
    assert rec.decision != "ACT" or r.decision == "ACT"
    assert compute_record_hash(d) != rec.record_hash or r.decision == "ACT"
    with pytest.raises(RecordImmutableError):
        gate.store.save(rec)


def test_10_no_network_all_paths(gate, tmp_path):
    with no_network() as attempts:
        g = Gate(STANDARD, store=SQLiteStore(str(tmp_path / "r.db")))
        for amt in (10, 1000, 25000, 250000):
            r = g.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": amt})
            g.record_outcome(r.record, "cancelled")
            g.evaluate_falsifier(r.record_id)
        with pytest.raises(Exception):
            socket.create_connection(("example.com", 80), timeout=1)
    assert len(attempts) == 1  # only the deliberate probe


# ---------------------------------------------------------------- precedence, scales, time

def test_block_beats_everything(gate):
    r = gate.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 500000},
                   confidence=0.1, irreversibility="CRITICAL")
    assert r.decision == "BLOCK"
    assert r.matched_rules[0] == "purchase_hard_limit"


def test_caller_can_raise_but_not_lower_risk(gate):
    low = gate.check(actor={"agent_id": "finance-agent"}, action={"type": "wire_transfer", "amount": 5}, risk="LOW")
    assert low.risk_level == "HIGH" and low.record.risk.source == "policy_mapping"
    hi = gate.check(actor={"agent_id": "support-agent"}, action={"type": "send_internal_message"},
                    risk={"level": "CRITICAL"}, confidence=0.99)
    assert hi.risk_level == "CRITICAL" and hi.decision == "ESCALATE"


def test_explicit_time_recorded(gate):
    r = gate.check(actor={"agent_id": "finance-agent"}, action={"type": "wire_transfer", "amount": 1},
                   context={"current_time": "2026-12-30T00:00:00Z"})
    assert r.record.time_source == "request"
    assert r.record.evaluation_time == "2026-12-30T00:00:00.000Z"
    assert r.reason_code == "acme.quarter_close_freeze"
    s = gate.check(actor={"agent_id": "finance-agent"}, action={"type": "wire_transfer", "amount": 1})
    assert s.record.time_source == "system"


def test_default_unmatched_is_escalate(gate):
    r = gate.check(actor={"agent_id": "robot-agent"}, action={"type": "never_seen_before"}, confidence=0.99)
    assert (r.decision, r.reason_code) == ("ESCALATE", "JUDGMENT_REQUIRED")


def test_unmatched_act_policy():
    g = Gate({"version": "0.1", "defaults": {"unmatched": "ACT"}})
    r = g.check(action={"type": "anything"})
    assert (r.decision, r.reason_code) == ("ACT", "POLICY_SATISFIED")


def test_operators():
    pol = {"version": "0.1", "defaults": {"unmatched": "ACT"}, "rules": [
        {"id": "neq", "when": {"field": "action.region", "op": "neq", "value": "us"}, "decision": "ESCALATE"},
        {"id": "notin", "when": {"field": "action.ccy", "op": "not_in", "value": ["USD", "EUR"]}, "decision": "BLOCK"},
        {"id": "contains_s", "when": {"field": "action.memo", "op": "contains", "value": "crypto"}, "decision": "BLOCK"},
        {"id": "contains_l", "when": {"field": "action.tags", "op": "contains", "value": "pii"}, "decision": "ESCALATE"},
        {"id": "notexists", "when": {"field": "evidence.ticket", "op": "not_exists"}, "decision": "ESCALATE",
         "reason_code": "HUMAN_APPROVAL_REQUIRED"},
        {"id": "anynot", "when": {"any": [{"not": {"field": "action.n", "op": "gte", "value": 0}},
                                          {"field": "action.n", "op": "lt", "value": -100}]}, "decision": "BLOCK"},
    ]}
    g = Gate(pol)
    ok = {"region": "us", "ccy": "USD", "memo": "office chairs", "tags": ["ops"], "n": 5}
    assert g.check(action={"type": "t", **ok}, evidence={"ticket": "T-1"}).decision == "ACT"
    assert g.check(action={"type": "t", **ok, "region": "eu"}, evidence={"ticket": "T"}).matched_rules == ("neq",)
    assert g.check(action={"type": "t", **ok, "ccy": "JPY"}, evidence={"ticket": "T"}).decision == "BLOCK"
    assert g.check(action={"type": "t", **ok, "memo": "buy crypto"}, evidence={"ticket": "T"}).decision == "BLOCK"
    assert g.check(action={"type": "t", **ok, "tags": ["pii"]}, evidence={"ticket": "T"}).decision == "ESCALATE"
    assert g.check(action={"type": "t", **ok}).reason_code == "HUMAN_APPROVAL_REQUIRED"
    assert g.check(action={"type": "t", **ok, "n": -5}, evidence={"ticket": "T"}).decision == "BLOCK"
    assert g.check(action={"type": "t", **ok, "tags": 5}, evidence={"ticket": "T"}).reason_code == "EVALUATION_FAILURE"


# ---------------------------------------------------------------- policy safety

@pytest.mark.parametrize("text,msg", [
    ('version: "0.1"\nrules:\n  - id: a\n    when: {field: acton.type, op: eq, value: x}\n    decision: ACT\n', "must start with"),
    ('version: "0.1"\nrules:\n  - id: a\n    when: {field: action.type, op: equals, value: x}\n    decision: ACT\n', "unknown op"),
    ('version: "0.1"\nrules:\n  - id: a\n    when: {field: action.type, op: eq, value: x}\n    decision: ALLOW\n', "decision"),
    ('version: "0.1"\nrules:\n  - id: a\n    when: {field: action.type, op: eq, value: x}\n    decision: ACT\n    reason_code: MADE_UP\n', "reason_code"),
    ('version: "0.1"\nrules:\n  - id: a\n    when: {field: action.type, op: eq, value: x}\n    decision: ACT\n  - id: a\n    when: {field: action.type, op: eq, value: y}\n    decision: ACT\n', "duplicate rule id"),
    ('version: "0.1"\nrulez: []\n', "unknown key"),
    ("version: 0.1\n", "string"),
    ('version: "0.1"\nx: &a [1]\ny: *a\n', "aliases"),
    ('version: "0.1"\nversion: "0.1"\n', "duplicate key"),
    ('version: "0.1"\nrules:\n  - id: a\n    when: {field: action.amount, op: gt, value: [1]}\n    decision: ACT\n', "number or string"),
    ('version: "0.1"\nrules: !!python/object/apply:os.system ["echo pwned"]\n', "invalid YAML"),
    ('version: "0.1"\nrules:\n  - id: a\n    when: {field: action.type, op: in, value: []}\n    decision: ACT\n', "non-empty"),
])
def test_invalid_policies_rejected(text, msg):
    with pytest.raises(PolicyError, match=msg):
        Gate(text)


def test_yaml_12_scalars():
    g = Gate('version: "0.1"\nrules:\n  - id: a\n    when: {field: action.flag, op: eq, value: yes}\n'
             '    decision: BLOCK\n  - id: b\n    when: {field: action.code, op: eq, value: 010}\n    decision: BLOCK\n'
             '  - id: c\n    when: {field: action.day, op: eq, value: 2026-09-29}\n    decision: BLOCK\n')
    assert g.check(action={"type": "t", "flag": "yes"}).decision == "BLOCK"       # 'yes' is a string, not true
    assert g.check(action={"type": "t", "flag": True}).decision == "ESCALATE"
    assert g.check(action={"type": "t", "code": 10}).decision == "BLOCK"          # 010 is decimal 10, not octal 8
    assert g.check(action={"type": "t", "day": "2026-09-29"}).decision == "BLOCK"  # dates stay strings


def test_policy_hash_is_stable_and_pinned():
    fx = json.load(open(os.path.join(fixtures_dir(), "decisions.json")))
    assert Gate(STANDARD).policy.hash == fx["expected_policy_hash"]
    p = Gate(STANDARD).policy
    assert Gate(p.raw).policy.hash == p.hash


def test_missing_policy_file():
    with pytest.raises(PolicyError, match="not found"):
        Gate("does-not-exist.yaml")


# ---------------------------------------------------------------- records, outcomes, falsifiers

def test_record_is_fjp_conf_l2_and_l3(gate):
    r = gate.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 100}, confidence=0.95)
    assert fjp_conf.conforms(fjp_conf.evaluate(r.record.to_dict(), 2))
    assert fjp_conf.conforms(fjp_conf.check_l3(GateAdapter(gate), r.record_id))


def test_outcome_links_and_never_mutates(gate):
    r = gate.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 100}, confidence=0.95)
    before = r.record.to_dict()
    o = gate.record_outcome(r.record_id, "executed", {"request_hash": r.record.request_hash, "final_amount": 100})
    assert o.parent_record_id == r.record_id and o.event_type == "OUTCOME" and verify_hash(o)
    assert gate.get_record(r.record_id).to_dict() == before
    assert gate.evaluate_falsifier(r.record_id) == "expired"


def test_falsifier_act_triggered_by_different_execution(gate):
    r = gate.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 100}, confidence=0.95)
    gate.record_outcome(r.record, "executed", {"request_hash": "sha256:" + "0" * 64})
    assert gate.evaluate_falsifier(r.record) == "triggered"


def test_falsifier_escalate_then_approved_then_executed(gate):
    r = gate.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 50000}, confidence=0.99)
    assert r.decision == "ESCALATE"
    gate.record_outcome(r.record, "approved", {"approver": "cfo"})
    gate.record_outcome(r.record, "executed")
    assert gate.evaluate_falsifier(r.record) == "expired"


def test_falsifier_expires_after_horizon(gate):
    r = gate.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 100}, confidence=0.95)
    later = datetime.now(timezone.utc) + timedelta(days=31)
    assert gate.evaluate_falsifier(r.record_id, now=later) == "expired"


def test_outcome_validation(gate):
    r = gate.check(action={"type": "x"}, actor={"agent_id": "robot-agent"})
    with pytest.raises(ValueError):
        gate.record_outcome(r.record, "done")
    with pytest.raises(LookupError):
        Gate(STANDARD).record_outcome("jgr_unknown", "executed")


@pytest.mark.parametrize("make_store", [
    lambda p: MemoryStore(), lambda p: FileStore(str(p / "r.jsonl")), lambda p: SQLiteStore(str(p / "r.db"))])
def test_stores_roundtrip_and_append_only(tmp_path, make_store):
    store = make_store(tmp_path)
    g = Gate(STANDARD, store=store)
    r = g.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 100.0}, confidence=0.95)
    g.record_outcome(r.record, "executed")
    got = store.get(r.record_id)
    assert got.record_hash == r.record.record_hash and verify_hash(got)
    assert len(store.linked(r.record_id)) == 2
    with pytest.raises(RecordImmutableError):
        store.save(r.record)


def test_sqlite_blocks_update_and_delete(tmp_path):
    import sqlite3
    store = SQLiteStore(str(tmp_path / "r.db"))
    g = Gate(STANDARD, store=store)
    g.check(action={"type": "x"}, actor={"agent_id": "robot-agent"})
    with pytest.raises(sqlite3.DatabaseError):
        with store._conn:
            store._conn.execute("UPDATE fjp_records SET record_json='{}'")
    with pytest.raises(sqlite3.DatabaseError):
        with store._conn:
            store._conn.execute("DELETE FROM fjp_records")


def test_store_failure_fails_closed():
    class Broken(MemoryStore):
        def save(self, record):
            raise OSError("disk full")
    r = Gate(STANDARD, store=Broken()).check(actor={"agent_id": "procurement-agent"},
                                             action={"type": "purchase", "amount": 100}, confidence=0.95)
    assert (r.decision, r.reason_code) == ("ESCALATE", "EVALUATION_FAILURE")


# ---------------------------------------------------------------- resolver interface

class FakeResolver:
    def __init__(self, decision="ACT", raise_exc=None):
        self.decision, self.raise_exc, self.calls = decision, raise_exc, 0

    def resolve(self, request, gate_result):
        self.calls += 1
        if self.raise_exc:
            raise self.raise_exc
        return Resolution(decision=self.decision, reason="Contextual review passed.", confidence=0.9,
                          falsifiers=("Vendor credit rating falls below BBB before 2026-12-31.",),
                          resolver_type="TEST", implementation="fake", implementation_version="1", reference="ext_1")


def test_resolver_only_called_on_escalate(gate):
    res = FakeResolver()
    g = Gate(STANDARD, resolver=res, store=MemoryStore())
    assert g.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 100},
                   confidence=0.95).decision == "ACT"
    assert g.check(actor={"agent_id": "procurement-agent"},
                   action={"type": "purchase", "amount": 10, "target": "vendor_blocked_1"}).decision == "BLOCK"
    assert res.calls == 0
    r = g.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 25000}, confidence=0.99)
    assert res.calls == 1
    assert r.decision == "ACT" and r.gate_decision == "ESCALATE"
    gate_rec, res_rec = r.records
    assert gate_rec.decision == "ESCALATE" and res_rec.parent_record_id == gate_rec.record_id
    assert res_rec.original_gate_decision == "ESCALATE" and res_rec.event_type == "RESOLUTION"
    assert verify_hash(gate_rec) and verify_hash(res_rec)
    assert fjp_conf.conforms(fjp_conf.evaluate(res_rec.to_dict(), 2))
    d = r.to_dict()
    assert d["original_gate_decision"] == "ESCALATE" and d["gate_record_id"] == gate_rec.record_id


def test_resolver_failure_stays_escalate():
    g = Gate(STANDARD, resolver=FakeResolver(raise_exc=TimeoutError("flow down")), store=MemoryStore())
    r = g.check(actor={"agent_id": "procurement-agent"}, action={"type": "purchase", "amount": 25000}, confidence=0.99)
    assert r.decision == "ESCALATE" and r.resolution["status"] == "unavailable"
    assert r.records[1].resolution_status == "unavailable"


def test_resolver_cannot_resolve_human_approval_or_failures():
    res = FakeResolver()
    pol = {"version": "0.1", "rules": [{"id": "h", "when": {"field": "action.type", "op": "eq", "value": "deploy"},
                                        "decision": "ESCALATE", "reason_code": "HUMAN_APPROVAL_REQUIRED"}]}
    g = Gate(pol, resolver=res)
    assert g.check(action={"type": "deploy"}).decision == "ESCALATE"
    assert g.check(action={"type": "x", "amount": float("inf")}).decision == "ESCALATE"
    assert res.calls == 0


def test_resolver_invalid_output_ignored():
    class Bad:
        def resolve(self, request, gate_result):
            return {"decision": "ACT"}  # not a Resolution
    r = Gate(STANDARD, resolver=Bad()).check(actor={"agent_id": "procurement-agent"},
                                            action={"type": "purchase", "amount": 25000}, confidence=0.99)
    assert r.decision == "ESCALATE" and r.resolution["status"] == "unavailable"


def test_resolver_disabled_in_policy():
    res = FakeResolver()
    g = Gate({"version": "0.1", "resolver": {"enabled": False}}, resolver=res)
    assert g.check(action={"type": "x"}).decision == "ESCALATE" and res.calls == 0


# ---------------------------------------------------------------- canonical JSON + signing

def test_canonical_vectors():
    vec = json.load(open(os.path.join(fixtures_dir(), "canonical.json"), encoding="utf-8"))["vectors"]
    for v in vec:
        assert canonical_json(v["value"]) == v["canonical"]
        assert hash_value(v["value"]) == v["hash"]


def test_signing_roundtrip(tmp_path):
    pytest.importorskip("cryptography")
    from abe.signing import Signer, generate_keypair, verify_signature
    priv, pub = generate_keypair()
    g = Gate(STANDARD, signer=Signer(priv, key_id="acme:key:1"))
    r = g.check(action={"type": "x"}, actor={"agent_id": "robot-agent"})
    assert r.record.signature.key_id == "acme:key:1"
    assert verify_signature(r.record, pub)
    d = r.record.to_dict()
    d["record_hash"] = "sha256:" + "1" * 64
    assert not verify_signature(d, pub)
    _, other_pub = generate_keypair()
    assert not verify_signature(r.record, other_pub)


# ---------------------------------------------------------------- schemas

def test_outputs_match_published_schemas(gate):
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    sdir = os.path.join(ROOT, "schemas")
    schemas = {n: json.load(open(os.path.join(sdir, n))) for n in os.listdir(sdir)}
    reg = Registry().with_resources([(s["$id"], Resource.from_contents(s)) for s in schemas.values()])
    V = jsonschema.Draft202012Validator
    V(schemas["fjp-policy.schema.json"]).validate(Gate(STANDARD).policy.raw)
    V(schemas["fjp-policy.schema.json"]).validate(Gate(STARTER).policy.raw)
    fx = json.load(open(os.path.join(fixtures_dir(), "decisions.json")))
    for case in fx["cases"]:
        r = gate.check(case["request"])
        V(schemas["fjp-response.schema.json"], registry=reg).validate({**r.to_dict(), "record": r.record.to_dict()})
        V(schemas["jgr.schema.json"]).validate(r.record.to_dict())
        if case["expect"]["reason_code"] != "EVALUATION_FAILURE":
            V(schemas["fjp-request.schema.json"]).validate(case["request"])
    o = gate.record_outcome(r.record, "cancelled")
    V(schemas["jgr.schema.json"]).validate(o.to_dict())


# ---------------------------------------------------------------- performance

def test_performance_targets():
    g = Gate(STANDARD)
    req = {"actor": {"agent_id": "procurement-agent"}, "action": {"type": "purchase", "amount": 12500},
           "evidence": {"vendor_approved": True}, "confidence": 0.95}
    for _ in range(50):
        g.check(req)
    ts = []
    for _ in range(500):
        t = time.perf_counter()
        g.check(req)
        ts.append((time.perf_counter() - t) * 1000)
    ts.sort()
    assert ts[250] < 2.0, f"p50 {ts[250]:.3f} ms"
    assert ts[475] < 10.0, f"p95 {ts[475]:.3f} ms"


# ---------------------------------------------------------------- HTTP mode

def test_http_server_roundtrip():
    from http.server import ThreadingHTTPServer

    from abe.server import make_handler
    g = Gate(STANDARD, store=MemoryStore())
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(g, token="s3cret"))
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    def call(method, path, body=None, token="s3cret"):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                     data=None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode()),
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    try:
        assert call("GET", "/healthz", token="")[0] == 200
        assert call("POST", "/v1/check", {"action": {"type": "x"}}, token="wrong")[0] == 401
        code, body = call("POST", "/v1/check", {"action": {"type": "wire_transfer", "amount": 50000},
                                                "context": {"agent_id": "finance-agent"}})
        assert code == 200 and body["decision"] == "ESCALATE" and body["record"]["record_id"] == body["record_id"]
        code, bad = call("POST", "/v1/check", b"{not json")
        assert code == 200 and bad["reason_code"] == "EVALUATION_FAILURE"
        code, o = call("POST", "/v1/outcome", {"record_id": body["record_id"], "status": "cancelled"})
        assert code == 200 and o["parent_record_id"] == body["record_id"]
        code, rec = call("GET", f"/v1/records/{body['record_id']}")
        assert code == 200 and rec["falsifier"]["status"] in ("open", "expired", "triggered")
        assert call("POST", f"/v1/records/{body['record_id']}/evaluate")[1]["status"] == rec["falsifier"]["status"]
        assert call("GET", "/v1/records/jgr_nope")[0] == 404
    finally:
        httpd.shutdown()


def test_serve_refuses_public_bind_by_default():
    from abe.server import serve
    g = Gate(STANDARD)
    with pytest.raises(SystemExit, match="refusing"):
        serve(g, host="0.0.0.0", port=0)
    with pytest.raises(SystemExit, match="token"):
        serve(g, host="0.0.0.0", port=0, allow_remote=True)


# ---------------------------------------------------------------- CLI

def test_cli(tmp_path, capsys, monkeypatch):
    from abe.cli import main
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert main(["validate-policy", "abe-policy.yaml"]) == 0
    assert main(["check", "request.json", "--record-out", "jgr.json"]) == 20
    out = capsys.readouterr().out
    assert "Decision: ESCALATE" in out and "Reason: FINANCIAL_THRESHOLD_EXCEEDED" in out and "Record: jgr_" in out
    assert main(["validate-record", "jgr.json"]) == 0
    rec = json.load(open("jgr.json"))
    rec["decision"] = "ACT"
    json.dump(rec, open("tampered.json", "w"))
    assert main(["validate-record", "tampered.json"]) == 1
    assert "does not match" in capsys.readouterr().out
    json.dump({"action": {"type": "purchase", "amount": 100}, "actor": {"agent_id": "a"}, "confidence": 0.99},
              open("small.json", "w"))
    assert main(["check", "small.json", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "ACT"
    assert main(["conformance"]) == 0
    assert "RESULT: conforms" in capsys.readouterr().out
    open("bad.yaml", "w").write("version: 0.1\n")
    assert main(["validate-policy", "bad.yaml"]) == 1


def test_cli_outcome_with_sqlite(tmp_path, capsys, monkeypatch):
    from abe.cli import main
    monkeypatch.chdir(tmp_path)
    main(["init"])
    capsys.readouterr()
    main(["check", "request.json", "--store", "sqlite:abe.db", "--json"])
    rid = json.loads(capsys.readouterr().out)["record_id"]
    assert main(["outcome", rid, "cancelled", "--store", "sqlite:abe.db"]) == 0
    assert json.loads(capsys.readouterr().out)["parent_record_id"] == rid


def test_cli_keygen_and_signed_check(tmp_path, capsys, monkeypatch):
    pytest.importorskip("cryptography")
    from abe.cli import main
    monkeypatch.chdir(tmp_path)
    main(["init"])
    assert main(["keygen"]) == 0
    assert oct(os.stat("abe-signing-key.pem").st_mode & 0o777) == "0o600"
    main(["check", "request.json", "--sign-key", "abe-signing-key.pem", "--record-out", "jgr.json"])
    assert main(["validate-record", "jgr.json", "--public-key", "abe-signing-key.pub.pem"]) == 0


# ---------------------------------------------------------------- MCP adapter

def test_mcp_tools():
    pytest.importorskip("mcp")
    import asyncio

    from abe.mcp_server import build_server
    srv = build_server(Gate(STANDARD, store=MemoryStore()))

    async def go():
        names = {t.name for t in await srv.list_tools()}
        assert names == {"fjp_check_action", "fjp_report_outcome", "fjp_get_record"}
        res = await srv.call_tool("fjp_check_action", {"action": {"type": "wire_transfer", "amount": 50000},
                                                       "context": {"agent_id": "finance-agent"}})
        payload = res[1] if isinstance(res, tuple) else json.loads(res[0].text)
        payload = payload.get("result", payload)
        assert payload["decision"] == "ESCALATE" and "Do not execute" in payload["what_to_do"]
        rid = payload["record_id"]
        out = await srv.call_tool("fjp_report_outcome", {"record_id": rid, "status": "cancelled"})
        assert out is not None
        rec = await srv.call_tool("fjp_get_record", {"record_id": rid})
        assert rec is not None
    asyncio.run(go())


def test_abe_name_and_legacy_policy_filename(tmp_path, capsys, monkeypatch):
    from abe import Abe
    from abe.cli import main
    assert Abe is Gate
    r = Abe(STARTER).check(action={"type": "wire_transfer", "amount": 50000}, context={"agent_id": "finance-agent"})
    assert (r.decision, r.reason_code) == ("ESCALATE", "FINANCIAL_THRESHOLD_EXCEEDED")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ABE_POLICY", raising=False)
    monkeypatch.delenv("FJP_POLICY", raising=False)
    main(["init", "--policy-out", "fjp-policy.yaml"])          # a pre-rename file name still works
    assert main(["check", "request.json"]) == 20
