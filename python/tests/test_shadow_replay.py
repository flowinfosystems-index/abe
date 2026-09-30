"""Shadow mode and `abe replay`."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from abe import Gate, Resolution, verify_hash
from abe.cli import main
from abe.conformance import fixtures_dir, fjp_conf, no_network
from abe.replay import ReplayInputError, load_cases, replay
from abe.stores import MemoryStore

STANDARD = os.path.join(fixtures_dir(), "policies", "standard.yaml")
CASES = json.load(open(os.path.join(fixtures_dir(), "decisions.json")))["cases"]
T01 = next(c for c in CASES if c["id"] == "T01_explicit_act")["request"]          # ACT
T02 = next(c for c in CASES if c["id"] == "T02_explicit_block_vendor")["request"]  # BLOCK
T03 = next(c for c in CASES if c["id"] == "T03_financial_escalation")["request"]   # ESCALATE


# ---------------------------------------------------------------- shadow mode

@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_shadow_never_changes_the_decision(case):
    e = Gate(STANDARD).check(case["request"])
    s = Gate(STANDARD, mode="shadow").check(case["request"])
    assert (s.decision, s.reason_code, s.matched_rules, s.allowed) == (e.decision, e.reason_code, e.matched_rules,
                                                                        e.allowed)
    assert s.record.request_hash == e.record.request_hash or e.reason_code == "EVALUATION_FAILURE"
    assert s.record.mode == "shadow" and not s.enforced and s.to_dict()["mode"] == "shadow"
    assert "mode" not in e.record and e.enforced and "mode" not in e.to_dict()     # enforce records unchanged
    assert verify_hash(s.record) and fjp_conf.conforms(fjp_conf.evaluate(s.record.to_dict(), 2))


def test_shadow_directive_says_not_enforced():
    r = Gate(STANDARD, mode="shadow").check(T02)
    assert r.record.action.directive.startswith("SHADOW: not enforced. Abe would BLOCK")
    assert "Shadow mode" in r.record.judgment.assessment


def test_bad_mode_rejected():
    with pytest.raises(ValueError):
        Gate(STANDARD, mode="observe")


def test_shadow_is_offline():
    with no_network():
        assert Gate(STANDARD, mode="shadow").check(T03).decision == "ESCALATE"


def _outcome(g, r, status, details=None):
    g.record_outcome(r.records[0], status, details or {})
    return g.evaluate_falsifier(r.records[0].record_id)


@pytest.mark.parametrize("req,status,expect", [
    (T02, "approved", "triggered"),    # people approved what Abe would BLOCK: disagreement
    (T02, "executed", "triggered"),
    (T02, "rejected", "expired"),      # people agreed
    (T01, "rejected", "triggered"),    # people rejected what Abe would ACT on
    (T01, "cancelled", "triggered"),
    (T01, "executed", "expired"),
    (T03, "executed", "expired"),      # ESCALATE: a person reviewed it, so agreement
])
def test_shadow_falsifier_measures_agreement(req, status, expect):
    g = Gate(STANDARD, store=MemoryStore(), mode="shadow")
    r = g.check(req)
    assert g.evaluate_falsifier(r.records[0].record_id) == "open"
    assert _outcome(g, r, status) == expect


def test_shadow_escalate_unnecessary_when_ran_unreviewed():
    g = Gate(STANDARD, store=MemoryStore(), mode="shadow")
    r = g.check(T03)
    assert _outcome(g, r, "executed", {"human_reviewed": False}) == "triggered"


def test_shadow_outcome_records_are_marked():
    g = Gate(STANDARD, store=MemoryStore(), mode="shadow")
    r = g.check(T01)
    assert g.record_outcome(r.records[0], "executed").mode == "shadow"


def test_enforce_falsifier_unchanged():
    g = Gate(STANDARD, store=MemoryStore())
    r = g.check(T02)
    assert _outcome(g, r, "approved") == "open"        # enforce BLOCK is only falsified by executed
    assert _outcome(g, r, "executed") == "triggered"


class _Flow:
    def resolve(self, request, gate_result):
        return Resolution(decision="ACT", reason="within budget", confidence=0.8)


def test_shadow_resolution_is_marked_and_still_consulted():
    g = Gate(STANDARD, store=MemoryStore(), mode="shadow", resolver=_Flow())
    r = g.check(T03)
    if r.resolution is None:
        pytest.skip("standard policy marks T03 not resolvable")
    res = r.records[1]
    assert res.mode == "shadow" and res.action.directive.startswith("SHADOW: not enforced. Abe would ACT")
    assert verify_hash(res) and r.to_dict()["mode"] == "shadow"


# ---------------------------------------------------------------- replay

def _write(tmp_path, name, rows):
    p = tmp_path / name
    if name.endswith(".jsonl"):
        p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    else:
        p.write_text(json.dumps(rows))
    return str(p)


def _stricter(tmp_path):
    text = open(STANDARD).read()
    assert "routine_purchase" in text
    stricter = tmp_path / "stricter.yaml"
    # Unmatched stays ESCALATE; add a rule that blocks every purchase over 50.
    stricter.write_text(text.replace("rules:\n", "rules:\n  - id: freeze_purchases\n    when: { all: [ { field: action.type, op: eq, value: purchase }, { field: action.amount, op: gt, value: 50 } ] }\n    decision: BLOCK\n    reason_code: HARD_POLICY_VIOLATION\n", 1))
    return str(stricter)


def test_load_cases_formats(tmp_path):
    a = _write(tmp_path, "a.jsonl", [T01, {"id": "inv-7", "request": T02, "expected": "BLOCK"}])
    b = _write(tmp_path, "b.json", [T03])
    cases = load_cases(str(tmp_path))
    assert [c["expected"] for c in cases] == [None, "BLOCK", None]
    assert cases[1]["id"] == "inv-7" and cases[0]["id"] == "a.jsonl:1"
    assert len(load_cases(a)) == 2 and len(load_cases(b)) == 1


@pytest.mark.parametrize("bad", ["[1]", '{"request": {"action": {"type": "x"}}, "expected": "MAYBE"}', "{nope"])
def test_load_cases_rejects_bad_input(tmp_path, bad):
    p = tmp_path / "bad.json"
    p.write_text(bad)
    with pytest.raises(ReplayInputError):
        load_cases(str(p))


def test_replay_reports_changes_and_mismatches(tmp_path):
    cases = [{"id": "t1", "request": T01, "expected": "ACT"}, {"id": "t2", "request": T02, "expected": "BLOCK"},
             {"id": "t3", "request": T03}]
    rep = replay(cases, _stricter(tmp_path), baseline=STANDARD)
    assert rep["decisions"] == {"ACT": 0, "BLOCK": 3, "ESCALATE": 0}
    assert [(c["id"], c["from"], c["to"]) for c in rep["changed"]] == [("t1", "ACT", "BLOCK"),
                                                                     ("t3", "ESCALATE", "BLOCK")]
    assert "freeze_purchases" in rep["changed"][0]["matched_rules"]
    assert rep["expected_cases"] == 2 and [m["id"] for m in rep["mismatches"]] == ["t1"] and rep["agreement"] == 0.5


def test_replay_matches_check_for_every_fixture():
    rep = replay([{"id": c["id"], "request": c["request"], "expected": c["expect"]["decision"]} for c in CASES],
                 STANDARD)
    assert rep["mismatches"] == [] and rep["agreement"] == 1.0


def test_replay_writes_nothing_and_is_offline(tmp_path):
    before = set(os.listdir(tmp_path))
    with no_network():
        replay([{"id": "x", "request": T03, "expected": None}], STANDARD)
    assert set(os.listdir(tmp_path)) == before


def test_cli_replay_exit_codes(tmp_path, capsys):
    cases = _write(tmp_path, "c.jsonl", [{"id": "t1", "request": T01}, {"id": "t2", "request": T02}])
    stricter = _stricter(tmp_path)
    assert main(["replay", cases, "--policy", STANDARD]) == 0
    assert main(["replay", cases, "--policy", stricter, "--baseline", STANDARD]) == 0
    out = capsys.readouterr().out
    assert "t1: ACT -> BLOCK" in out and "Changed vs baseline" in out
    assert main(["replay", cases, "--policy", stricter, "--baseline", STANDARD, "--fail-on-change"]) == 1
    exp = _write(tmp_path, "e.jsonl", [{"id": "t1", "request": T01, "expected": "BLOCK"}])
    assert main(["replay", exp, "--policy", STANDARD]) == 1                      # expectation mismatch
    capsys.readouterr()
    assert main(["replay", exp, "--policy", STANDARD, "--json"]) == 1
    rep = json.loads(capsys.readouterr().out)
    assert rep["mismatches"][0]["id"] == "t1" and "results" not in rep
    assert main(["replay", str(tmp_path / "missing.jsonl"), "--policy", STANDARD]) == 2


def test_cli_check_shadow_keeps_exit_code(tmp_path, capsys, monkeypatch):
    req = _write(tmp_path, "r.json", T02)
    assert main(["check", req, "--policy", STANDARD, "--shadow"]) == 10          # BLOCK exit code unchanged
    assert "Mode: shadow" in capsys.readouterr().out
    monkeypatch.setenv("ABE_MODE", "shadow")
    assert main(["check", req, "--policy", STANDARD, "--json"]) == 10
    assert json.loads(capsys.readouterr().out)["mode"] == "shadow"
    monkeypatch.setenv("ABE_MODE", "bogus")
    with pytest.raises(SystemExit):
        main(["check", req, "--policy", STANDARD])


def test_cli_entrypoint_lists_replay():
    out = subprocess.run([sys.executable, "-m", "abe", "--help"], capture_output=True, text=True).stdout
    assert "replay" in out
