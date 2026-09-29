"""FJP-CONF v0.1 — Gate profile conformance.

Levels (cumulative):
  L0  Valid FJP request/response schema
  L1  Deterministic ACT / BLOCK / ESCALATE behavior (golden fixtures, shared with every SDK)
  L2  Valid Judgment-Grounded Records (FJP-CONF v0.1 L0-L2 on every record + Gate fields)
  L3  Record integrity (hash, tamper detection, immutability), linked outcome records,
      falsifier re-evaluation (FJP-CONF L3 adapter), reproducibility, no-network operation

Run:  abe conformance            (or python -m abe conformance)
"""
from __future__ import annotations

import json
import os
import socket
import statistics
import time
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources

from . import fjp_conf

FIXTURE_PKG = "abe.conformance"


@dataclass
class Check:
    level: int
    check_id: str
    passed: bool
    detail: str = ""


class GateAdapter:
    """FJP-CONF L3 adapter over a Gate with a record store."""

    def __init__(self, gate):
        if gate.store is None:
            raise ValueError("L3 needs a Gate configured with a store")
        self.gate = gate

    def get_record(self, record_id: str) -> dict:
        rec = self.gate.get_record(record_id).to_dict()
        rec["falsifier"]["status"] = self.gate.evaluate_falsifier(record_id)
        return rec

    def evaluate_falsifier(self, record_id: str) -> str:
        return self.gate.evaluate_falsifier(record_id)


def fixtures_dir() -> str:
    return str(resources.files(FIXTURE_PKG).joinpath("fixtures"))


def load_fixtures(base: str | None = None) -> tuple[str, dict]:
    base = base or fixtures_dir()
    with open(os.path.join(base, "decisions.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    return os.path.join(base, data["policy"]), data


class _NetworkBlocked(RuntimeError):
    pass


@contextmanager
def no_network():
    """Any outbound connection attempt inside this block raises and is counted."""
    attempts = []
    orig_connect, orig_cx, orig_gai = socket.socket.connect, socket.create_connection, socket.getaddrinfo

    def deny(*a, **k):
        attempts.append(a[1:] if len(a) > 1 else a)
        raise _NetworkBlocked("network access attempted during Abe evaluation")

    socket.socket.connect = deny
    socket.create_connection = deny
    socket.getaddrinfo = deny
    try:
        yield attempts
    finally:
        socket.socket.connect, socket.create_connection, socket.getaddrinfo = orig_connect, orig_cx, orig_gai


RESPONSE_REQUIRED = ("protocol", "version", "decision", "reason_code", "risk_level", "record_id", "timestamp")
RECORD_REQUIRED = ("protocol", "version", "record_id", "request_id", "timestamp", "event_type", "actor", "action",
                   "decision", "reason_code", "policy", "resolver", "record_hash", "signal", "judgment", "falsifier")


def run(fixtures_base: str | None = None, level: int = 3) -> list[Check]:
    from .. import Gate  # local import: avoid cycles
    from ..canonical import canonical_json, hash_value
    from ..exceptions import RecordImmutableError
    from ..records import compute_record_hash, verify_hash
    from ..reason_codes import is_valid
    from ..stores import MemoryStore

    out: list[Check] = []
    add = lambda lvl, cid, ok, detail="": out.append(Check(lvl, cid, bool(ok), detail))  # noqa: E731
    policy_path, fx = load_fixtures(fixtures_base)

    with no_network() as attempts:
        store = MemoryStore()
        gate = Gate(policy_path, store=store)
        results = {}
        for case in fx["cases"]:
            results[case["id"]] = gate.check(case["request"])

        # ---------------- L0: schemas
        for cid, r in results.items():
            resp = r.to_dict()
            ok = all(k in resp for k in RESPONSE_REQUIRED) and resp["protocol"] == "FJP" and resp["version"] == "0.1" \
                and resp["decision"] in ("ACT", "BLOCK", "ESCALATE") and is_valid(resp["reason_code"])
            add(0, f"L0.response.{cid}", ok, "" if ok else f"invalid response {resp}")
        with open(os.path.join(fixtures_base or fixtures_dir(), "canonical.json"), encoding="utf-8") as fh:
            for i, v in enumerate(json.load(fh)["vectors"]):
                try:
                    got, h = canonical_json(v["value"]), hash_value(v["value"])
                except Exception as e:  # noqa: BLE001
                    got, h = repr(e), ""
                add(0, f"L0.canonical_json.vector_{i}", got == v["canonical"] and h == v["hash"], f"{got} != {v['canonical']}")
        if fx.get("expected_policy_hash"):
            add(0, "L0.policy_hash.cross_language", gate.policy.hash == fx["expected_policy_hash"],
                f"{gate.policy.hash} != {fx['expected_policy_hash']}")

        # ---------------- L1: golden decisions
        if level >= 1:
            for case in fx["cases"]:
                r, exp = results[case["id"]], case["expect"]
                problems = []
                if r.decision != exp["decision"]:
                    problems.append(f"decision {r.decision} != {exp['decision']}")
                if r.reason_code != exp["reason_code"]:
                    problems.append(f"reason_code {r.reason_code} != {exp['reason_code']}")
                if "matched_rules" in exp and list(r.matched_rules) != exp["matched_rules"]:
                    problems.append(f"matched_rules {list(r.matched_rules)} != {exp['matched_rules']}")
                if "missing_evidence" in exp and list(r.missing_evidence) != exp["missing_evidence"]:
                    problems.append(f"missing_evidence {list(r.missing_evidence)} != {exp['missing_evidence']}")
                if "risk_level" in exp and r.risk_level != exp["risk_level"]:
                    problems.append(f"risk_level {r.risk_level} != {exp['risk_level']}")
                if "time_source" in exp and r.record.get("time_source") != exp["time_source"]:
                    problems.append(f"time_source {r.record.get('time_source')} != {exp['time_source']}")
                add(1, f"L1.{case['id']}", not problems, "; ".join(problems))
            never_act = all(results[c["id"]].decision != "ACT" for c in fx["cases"]
                            if c["expect"]["reason_code"] == "EVALUATION_FAILURE")
            add(1, "L1.fail_closed.never_act", never_act, "an evaluation failure produced ACT")

        # ---------------- L2: records
        if level >= 2:
            for cid, r in results.items():
                rec = r.record.to_dict()
                conf = fjp_conf.evaluate(rec, 2)
                failed = [c.check_id for c in conf if not c.passed]
                add(2, f"L2.fjp_conf.{cid}", not failed, f"FJP-CONF failures: {failed}")
                missing = [k for k in RECORD_REQUIRED if k not in rec]
                add(2, f"L2.gate_fields.{cid}", not missing and rec["policy"].get("hash", "").startswith("sha256:")
                    and rec["request_hash"].startswith("sha256:"), f"missing {missing}")

        # ---------------- L3: integrity, linking, falsifiers
        if level >= 3:
            for cid, r in results.items():
                add(3, f"L3.hash.{cid}", verify_hash(r.record), "record_hash does not verify")
            sample = results["T08_definition_of_done"].record
            tampered = sample.to_dict()
            tampered["decision"] = "ACT"
            add(3, "L3.hash.detects_tampering", compute_record_hash(tampered) != tampered["record_hash"])
            try:
                sample.decision = "ACT"  # type: ignore[misc]
                add(3, "L3.immutability", False, "record attribute was assignable")
            except RecordImmutableError:
                add(3, "L3.immutability", True)
            try:
                store.save(sample)
                add(3, "L3.store.append_only", False, "store accepted a duplicate record_id")
            except RecordImmutableError:
                add(3, "L3.store.append_only", True)

            # reproducibility: same canonical request + same policy -> same evaluation content
            req = next(c["request"] for c in fx["cases"] if c["id"] == "T01_explicit_act")
            a, b = gate.check(req).record.evaluation_content(), gate.check(req).record.evaluation_content()
            a.pop("evaluation_time", None), b.pop("evaluation_time", None)
            add(3, "L3.reproducible", canonical_json(a) == canonical_json(b), "evaluation content differs")

            # linked outcomes + falsifier re-evaluation
            adapter = GateAdapter(gate)
            act = results["T01_explicit_act"]
            blk = results["T02_explicit_block_vendor"]
            esc = results["T03_financial_escalation"]
            add(3, "L3.falsifier.open_initially", adapter.evaluate_falsifier(act.record_id) == "open")
            o = gate.record_outcome(act.record, "executed", {"request_hash": act.record.request_hash})
            add(3, "L3.outcome.linked", o.parent_record_id == act.record_id and o.root_record_id == act.record_id
                and o.event_type == "OUTCOME")
            add(3, "L3.outcome.original_unchanged", store.get(act.record_id) == act.record)
            add(3, "L3.falsifier.act_executed_as_evaluated", adapter.evaluate_falsifier(act.record_id) == "expired")
            gate.record_outcome(blk.record, "executed")
            add(3, "L3.falsifier.block_ignored_triggers", adapter.evaluate_falsifier(blk.record_id) == "triggered")
            gate.record_outcome(esc.record, "executed")
            add(3, "L3.falsifier.escalate_bypassed_triggers", adapter.evaluate_falsifier(esc.record_id) == "triggered")
            for rid in (act.record_id, blk.record_id, esc.record_id, o.record_id):
                l3 = fjp_conf.check_l3(adapter, rid)
                failed = [c.check_id for c in l3 if not c.passed]
                add(3, f"L3.fjp_conf.{rid}", not failed, f"FJP-CONF L3 failures: {failed}")
            add(3, "L3.policy_hash_in_every_record",
                all(r.record.policy.hash == gate.policy.hash for r in results.values()))
            add(3, "L3.hash_of_policy_is_canonical", gate.policy.hash == hash_value(gate.policy.raw))

    add(3 if level >= 3 else 0, "L3.no_network", not attempts, f"{len(attempts)} network attempt(s)")
    return [c for c in out if c.level <= level]


def benchmark(n: int = 2000, fixtures_base: str | None = None) -> dict:
    from .. import Gate
    policy_path, fx = load_fixtures(fixtures_base)
    gate = Gate(policy_path)
    reqs = [c["request"] for c in fx["cases"]]
    for r in reqs:
        gate.check(r)
    times = []
    for i in range(n):
        t = time.perf_counter()
        gate.check(reqs[i % len(reqs)])
        times.append((time.perf_counter() - t) * 1000)
    times.sort()
    return {"n": n, "p50_ms": round(statistics.median(times), 3), "p95_ms": round(times[int(n * 0.95) - 1], 3),
            "max_ms": round(times[-1], 3)}


def report(checks: list[Check], level: int) -> tuple[bool, str]:
    lines = [f"FJP-CONF v0.1 — Gate profile — target Level {level}", ""]
    for c in checks:
        lines.append(f"  [{'PASS' if c.passed else 'FAIL'}] L{c.level}  {c.check_id}")
        if not c.passed and c.detail:
            lines.append(f"         -> {c.detail}")
    ok = all(c.passed for c in checks)
    passed = sum(c.passed for c in checks)
    lines += ["", f"{passed}/{len(checks)} checks passed",
              f"RESULT: {'conforms to' if ok else 'does NOT conform to'} FJP-CONF v0.1 Gate profile, Level {level}"]
    return ok, "\n".join(lines)
