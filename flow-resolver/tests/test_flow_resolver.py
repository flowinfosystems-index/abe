"""FlowResolver against a fake transport that mimics resolve.flowinfo.co /api/v1/tools/judge."""
import json
import os

import pytest

from abe import Gate, verify_hash
from abe.conformance import fixtures_dir, fjp_conf, no_network
from abe.stores import MemoryStore
from abe_flow import FlowResolver, redact

STANDARD = os.path.join(fixtures_dir(), "policies", "standard.yaml")
ESC = {"actor": {"agent_id": "procurement-agent"}, "action": {"type": "purchase", "amount": 25000, "vendor": "Acme",
                                                              "card_number": "4111111111111111"},
       "evidence": {"vendor_approved": True, "budget_remaining": 90000}, "confidence": 0.95}


def flow_reply(verb="REACH", confidence="high", jgr=True, request_id="call_123"):
    out = {"verb": verb, "framing": "Budget headroom and vendor history support this. (per FJP judgment)",
           "timing": "now", "confidence": confidence,
           "counter_signal": "Vendor misses the Oct 15 delivery date — Judged by FJP.", "request_id": request_id}
    if jgr:
        out["jgr"] = {"record_id": request_id, "timestamp": "2026-09-29T16:00:00Z",
                      "signal": {"id": f"sig-{request_id}", "description": "x", "sources": ["fjp:gate-record:x"],
                                 "observed_at": "2026-09-29T16:00:00Z"},
                      "judgment": {"id": f"jud-{request_id}", "assessment": "ok", "confidence": 0.8,
                                   "signal_ref": f"sig-{request_id}"},
                      "action": {"directive": f"{verb} (timing: now)", "judgment_ref": f"jud-{request_id}"},
                      "falsifier": {"condition": "Vendor misses the Oct 15 delivery date.", "checkable": True,
                                    "status": "open"}}
    return out


class FakeFlow:
    def __init__(self, status=200, body=None, exc=None):
        self.status, self.body, self.exc, self.calls = status, body if body is not None else flow_reply(), exc, []

    def __call__(self, url, headers, body, timeout):
        self.calls.append((url, headers, json.loads(body), timeout))
        if self.exc:
            raise self.exc
        return self.status, json.dumps(self.body).encode()


def make(fake, **kw):
    return Gate(STANDARD, resolver=FlowResolver(api_key="fjp_test_x", transport=fake, **kw), store=MemoryStore())


def test_escalate_resolved_to_act_with_linked_records():
    fake = FakeFlow()
    r = make(fake).check(ESC)
    assert r.gate_decision == "ESCALATE" and r.decision == "ACT"
    url, headers, body, _ = fake.calls[0]
    assert url == "https://resolve.flowinfo.co/api/v1/tools/judge"
    assert headers["Authorization"] == "Bearer fjp_test_x" and len(headers["X-Idempotency-Key"]) == 64
    assert "4111111111111111" not in body["context"] and "[REDACTED]" in body["context"]
    assert body["sources"][0] == f"fjp:gate-record:{r.records[0].record_id}"
    gate_rec, res = r.records
    assert res.parent_record_id == gate_rec.record_id and res.resolver.type == "FLOW"
    assert res.reason_code == "flow.reach" and res.external_record.record_id == "call_123"
    assert res.judgment_detail.falsifiers[0] == "Vendor misses the Oct 15 delivery date."
    assert verify_hash(res) and fjp_conf.conforms(fjp_conf.evaluate(res.to_dict(), 2))
    assert gate_rec.decision == "ESCALATE"  # the Gate record is never overwritten


@pytest.mark.parametrize("verb,decision", [("SKIP", "BLOCK"), ("WAIT", "ESCALATE"), ("RESEARCH_FIRST", "ESCALATE"),
                                           ("ESCALATE", "ESCALATE")])
def test_verb_mapping(verb, decision):
    assert make(FakeFlow(body=flow_reply(verb))).check(ESC).decision == decision


def test_low_confidence_reach_stays_escalate():
    r = make(FakeFlow(body=flow_reply("REACH", "low"))).check(ESC)
    assert r.decision == "ESCALATE" and "below this resolver's bar" in r.resolution["reason"]


def test_degraded_output_never_acts():
    r = make(FakeFlow(body=flow_reply("REACH", jgr=False))).check(ESC)
    assert r.decision == "ESCALATE" and r.reason_code == "flow.degraded"


@pytest.mark.parametrize("status", [401, 402, 429, 500, 503])
def test_flow_errors_stay_escalate(status):
    r = make(FakeFlow(status=status, body={"error": "x"})).check(ESC)
    assert r.decision == "ESCALATE" and r.resolution["status"] == "unavailable"


def test_flow_unreachable_offline():
    # Real urllib transport with the network blocked: the Gate must still answer.
    with no_network():
        g = Gate(STANDARD, resolver=FlowResolver(api_key="fjp_test_x", timeout=1))
        r = g.check(ESC)
    assert r.decision == "ESCALATE" and r.resolution["status"] == "unavailable"


def test_flow_never_called_for_act_or_block():
    fake = FakeFlow()
    g = make(fake)
    g.check({"actor": {"agent_id": "procurement-agent"}, "action": {"type": "purchase", "amount": 100}, "confidence": 0.95})
    g.check({"actor": {"agent_id": "procurement-agent"}, "action": {"type": "purchase", "amount": 500000}})
    g.check({"actor": {"agent_id": "support-agent"}, "action": {"type": "refund", "amount": 5}})  # evidence missing -> sent
    assert len(fake.calls) == 1


def test_bad_verb_and_bad_json():
    assert make(FakeFlow(body={"verb": "MAYBE"})).check(ESC).resolution["status"] == "unavailable"

    def junk(url, headers, body, timeout):
        return 200, b"<html>"
    assert make(junk).check(ESC).resolution["status"] == "unavailable"


def test_redact_nested():
    assert redact({"a": {"Card_Number": "1", "ok": [{"api_key": "k", "v": 1}]}}, ["card_number", "api_key"]) == \
        {"a": {"Card_Number": "[REDACTED]", "ok": [{"api_key": "[REDACTED]", "v": 1}]}}


def test_requires_key_and_https(monkeypatch):
    monkeypatch.delenv("FLOW_API_KEY", raising=False)
    monkeypatch.delenv("FJP_API_KEY", raising=False)
    with pytest.raises(ValueError):
        FlowResolver()
    with pytest.raises(ValueError):
        FlowResolver(api_key="k", base_url="http://resolve.flowinfo.co")


def test_report_outcome():
    fake = FakeFlow(body={"acknowledged": True, "feedback_id": "f1"})
    res = FlowResolver(api_key="k", transport=fake)
    assert res.report_outcome("call_123", "CORRECT")["acknowledged"] is True
    assert fake.calls[0][0].endswith("/api/v1/outcome")
    with pytest.raises(ValueError):
        res.report_outcome("call_123", "GREAT")


def test_tls_uses_certifi_bundle(monkeypatch):
    import ssl
    from abe_flow import _ssl_context
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    ctx = _ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.cert_store_stats()["x509_ca"] > 50      # a real CA bundle was loaded
