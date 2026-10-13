"""`--resolver flow` on the abe CLI and MCP adapter (abe-ai 0.2.1). Flow is faked; nothing leaves the process."""
import asyncio
import json
import os

import pytest

import abe_flow
from abe import Gate
from abe.cli import main
from abe.conformance import fixtures_dir
from abe.stores import MemoryStore
from abe_flow import FlowResolver

from test_flow_resolver import ESC, FakeFlow, flow_reply

STANDARD = os.path.join(fixtures_dir(), "policies", "standard.yaml")


@pytest.fixture
def req_file(tmp_path, monkeypatch):
    for k in ("ABE_RESOLVER", "FLOW_API_KEY", "FJP_API_KEY", "FLOW_RESOLVER_URL", "ABE_MODE"):
        monkeypatch.delenv(k, raising=False)
    p = tmp_path / "request.json"
    p.write_text(json.dumps(ESC))
    return str(p)


def _fake(monkeypatch, **kw):
    fake = FakeFlow(**kw)
    monkeypatch.setattr(abe_flow, "_urllib_transport", fake)
    return fake


def test_default_is_local_only(req_file, monkeypatch):
    fake = _fake(monkeypatch)
    monkeypatch.setenv("FLOW_API_KEY", "fjp_test_x")      # a key alone never turns Flow on
    assert main(["check", req_file, "--policy", STANDARD]) == 20
    assert fake.calls == []


def test_resolver_flag_sends_escalation_to_flow(req_file, monkeypatch, capsys):
    fake = _fake(monkeypatch)
    monkeypatch.setenv("FLOW_API_KEY", "fjp_test_x")
    assert main(["check", req_file, "--policy", STANDARD, "--resolver", "flow"]) == 0     # Flow REACH -> ACT
    assert len(fake.calls) == 1 and fake.calls[0][1]["Authorization"] == "Bearer fjp_test_x"
    out = capsys.readouterr().out
    assert "Decision: ACT" in out and "Resolver: FLOW resolved (Gate said ESCALATE)" in out
    assert "Falsifier: Vendor misses the Oct 15 delivery date." in out


def test_resolver_env_var(req_file, monkeypatch):
    fake = _fake(monkeypatch, body=flow_reply("SKIP"))
    monkeypatch.setenv("FLOW_API_KEY", "fjp_test_x")
    monkeypatch.setenv("ABE_RESOLVER", "flow")
    assert main(["check", req_file, "--policy", STANDARD]) == 10                           # Flow SKIP -> BLOCK
    assert len(fake.calls) == 1


def test_resolver_none_overrides_env(req_file, monkeypatch):
    fake = _fake(monkeypatch)
    monkeypatch.setenv("ABE_RESOLVER", "flow")
    assert main(["check", req_file, "--policy", STANDARD, "--resolver", "none"]) == 20
    assert fake.calls == []


def test_missing_key_is_a_clear_error(req_file, capsys):
    with pytest.raises(SystemExit) as e:
        main(["check", req_file, "--policy", STANDARD, "--resolver", "flow"])
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "FLOW_API_KEY" in err and "fjp.flowinfo.co/credits" in err


def test_bad_resolver_env(req_file, monkeypatch, capsys):
    monkeypatch.setenv("ABE_RESOLVER", "flwo")
    with pytest.raises(SystemExit) as e:
        main(["check", req_file, "--policy", STANDARD])
    assert e.value.code == 2 and "resolver must be one of" in capsys.readouterr().err


def test_flow_402_stays_escalate_on_cli(req_file, monkeypatch, capsys):
    _fake(monkeypatch, status=402, body={"error": "insufficient_credits"})
    monkeypatch.setenv("FLOW_API_KEY", "fjp_test_x")
    assert main(["check", req_file, "--policy", STANDARD, "--resolver", "flow"]) == 20
    assert "out of credits (402)" in capsys.readouterr().err


def test_outcome_ignores_resolver_env(tmp_path, monkeypatch):
    # outcome has no --resolver; ABE_RESOLVER=flow without a key must not break it
    monkeypatch.delenv("FLOW_API_KEY", raising=False)
    monkeypatch.setenv("ABE_RESOLVER", "flow")
    db = f"sqlite:{tmp_path / 'abe.db'}"
    rid = Gate(STANDARD, store=__import__("abe.stores", fromlist=["store_from_uri"]).store_from_uri(db)).check(ESC).record_id
    assert main(["outcome", rid, "cancelled", "--policy", STANDARD, "--store", db]) == 0


# ---------------------------------------------------------------- MCP

def _call(fake, **gate_kw):
    pytest.importorskip("mcp")
    from abe.mcp_server import build_server
    srv = build_server(Gate(STANDARD, resolver=FlowResolver(api_key="fjp_test_x", transport=fake), store=MemoryStore(),
                            **gate_kw))

    async def go():
        res = await srv.call_tool("fjp_check_action", {"action": ESC["action"], "actor": ESC["actor"],
                                                       "evidence": ESC["evidence"], "confidence": ESC["confidence"]})
        payload = res[1] if isinstance(res, tuple) else json.loads(res[0].text)
        return payload.get("result", payload)
    return asyncio.run(go())


def test_mcp_includes_flow_judgment():
    out = _call(FakeFlow())
    assert out["decision"] == "ACT" and out["original_gate_decision"] == "ESCALATE"
    assert "Flow's judgment:" in out["what_to_do"] and "Oct 15 delivery date" in out["what_to_do"]
    assert "resolver_help" not in out


@pytest.mark.parametrize("status,url", [(402, "https://fjp.flowinfo.co/credits"),
                                        (401, "https://fjp.flowinfo.co/credits#lost-key"), (429, None)])
def test_mcp_resolver_help(status, url):
    out = _call(FakeFlow(status=status, body={"error": "x"}))
    assert out["decision"] == "ESCALATE" and "Do not execute" in out["what_to_do"]
    assert out["resolver_help"].get("fix_url") == url
    if url:
        assert url in out["what_to_do"]


def test_mcp_flow_unreachable():
    out = _call(FakeFlow(exc=TimeoutError("timed out")))
    assert out["decision"] == "ESCALATE" and "could not be reached" in out["resolver_help"]["problem"]
