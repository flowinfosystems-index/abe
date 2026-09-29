// Abe (TypeScript) — spec §33 golden tests, safety, integrity, resolver, HTTP, CLI.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  Gate, MemoryStore, FileStore, PolicyError, RecordImmutableError, verifyHash, computeRecordHash, canonicalJson, hashValue,
  Ed25519Signer, generateKeyPair, verifySignature, createGateServer, conformance, fjpConf, Abe,
} from "../dist/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "fixtures");
const STANDARD = join(FIX, "policies", "standard.yaml");
const STARTER = join(HERE, "..", "templates", "starter.yaml");
const CLI = join(HERE, "..", "dist", "cli.js");
const gate = () => new Gate({ policy: STANDARD, store: new MemoryStore() });

test("§45 definition of done (offline)", async () => {
  const { value: r, attempts } = await conformance.withNoNetwork(async () => {
    const g = new Gate({ policy: STARTER });
    return g.check({ action: { type: "wire_transfer", amount: 50000 }, context: { agent_id: "finance-agent" } });
  });
  assert.equal(r.decision, "ESCALATE");
  assert.equal(r.reasonCode, "FINANCIAL_THRESHOLD_EXCEEDED");
  assert.equal(r.record.protocol, "FJP");
  assert.equal(r.record.version, "0.1");
  assert.ok(verifyHash(r.record));
  assert.equal(attempts, 0);
});

test("§22 spec example: new Gate({policy}) + await gate.check", async () => {
  const g = new Gate({ policy: STARTER });
  const result = await g.check({ action: { type: "purchase", amount: 12500, currency: "USD" },
    context: { agent_id: "procurement-agent", principal_id: "user_123" } });
  assert.equal(result.decision, "ESCALATE");
  assert.equal(result.toResponse().reason_code, "FINANCIAL_THRESHOLD_EXCEEDED");
});

test("§33 tests 1-5, 7", async () => {
  const g = gate();
  const c = async (req) => (await g.check(req));
  let r = await c({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 100 }, evidence: { vendor_approved: true }, confidence: 0.95 });
  assert.deepEqual([r.decision, r.reasonCode, r.allowed], ["ACT", "POLICY_SATISFIED", true]);
  r = await c({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 100, target: "vendor_blocked_1" } });
  assert.deepEqual([r.decision, r.reasonCode], ["BLOCK", "HARD_POLICY_VIOLATION"]);
  r = await c({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 25000 }, confidence: 0.99 });
  assert.deepEqual([r.decision, r.reasonCode], ["ESCALATE", "FINANCIAL_THRESHOLD_EXCEEDED"]);
  r = await c({ actor: { agent_id: "support-agent" }, action: { type: "refund", amount: 20 }, evidence: { customer_verified: true }, confidence: 0.99 });
  assert.deepEqual([r.decision, r.reasonCode], ["ESCALATE", "EVIDENCE_MISSING"]);
  assert.deepEqual(r.missingEvidence, ["evidence.original_transaction", "evidence.refund_policy_loaded"]);
  r = await c({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 12500 }, evidence: { vendor_approved: true }, confidence: 0.99 });
  assert.equal(r.reasonCode, "CONFLICTING_RULES");
  r = await c({ actor: { agent_id: "robot-agent" }, action: { type: "robot_move_payload", payload_kg: 1800 }, context: { humans_present: true },
    risk: { level: "CRITICAL" }, irreversibility: { level: "HIGH" }, confidence: 0.99 });
  assert.deepEqual([r.decision, r.reasonCode, r.riskLevel], ["ESCALATE", "HIGH_CONSEQUENCE_ACTION", "CRITICAL"]);
});

test("§33 test 6: fail closed, never throws", async () => {
  const g = gate();
  const bad = [
    { actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: "lots" } },
    { action: { amount: 5 } }, { action: "purchase" }, { action: { type: "x", amount: NaN } },
    { action: { type: "x", amount: 2 ** 60 } }, { action: { type: "x" }, confidence: 7 },
    { action: { type: "x" }, risk: { level: "EXTREME" } }, { action: { type: "x" }, context: { current_time: 5 } },
    { action: { type: "x", judgment_ref: "forged" } }, { action: { type: "x", blob: new Map() } }, { protocol: "OTHER", action: { type: "x" } },
    { action: { type: "x", blob: "a".repeat(300_000) } }, null, 42, "x", [],
  ];
  for (const b of bad) {
    const r = await g.check(b);
    assert.deepEqual([r.decision, r.reasonCode], ["ESCALATE", "EVALUATION_FAILURE"], JSON.stringify(b)?.slice(0, 80));
    assert.ok(verifyHash(r.record));
    assert.ok(fjpConf.conforms(fjpConf.evaluate(r.record, 2)));
  }
});

test("§33 tests 8-9: reproducible, immutable", async () => {
  const g = gate();
  const req = { actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 100 }, context: { current_time: "2026-09-29T16:00:00Z" }, confidence: 0.95 };
  const a = await g.check(req), b = await g.check(JSON.parse(JSON.stringify(req)));
  assert.notEqual(a.recordId, b.recordId);
  assert.equal(a.record.request_hash, b.record.request_hash);
  assert.equal(a.record.evaluation_time, "2026-09-29T16:00:00.000Z");
  assert.throws(() => { a.record.decision = "ACT"; }, TypeError);
  assert.throws(() => { a.record.action.amount = 1; }, TypeError);
  assert.throws(() => { delete a.record.decision; }, TypeError);
  assert.throws(() => g.store.save(a.record), RecordImmutableError);
  const t = { ...JSON.parse(canonicalJson(a.record)), decision: "BLOCK" };
  assert.notEqual(computeRecordHash(t), t.record_hash);
});

test("policy safety: invalid policies rejected at construction", () => {
  const bad = [
    ['version: "0.1"\nrules:\n  - id: a\n    when: {field: acton.type, op: eq, value: x}\n    decision: ACT\n', /must start with/],
    ['version: "0.1"\nrules:\n  - id: a\n    when: {field: action.type, op: equals, value: x}\n    decision: ACT\n', /unknown op/],
    ['version: "0.1"\nrules:\n  - id: a\n    when: {field: action.type, op: eq, value: x}\n    decision: ACT\n    reason_code: MADE_UP\n', /reason_code/],
    ["version: 0.1\n", /string/],
    ['version: "0.1"\nx: &a [1]\ny: *a\n', /aliases/],
    ['version: "0.1"\nversion: "0.1"\n', /invalid YAML/],
    ['version: "0.1"\nrules: !!python/object/apply:os.system ["echo"]\n', /invalid YAML/],
    ['version: "0.1"\nrulez: []\n', /unknown key/],
  ];
  for (const [text, msg] of bad) assert.throws(() => new Gate(text), (e) => e instanceof PolicyError && msg.test(e.message), text);
  assert.throws(() => new Gate("nope.yaml"), /not found/);
});

test("YAML 1.2 scalars match Python", async () => {
  const g = new Gate('version: "0.1"\nrules:\n  - id: a\n    when: {field: action.flag, op: eq, value: yes}\n    decision: BLOCK\n  - id: b\n    when: {field: action.code, op: eq, value: 010}\n    decision: BLOCK\n');
  assert.equal((await g.check({ action: { type: "t", flag: "yes" } })).decision, "BLOCK");
  assert.equal((await g.check({ action: { type: "t", flag: true } })).decision, "ESCALATE");
  assert.equal((await g.check({ action: { type: "t", code: 10 } })).decision, "BLOCK");
});

test("canonical vectors", () => {
  for (const v of JSON.parse(readFileSync(join(FIX, "canonical.json"), "utf8")).vectors) {
    assert.equal(canonicalJson(v.value), v.canonical);
    assert.equal(hashValue(v.value), v.hash);
  }
});

test("outcomes, falsifiers, stores", async () => {
  const dir = mkdtempSync(join(tmpdir(), "fjp-"));
  for (const store of [new MemoryStore(), new FileStore(join(dir, "r.jsonl"))]) {
    const g = new Gate({ policy: STANDARD, store });
    const act = await g.check({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 100 }, confidence: 0.95 });
    assert.equal(await g.evaluateFalsifier(act.recordId), "open");
    const o = await g.recordOutcome(act.recordId, "executed", { request_hash: act.record.request_hash });
    assert.equal(o.parent_record_id, act.recordId);
    assert.equal(await g.evaluateFalsifier(act.recordId), "expired");
    const esc = await g.check({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 50000 }, confidence: 0.99 });
    await g.recordOutcome(esc.record, "approved");
    await g.recordOutcome(esc.record, "executed");
    assert.equal(await g.evaluateFalsifier(esc.record), "expired");
    const blk = await g.check({ actor: { agent_id: "rogue" }, action: { type: "purchase", amount: 1 } });
    await g.recordOutcome(blk.record, "executed");
    assert.equal(await g.evaluateFalsifier(blk.record), "triggered");
    assert.ok(verifyHash(await store.get(act.recordId)));
    await assert.rejects(() => g.recordOutcome(act.record, "done"), TypeError);
  }
});

test("store failure fails closed", async () => {
  const g = new Gate({ policy: STANDARD, store: { save() { throw new Error("disk full"); }, get: () => null, linked: () => [] } });
  const r = await g.check({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 100 }, confidence: 0.95 });
  assert.deepEqual([r.decision, r.reasonCode], ["ESCALATE", "EVALUATION_FAILURE"]);
});

test("resolver: only on ESCALATE, linked record, failures stay ESCALATE, human approval never auto-resolved", async () => {
  let calls = 0;
  const ok = { resolve: async () => { calls++; return { decision: "ACT", reason: "Reviewed.", confidence: 0.9,
    falsifiers: ["Vendor credit rating falls below BBB before 2026-12-31."], resolverType: "TEST", reference: "ext_1" }; } };
  const g = new Gate({ policy: STANDARD, resolver: ok, store: new MemoryStore() });
  assert.equal((await g.check({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 100 }, confidence: 0.95 })).decision, "ACT");
  assert.equal((await g.check({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 999999 } })).decision, "BLOCK");
  assert.equal(calls, 0);
  const r = await g.check({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 25000 }, confidence: 0.99 });
  assert.equal(calls, 1);
  assert.deepEqual([r.decision, r.gateDecision], ["ACT", "ESCALATE"]);
  assert.equal(r.records[1].parent_record_id, r.records[0].record_id);
  assert.equal(r.records[0].decision, "ESCALATE");
  assert.ok(verifyHash(r.records[1]) && fjpConf.conforms(fjpConf.evaluate(r.records[1], 2)));
  assert.equal(r.toResponse().original_gate_decision, "ESCALATE");

  for (const bad of [{ resolve: () => { throw new Error("down"); } }, { resolve: async () => ({ decision: "YES" , reason: "x"}) },
    { resolve: () => new Promise(() => {}) }]) {
    const g2 = new Gate({ policy: STANDARD, resolver: bad, resolverTimeoutMs: 50 });
    const x = await g2.check({ actor: { agent_id: "procurement-agent" }, action: { type: "purchase", amount: 25000 }, confidence: 0.99 });
    assert.equal(x.decision, "ESCALATE");
    assert.equal(x.resolution.status, "unavailable");
  }
  let hc = 0;
  const g3 = new Gate({ policy: { version: "0.1", rules: [{ id: "h", when: { field: "action.type", op: "eq", value: "deploy" }, decision: "ESCALATE", reason_code: "HUMAN_APPROVAL_REQUIRED" }] },
    resolver: { resolve: () => { hc++; return null; } } });
  assert.equal((await g3.check({ action: { type: "deploy" } })).decision, "ESCALATE");
  assert.equal(hc, 0);
});

test("signing interoperates (PEM ed25519)", async () => {
  const { privateKeyPem, publicKeyPem } = generateKeyPair();
  const g = new Gate({ policy: STANDARD, signer: new Ed25519Signer(privateKeyPem, "acme:key:1") });
  const r = await g.check({ action: { type: "x" }, actor: { agent_id: "robot-agent" } });
  assert.equal(r.record.signature.key_id, "acme:key:1");
  assert.ok(verifySignature(r.record, publicKeyPem));
  assert.ok(!verifySignature({ ...r.record, record_hash: "sha256:" + "1".repeat(64) }, publicKeyPem));
  assert.ok(!verifySignature(r.record, generateKeyPair().publicKeyPem));
});

test("HTTP server", async () => {
  const g = gate();
  const srv = createGateServer(g, "s3cret");
  await new Promise((res) => srv.listen(0, "127.0.0.1", res));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const call = async (method, path, body, token = "s3cret") => {
    const res = await fetch(base + path, { method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) });
    return [res.status, await res.json()];
  };
  try {
    assert.equal((await call("GET", "/healthz", undefined, ""))[0], 200);
    assert.equal((await call("POST", "/v1/check", { action: { type: "x" } }, "wrong"))[0], 401);
    const [code, body] = await call("POST", "/v1/check", { action: { type: "wire_transfer", amount: 50000 }, context: { agent_id: "finance-agent" } });
    assert.equal(code, 200);
    assert.equal(body.decision, "ESCALATE");
    assert.equal(body.record.record_id, body.record_id);
    assert.equal((await call("POST", "/v1/check", "{not json"))[1].reason_code, "EVALUATION_FAILURE");
    const [oc, o] = await call("POST", "/v1/outcome", { record_id: body.record_id, status: "cancelled" });
    assert.equal(oc, 200);
    assert.equal(o.parent_record_id, body.record_id);
    assert.equal((await call("GET", `/v1/records/${body.record_id}`))[0], 200);
    assert.equal((await call("GET", "/v1/records/jgr_nope"))[0], 404);
  } finally {
    srv.close();
  }
});

test("CLI", () => {
  const dir = mkdtempSync(join(tmpdir(), "fjp-cli-"));
  const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: "utf8" });
  assert.equal(run("init").status, 0);
  assert.equal(run("validate-policy", "abe-policy.yaml").status, 0);
  const c = run("check", "request.json", "--record-out", "jgr.json");
  assert.equal(c.status, 20);
  assert.match(c.stdout, /Decision: ESCALATE/);
  assert.match(c.stdout, /Record: jgr_/);
  assert.equal(run("validate-record", "jgr.json").status, 0);
  const rec = JSON.parse(readFileSync(join(dir, "jgr.json"), "utf8"));
  writeFileSync(join(dir, "t.json"), JSON.stringify({ ...rec, decision: "ACT" }));
  assert.equal(run("validate-record", "t.json").status, 1);
  assert.equal(run("keygen").status, 0);
  assert.equal(statSync(join(dir, "abe-signing-key.pem")).mode & 0o777, 0o600);
  run("check", "request.json", "--sign-key", "abe-signing-key.pem", "--record-out", "s.json");
  assert.equal(run("validate-record", "s.json", "--public-key", "abe-signing-key.pub.pem").status, 0);
  assert.equal(run("conformance").status, 0);
  const s = run("serve", "--host", "0.0.0.0");
  assert.equal(s.status, 2);
  assert.match(s.stderr, /refusing/);
});

test("performance targets", async () => {
  const b = await conformance.benchmark(1000);
  assert.ok(b.p50_ms < 2, `p50 ${b.p50_ms}`);
  assert.ok(b.p95_ms < 10, `p95 ${b.p95_ms}`);
});

test("Abe is the product name for Gate", async () => {
  assert.equal(Abe, Gate);
  const r = await new Abe({ policy: STARTER }).check({ action: { type: "wire_transfer", amount: 50000 }, context: { agent_id: "finance-agent" } });
  assert.equal(r.reasonCode, "FINANCIAL_THRESHOLD_EXCEEDED");
});
