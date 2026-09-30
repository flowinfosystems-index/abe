// Abe (TypeScript) — shadow mode and `abe replay`. Mirrors python/tests/test_shadow_replay.py.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Gate, MemoryStore, verifyHash, fjpConf, conformance, replay, loadCases, ReplayInputError } from "../dist/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "..", "fixtures");
const STANDARD = join(FIX, "policies", "standard.yaml");
const CLI = join(HERE, "..", "dist", "cli.js");
const CASES = JSON.parse(readFileSync(join(FIX, "decisions.json"), "utf8")).cases;
const req = (id) => CASES.find((c) => c.id === id).request;
const T01 = req("T01_explicit_act"), T02 = req("T02_explicit_block_vendor"), T03 = req("T03_financial_escalation");
const tmp = () => mkdtempSync(join(tmpdir(), "abe-shadow-"));
const cli = (args, env = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", env: { ...process.env, ...env } });

function stricter(dir) {
  const text = readFileSync(STANDARD, "utf8");
  const p = join(dir, "stricter.yaml");
  writeFileSync(p, text.replace("rules:\n", "rules:\n  - id: freeze_purchases\n    when: { all: [ { field: action.type, op: eq, value: purchase }, { field: action.amount, op: gt, value: 50 } ] }\n    decision: BLOCK\n    reason_code: HARD_POLICY_VIOLATION\n"));
  return p;
}

test("shadow never changes the decision; enforce records unchanged", async () => {
  for (const c of CASES) {
    const e = await new Gate({ policy: STANDARD }).check(c.request);
    const s = await new Gate({ policy: STANDARD, mode: "shadow" }).check(c.request);
    assert.deepEqual([s.decision, s.reasonCode, s.matchedRules, s.allowed], [e.decision, e.reasonCode, e.matchedRules, e.allowed], c.id);
    assert.equal(s.record.mode, "shadow");
    assert.equal(s.enforced, false);
    assert.equal(s.toResponse().mode, "shadow");
    assert.equal("mode" in e.record, false);
    assert.equal(e.enforced, true);
    assert.equal("mode" in e.toResponse(), false);
    assert.ok(verifyHash(s.record) && fjpConf.conforms(fjpConf.evaluate(s.record, 2)), c.id);
  }
});

test("shadow directive says not enforced; bad mode rejected; offline", async () => {
  const r = await new Gate({ policy: STANDARD, mode: "shadow" }).check(T02);
  assert.ok(r.record.action.directive.startsWith("SHADOW: not enforced. Abe would BLOCK"));
  assert.ok(r.record.judgment.assessment.includes("Shadow mode"));
  assert.throws(() => new Gate({ policy: STANDARD, mode: "observe" }), TypeError);
  const { value } = await conformance.withNoNetwork(() => new Gate({ policy: STANDARD, mode: "shadow" }).check(T03));
  assert.equal(value.decision, "ESCALATE");
});

async function outcome(request, status, details = {}, mode = "shadow") {
  const g = new Gate({ policy: STANDARD, store: new MemoryStore(), mode });
  const r = await g.check(request);
  assert.equal(await g.evaluateFalsifier(r.records[0].record_id), "open");
  await g.recordOutcome(r.records[0], status, details);
  return g.evaluateFalsifier(r.records[0].record_id);
}

test("shadow falsifier measures agreement", async () => {
  for (const [r, status, expect] of [[T02, "approved", "triggered"], [T02, "executed", "triggered"], [T02, "rejected", "expired"],
    [T01, "rejected", "triggered"], [T01, "cancelled", "triggered"], [T01, "executed", "expired"], [T03, "executed", "expired"]])
    assert.equal(await outcome(r, status), expect, `${status}`);
  assert.equal(await outcome(T03, "executed", { human_reviewed: false }), "triggered");
  assert.equal(await outcome(T02, "approved", {}, "enforce"), "open");
});

test("shadow outcome and resolution records are marked", async () => {
  const g = new Gate({ policy: STANDARD, store: new MemoryStore(), mode: "shadow",
    resolver: { resolve: () => ({ decision: "ACT", reason: "within budget", confidence: 0.8 }) } });
  const r = await g.check(T01);
  assert.equal((await g.recordOutcome(r.records[0], "executed")).mode, "shadow");
  const e = await g.check(T03);
  if (e.resolution) {
    assert.equal(e.records[1].mode, "shadow");
    assert.ok(e.records[1].action.directive.startsWith("SHADOW: not enforced. Abe would ACT"));
    assert.ok(verifyHash(e.records[1]));
  }
});

test("replay: load formats, reject bad input", () => {
  const d = tmp();
  writeFileSync(join(d, "a.jsonl"), [T01, { id: "inv-7", request: T02, expected: "BLOCK" }].map((x) => JSON.stringify(x)).join("\n") + "\n");
  writeFileSync(join(d, "b.json"), JSON.stringify([T03]));
  const cases = loadCases(d);
  assert.deepEqual(cases.map((c) => c.expected), [null, "BLOCK", null]);
  assert.equal(cases[1].id, "inv-7");
  assert.equal(cases[0].id, "a.jsonl:1");
  for (const bad of ["[1]", '{"request": {"action": {"type": "x"}}, "expected": "MAYBE"}', "{nope"]) {
    const b = tmp();
    writeFileSync(join(b, "bad.json"), bad);
    assert.throws(() => loadCases(join(b, "bad.json")), ReplayInputError);
  }
});

test("replay: changes, mismatches, parity with check", async () => {
  const d = tmp();
  const rep = await replay([{ id: "t1", request: T01, expected: "ACT" }, { id: "t2", request: T02, expected: "BLOCK" },
    { id: "t3", request: T03, expected: null }], stricter(d), STANDARD);
  assert.deepEqual(rep.decisions, { ACT: 0, BLOCK: 3, ESCALATE: 0 });
  assert.deepEqual(rep.changed.map((c) => [c.id, c.from, c.to]), [["t1", "ACT", "BLOCK"], ["t3", "ESCALATE", "BLOCK"]]);
  assert.deepEqual(rep.mismatches.map((m) => m.id), ["t1"]);
  assert.equal(rep.agreement, 0.5);
  const all = await replay(CASES.map((c) => ({ id: c.id, request: c.request, expected: c.expect.decision })), STANDARD);
  assert.deepEqual(all.mismatches, []);
  assert.equal(all.agreement, 1);
  assert.deepEqual(readdirSync(d), ["stricter.yaml"]); // replay writes nothing
});

test("CLI: replay exit codes and shadow check", () => {
  const d = tmp();
  const cases = join(d, "c.jsonl");
  writeFileSync(cases, [{ id: "t1", request: T01 }, { id: "t2", request: T02 }].map((x) => JSON.stringify(x)).join("\n"));
  const s = stricter(d);
  assert.equal(cli(["replay", cases, "--policy", STANDARD]).status, 0);
  const ch = cli(["replay", cases, "--policy", s, "--baseline", STANDARD]);
  assert.equal(ch.status, 0);
  assert.ok(ch.stdout.includes("t1: ACT -> BLOCK") && ch.stdout.includes("Changed vs baseline"));
  assert.equal(cli(["replay", cases, "--policy", s, "--baseline", STANDARD, "--fail-on-change"]).status, 1);
  const exp = join(d, "e.jsonl");
  writeFileSync(exp, JSON.stringify({ id: "t1", request: T01, expected: "BLOCK" }));
  assert.equal(cli(["replay", exp, "--policy", STANDARD]).status, 1);
  const j = cli(["replay", exp, "--policy", STANDARD, "--json"]);
  const rep = JSON.parse(j.stdout);
  assert.equal(rep.mismatches[0].id, "t1");
  assert.equal("results" in rep, false);
  assert.equal(cli(["replay", join(d, "missing.jsonl"), "--policy", STANDARD]).status, 2);

  const rq = join(d, "r.json");
  writeFileSync(rq, JSON.stringify(T02));
  const sh = cli(["check", "--shadow", rq, "--policy", STANDARD]);   // --shadow must not swallow the filename
  assert.equal(sh.status, 10);
  assert.ok(sh.stdout.includes("Mode: shadow"));
  const env = cli(["check", rq, "--policy", STANDARD, "--json"], { ABE_MODE: "shadow" });
  assert.equal(env.status, 10);
  assert.equal(JSON.parse(env.stdout).mode, "shadow");
  assert.equal(cli(["check", rq, "--policy", STANDARD], { ABE_MODE: "bogus" }).status, 2);
});
