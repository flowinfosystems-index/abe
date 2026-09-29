/** FJP-CONF v0.1 Gate profile (same fixtures and levels as the Python SDK). */
import { readFileSync } from "node:fs";
import dns from "node:dns";
import net from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalJson, hashValue } from "./canonical.js";
import { RecordImmutableError } from "./errors.js";
import * as fjpConf from "./fjpConf.js";
import { Gate, type GateResult } from "./gate.js";
import { isValidReasonCode } from "./reasonCodes.js";
import { type JGR, computeRecordHash, verifyHash } from "./records.js";
import { MemoryStore } from "./stores.js";

export interface Check { level: number; check_id: string; passed: boolean; detail: string }

export function fixturesDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures");
}

export class GateAdapter implements fjpConf.L3Adapter {
  constructor(private gate: Gate) {
    if (!gate.store) throw new Error("L3 needs a Gate configured with a store");
  }
  async getRecord(id: string) {
    const rec = JSON.parse(canonicalJson(await this.gate.getRecord(id)));
    rec.falsifier.status = await this.gate.evaluateFalsifier(id);
    return rec;
  }
  evaluateFalsifier(id: string) {
    return this.gate.evaluateFalsifier(id);
  }
}

/** Blocks outbound connections (net, dns, fetch) while fn runs; returns the attempt count. */
export async function withNoNetwork<T>(fn: () => Promise<T>): Promise<{ value: T; attempts: number }> {
  let attempts = 0;
  const deny = () => { attempts++; throw new Error("network access attempted during Abe evaluation"); };
  const origConnect = net.Socket.prototype.connect, origLookup = dns.lookup, origFetch = globalThis.fetch;
  net.Socket.prototype.connect = deny as never;
  (dns as { lookup: unknown }).lookup = deny;
  globalThis.fetch = (async () => deny()) as never;
  try {
    return { value: await fn(), attempts };
  } finally {
    net.Socket.prototype.connect = origConnect;
    (dns as { lookup: unknown }).lookup = origLookup;
    globalThis.fetch = origFetch;
  }
}

const RESPONSE_REQUIRED = ["protocol", "version", "decision", "reason_code", "risk_level", "record_id", "timestamp"];
export const RECORD_REQUIRED = ["protocol", "version", "record_id", "request_id", "timestamp", "event_type", "actor", "action",
  "decision", "reason_code", "policy", "resolver", "record_hash", "signal", "judgment", "falsifier"];

export async function run(fixturesBase = fixturesDir(), level = 3): Promise<Check[]> {
  const out: Check[] = [];
  const add = (lvl: number, id: string, ok: unknown, detail = "") => out.push({ level: lvl, check_id: id, passed: !!ok, detail });
  const fx = JSON.parse(readFileSync(join(fixturesBase, "decisions.json"), "utf8"));
  const canon = JSON.parse(readFileSync(join(fixturesBase, "canonical.json"), "utf8"));

  const { attempts } = await withNoNetwork(async () => {
    const store = new MemoryStore();
    const gate = new Gate({ policy: join(fixturesBase, fx.policy), store });
    const results: Record<string, GateResult> = {};
    for (const c of fx.cases) results[c.id] = await gate.check(c.request);

    for (const [cid, r] of Object.entries(results)) {
      const resp = r.toResponse();
      const ok = RESPONSE_REQUIRED.every((k) => k in resp) && resp.protocol === "FJP" && resp.version === "0.1"
        && ["ACT", "BLOCK", "ESCALATE"].includes(resp.decision as string) && isValidReasonCode(resp.reason_code);
      add(0, `L0.response.${cid}`, ok, ok ? "" : `invalid response ${JSON.stringify(resp)}`);
    }
    if (fx.expected_policy_hash)
      add(0, "L0.policy_hash.cross_language", gate.policy.hash === fx.expected_policy_hash, `${gate.policy.hash} != ${fx.expected_policy_hash}`);
    for (const [i, v] of canon.vectors.entries()) {
      let got = "", h = "";
      try { got = canonicalJson(v.value); h = hashValue(v.value); } catch (e) { got = String(e); }
      add(0, `L0.canonical_json.vector_${i}`, got === v.canonical && h === v.hash, `${got} != ${v.canonical}`);
    }

    if (level >= 1) {
      for (const c of fx.cases) {
        const r = results[c.id], e = c.expect, problems: string[] = [];
        if (r.decision !== e.decision) problems.push(`decision ${r.decision} != ${e.decision}`);
        if (r.reasonCode !== e.reason_code) problems.push(`reason_code ${r.reasonCode} != ${e.reason_code}`);
        if (e.matched_rules && JSON.stringify(r.matchedRules) !== JSON.stringify(e.matched_rules))
          problems.push(`matched_rules ${JSON.stringify(r.matchedRules)} != ${JSON.stringify(e.matched_rules)}`);
        if (e.missing_evidence && JSON.stringify(r.missingEvidence) !== JSON.stringify(e.missing_evidence))
          problems.push(`missing_evidence ${JSON.stringify(r.missingEvidence)} != ${JSON.stringify(e.missing_evidence)}`);
        if (e.risk_level && r.riskLevel !== e.risk_level) problems.push(`risk_level ${r.riskLevel} != ${e.risk_level}`);
        if (e.time_source && r.record.time_source !== e.time_source) problems.push(`time_source ${r.record.time_source} != ${e.time_source}`);
        add(1, `L1.${c.id}`, !problems.length, problems.join("; "));
      }
      add(1, "L1.fail_closed.never_act", fx.cases.filter((c: { expect: { reason_code: string } }) => c.expect.reason_code === "EVALUATION_FAILURE")
        .every((c: { id: string }) => results[c.id].decision !== "ACT"), "an evaluation failure produced ACT");
    }

    if (level >= 2) {
      for (const [cid, r] of Object.entries(results)) {
        const rec = r.record as Record<string, unknown>;
        const failed = fjpConf.evaluate(rec, 2).filter((x) => !x.passed).map((x) => x.check_id);
        add(2, `L2.fjp_conf.${cid}`, !failed.length, `FJP-CONF failures: ${failed}`);
        const missing = RECORD_REQUIRED.filter((k) => !(k in rec));
        add(2, `L2.gate_fields.${cid}`, !missing.length && String((rec.policy as JGR).hash).startsWith("sha256:")
          && String(rec.request_hash).startsWith("sha256:"), `missing ${missing}`);
      }
    }

    if (level >= 3) {
      for (const [cid, r] of Object.entries(results)) add(3, `L3.hash.${cid}`, verifyHash(r.record), "record_hash does not verify");
      const sample = results["T08_definition_of_done"].record;
      const tampered = { ...JSON.parse(canonicalJson(sample)), decision: "ACT" };
      add(3, "L3.hash.detects_tampering", computeRecordHash(tampered) !== tampered.record_hash);
      try {
        (sample as Record<string, unknown>).decision = "ACT";
        add(3, "L3.immutability", false, "record property was assignable");
      } catch (e) {
        add(3, "L3.immutability", e instanceof TypeError);
      }
      try {
        store.save(sample);
        add(3, "L3.store.append_only", false, "store accepted a duplicate record_id");
      } catch (e) {
        add(3, "L3.store.append_only", e instanceof RecordImmutableError);
      }
      const req = fx.cases.find((c: { id: string }) => c.id === "T01_explicit_act").request;
      const content = (rec: JGR) => {
        const keep = ["protocol", "version", "event_type", "decision", "reason_code", "reason_codes", "matched_rules", "risk",
          "irreversibility", "evidence_present", "evidence_missing", "confidence", "policy", "request_hash", "actor", "time_source", "resolver"];
        return canonicalJson(Object.fromEntries(keep.filter((k) => k in rec).map((k) => [k, rec[k]])));
      };
      add(3, "L3.reproducible", content((await gate.check(req)).record) === content((await gate.check(req)).record), "evaluation content differs");
      const adapter = new GateAdapter(gate);
      const act = results["T01_explicit_act"], blk = results["T02_explicit_block_vendor"], esc = results["T03_financial_escalation"];
      add(3, "L3.falsifier.open_initially", (await adapter.evaluateFalsifier(act.recordId)) === "open");
      const o = await gate.recordOutcome(act.record, "executed", { request_hash: act.record.request_hash });
      add(3, "L3.outcome.linked", o.parent_record_id === act.recordId && o.root_record_id === act.recordId && o.event_type === "OUTCOME");
      add(3, "L3.outcome.original_unchanged", canonicalJson(store.get(act.recordId)) === canonicalJson(act.record));
      add(3, "L3.falsifier.act_executed_as_evaluated", (await adapter.evaluateFalsifier(act.recordId)) === "expired");
      await gate.recordOutcome(blk.record, "executed");
      add(3, "L3.falsifier.block_ignored_triggers", (await adapter.evaluateFalsifier(blk.recordId)) === "triggered");
      await gate.recordOutcome(esc.record, "executed");
      add(3, "L3.falsifier.escalate_bypassed_triggers", (await adapter.evaluateFalsifier(esc.recordId)) === "triggered");
      for (const rid of [act.recordId, blk.recordId, esc.recordId, o.record_id]) {
        const failed = (await fjpConf.checkL3(adapter, rid)).filter((x) => !x.passed).map((x) => x.check_id);
        add(3, `L3.fjp_conf.${rid}`, !failed.length, `FJP-CONF L3 failures: ${failed}`);
      }
      add(3, "L3.policy_hash_in_every_record", Object.values(results).every((r) => r.record.policy.hash === gate.policy.hash));
      add(3, "L3.hash_of_policy_is_canonical", gate.policy.hash === hashValue(gate.policy.raw));
    }
  });
  add(level >= 3 ? 3 : 0, "L3.no_network", attempts === 0, `${attempts} network attempt(s)`);
  return out.filter((c) => c.level <= level);
}

export function report(checks: Check[], level: number): { ok: boolean; text: string } {
  const lines = [`FJP-CONF v0.1 — Gate profile (TypeScript) — target Level ${level}`, ""];
  for (const c of checks) {
    lines.push(`  [${c.passed ? "PASS" : "FAIL"}] L${c.level}  ${c.check_id}`);
    if (!c.passed && c.detail) lines.push(`         -> ${c.detail}`);
  }
  const ok = checks.every((c) => c.passed);
  lines.push("", `${checks.filter((c) => c.passed).length}/${checks.length} checks passed`,
    `RESULT: ${ok ? "conforms to" : "does NOT conform to"} FJP-CONF v0.1 Gate profile, Level ${level}`);
  return { ok, text: lines.join("\n") };
}

export async function benchmark(n = 2000, fixturesBase = fixturesDir()) {
  const fx = JSON.parse(readFileSync(join(fixturesBase, "decisions.json"), "utf8"));
  const gate = new Gate({ policy: join(fixturesBase, fx.policy) });
  const reqs = fx.cases.map((c: { request: unknown }) => c.request);
  for (const r of reqs) await gate.check(r);
  const t: number[] = [];
  for (let i = 0; i < n; i++) {
    const s = performance.now();
    await gate.check(reqs[i % reqs.length]);
    t.push(performance.now() - s);
  }
  t.sort((a, b) => a - b);
  return { n, p50_ms: +t[Math.floor(n / 2)].toFixed(3), p95_ms: +t[Math.floor(n * 0.95) - 1].toFixed(3), max_ms: +t[n - 1].toFixed(3) };
}
