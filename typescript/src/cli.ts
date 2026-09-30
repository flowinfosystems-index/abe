#!/usr/bin/env node
/**
 * abe — Abe CLI (TypeScript). Same commands and exit codes as the Python CLI:
 *   abe init | check <request.json> | validate-policy <file> | validate-record <file> [--public-key pem]
 *   abe conformance [--level 3] [--bench] | serve [--host] [--port] [--token] [--allow-remote] | keygen [--out-dir]
 *   abe replay <cases.jsonl|.json|dir> [--baseline old.yaml] [--fail-on-change] [--json] [--all]
 * Exit codes for check: 0 ACT, 10 BLOCK, 20 ESCALATE (unchanged by --shadow / ABE_MODE=shadow).
 */
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as conformance from "./conformance.js";
import { PolicyError } from "./errors.js";
import * as fjpConf from "./fjpConf.js";
import { Gate, type Mode } from "./gate.js";
import { loadPolicy } from "./policy.js";
import { isValidReasonCode } from "./reasonCodes.js";
import { verifyHash } from "./records.js";
import { formatReport, loadCases, replay, ReplayInputError } from "./replay.js";
import { serve } from "./server.js";
import { Ed25519Signer, generateKeyPair, verifySignature } from "./signing.js";
import { storeFromUri } from "./stores.js";
import { VERSION } from "./version.js";

const EXIT: Record<string, number> = { ACT: 0, BLOCK: 10, ESCALATE: 20 };
const HERE = dirname(fileURLToPath(import.meta.url));

function parse(argv: string[]) {
  const pos: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=", 2);
      if (v !== undefined) flags[k] = v;
      else if (i + 1 < argv.length && !argv[i + 1].startsWith("--") && !["json", "record", "force", "bench", "allow-remote", "shadow", "fail-on-change", "all"].includes(k)) flags[k] = argv[++i];
      else flags[k] = true;
    } else pos.push(a);
  }
  return { pos, flags };
}

const policyPath = (f: Record<string, string | boolean>) => (f.policy as string) || process.env.ABE_POLICY || process.env.FJP_POLICY
  || (!existsSync("abe-policy.yaml") && existsSync("fjp-policy.yaml") ? "fjp-policy.yaml" : "abe-policy.yaml");

function modeOf(f: Record<string, string | boolean>): Mode {
  if (f.shadow) return "shadow";
  const env = (process.env.ABE_MODE || "enforce").trim().toLowerCase();
  if (env !== "enforce" && env !== "shadow") {
    console.error(`ABE_MODE must be enforce or shadow, got '${env}'`);
    process.exit(2);
  }
  return env;
}

function makeGate(f: Record<string, string | boolean>, defaultStore?: string) {
  const key = (f["sign-key"] as string) || (process.env.ABE_SIGNING_KEY || process.env.FJP_SIGNING_KEY);
  const mode = modeOf(f);
  try {
    return new Gate({ policy: policyPath(f), store: storeFromUri((f.store as string) || defaultStore),
      signer: key ? Ed25519Signer.fromFile(key, (f["key-id"] as string) || "local:key:1") : null, mode });
  } catch (e) {
    if (e instanceof PolicyError) {
      console.error(`policy error: ${e.message}`);
      process.exit(2);
    }
    throw e;
  }
}

function readJson(path: string): unknown {
  const raw = path === "-" ? readFileSync(0, "utf8") : readFileSync(path, "utf8");
  if (Buffer.byteLength(raw) > 1_048_576) throw new Error("input exceeds 1 MiB");
  return JSON.parse(raw);
}

export function validateRecord(rec: unknown): string[] {
  if (!rec || typeof rec !== "object" || Array.isArray(rec)) return ["record must be a JSON object"];
  const r = rec as Record<string, unknown>;
  const p = conformance.RECORD_REQUIRED.filter((k) => !(k in r)).map((k) => `missing field ${k}`);
  if (r.protocol !== "FJP") p.push('protocol must be "FJP"');
  if (r.version !== "0.1") p.push('version must be "0.1"');
  if (!["DECISION", "RESOLUTION", "OUTCOME"].includes(r.event_type as string)) p.push("event_type must be DECISION, RESOLUTION or OUTCOME");
  if (!["ACT", "BLOCK", "ESCALATE"].includes(r.decision as string)) p.push("decision must be ACT, BLOCK or ESCALATE");
  if ("reason_code" in r && r.event_type !== "OUTCOME" && !isValidReasonCode(r.reason_code)) p.push(`reason_code ${JSON.stringify(r.reason_code)} is not standard or namespaced`);
  if ("record_hash" in r && !verifyHash(r)) p.push("record_hash does not match the record contents (modified after creation?)");
  for (const c of fjpConf.evaluate(r, 2)) if (!c.passed) p.push(`FJP-CONF ${c.check_id}: ${c.detail}`);
  return p;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  const { pos, flags } = parse(rest);
  switch (cmd) {
    case "--version": case "-v": console.log(`abe-ai ${VERSION}`); return 0;
    case "init": {
      const pOut = (flags["policy-out"] as string) || "abe-policy.yaml", rOut = (flags["request-out"] as string) || "request.json";
      for (const [name, dest] of [["starter.yaml", pOut], ["request.json", rOut]]) {
        if (existsSync(dest) && !flags.force) { console.log(`exists, skipped: ${dest} (use --force to overwrite)`); continue; }
        writeFileSync(dest, readFileSync(join(HERE, "..", "templates", name), "utf8"));
        console.log(`wrote ${dest}`);
      }
      console.log(`\nnext:  npx abe check ${rOut} --policy ${pOut}`);
      return 0;
    }
    case "check": {
      const gate = makeGate(flags);
      let req: unknown = null;
      try { req = readJson(pos[0] ?? "-"); } catch (e) { console.error(`cannot read request: ${(e as Error).message}`); }
      const r = await gate.check(req as never);
      if (flags.json) console.log(JSON.stringify({ ...r.toResponse(), ...(flags.record ? { record: r.record } : {}) }, null, 2));
      else {
        console.log(`Decision: ${r.decision}\nReason: ${r.reasonCode}`);
        if (r.matchedRules.length) console.log(`Rules: ${r.matchedRules.join(", ")}`);
        if (r.missingEvidence.length) console.log(`Missing evidence: ${r.missingEvidence.join(", ")}`);
        console.log(`Risk: ${r.riskLevel}\nRecord: ${r.recordId}`);
        if (!r.enforced) console.log("Mode: shadow (recorded, not enforced)");
        for (const w of r.warnings) console.error(`Warning: ${w}`);
        if (flags.record) console.log(JSON.stringify(r.record, null, 2));
      }
      if (flags["record-out"]) writeFileSync(flags["record-out"] as string, JSON.stringify(r.record, null, 2));
      return EXIT[r.decision];
    }
    case "replay": {
      if (!pos[0]) { console.error("usage: abe replay <cases.jsonl|.json|dir> [--policy p.yaml] [--baseline old.yaml]"); return 2; }
      let rep;
      try {
        rep = await replay(loadCases(pos[0]), policyPath(flags), (flags.baseline as string) || null);
      } catch (e) {
        if (e instanceof PolicyError) { console.error(`policy error: ${e.message}`); return 2; }
        if (e instanceof ReplayInputError || (e as NodeJS.ErrnoException).code) { console.error(`cannot read cases: ${(e as Error).message}`); return 2; }
        throw e;
      }
      if (flags.json) {
        const { results, ...summary } = rep;
        console.log(JSON.stringify(flags.all ? { ...summary, results } : summary, null, 2));
      } else console.log(formatReport(rep));
      if (rep.mismatches.length) return 1;
      if (flags["fail-on-change"] && rep.changed.length) return 1;
      return 0;
    }
    case "validate-policy": {
      try {
        const p = loadPolicy(pos[0]);
        console.log(`VALID  ${pos[0]}\n  policy_id:      ${p.policy_id}\n  policy_version: ${p.policy_version}\n  hash:           ${p.hash}`);
        console.log(`  rules: ${p.rules.length}  evidence requirements: ${p.evidence_requirements.length}  judgment boundaries: ${p.judgment_required.length}  unmatched -> ${p.unmatched_decision}`);
        return 0;
      } catch (e) {
        console.log(`INVALID: ${(e as Error).message}`);
        return 1;
      }
    }
    case "validate-record": {
      let rec: unknown;
      try { rec = readJson(pos[0]); } catch (e) { console.log(`INVALID: cannot read record: ${(e as Error).message}`); return 2; }
      const problems = validateRecord(rec);
      if (flags["public-key"] && rec && typeof rec === "object" && !verifySignature(rec as Record<string, unknown>, readFileSync(flags["public-key"] as string, "utf8")))
        problems.push("signature missing or does not verify with the given public key");
      if (problems.length) { console.log(`INVALID  ${pos[0]}`); for (const p of problems) console.log(`  - ${p}`); return 1; }
      const r = rec as Record<string, unknown>;
      console.log(`VALID  ${pos[0]}  (${r.record_id}, ${r.event_type} ${r.decision}, hash verified${flags["public-key"] ? ", signature verified" : ""}; FJP-CONF v0.1 L0-L2)`);
      return 0;
    }
    case "conformance": {
      const level = flags.level ? Number(flags.level) : 3;
      const checks = await conformance.run((flags.fixtures as string) || conformance.fixturesDir(), level);
      const { ok, text } = conformance.report(checks, level);
      console.log(text);
      if (flags.bench) {
        const b = await conformance.benchmark();
        console.log(`\nperformance: p50 ${b.p50_ms} ms  p95 ${b.p95_ms} ms  (n=${b.n}; targets p50 < 2 ms, p95 < 10 ms)`);
      }
      return ok ? 0 : 1;
    }
    case "serve": {
      const gate = makeGate(flags, "memory:");
      try {
        serve(gate, { host: (flags.host as string) || "127.0.0.1", port: flags.port ? Number(flags.port) : 8787,
          token: (flags.token as string) || (process.env.ABE_TOKEN || process.env.FJP_TOKEN) || null, allowRemote: !!flags["allow-remote"] });
      } catch (e) {
        console.error((e as Error).message);
        return 2;
      }
      return -1; // keep running
    }
    case "keygen": {
      const dir = (flags["out-dir"] as string) || ".";
      const pp = join(dir, "abe-signing-key.pem"), bp = join(dir, "abe-signing-key.pub.pem");
      if (existsSync(pp) && !flags.force) { console.log(`exists: ${pp} (use --force)`); return 1; }
      const { privateKeyPem, publicKeyPem } = generateKeyPair();
      writeFileSync(pp, privateKeyPem, { mode: 0o600 });
      chmodSync(pp, 0o600);
      writeFileSync(bp, publicKeyPem);
      console.log(`wrote ${pp} (private, keep secret; mode 600)\nwrote ${bp} (public, share with auditors)`);
      return 0;
    }
    default:
      console.log(`abe ${VERSION} — Abe: one control point before an AI agent acts.

  abe init                          write abe-policy.yaml + request.json
  abe check request.json            Decision / Reason / Record  (exit 0 ACT, 10 BLOCK, 20 ESCALATE)
  abe replay cases.jsonl [--baseline old.yaml] [--fail-on-change]   test a policy on saved requests
  abe validate-policy abe-policy.yaml
  abe validate-record jgr.json [--public-key pub.pem]
  abe conformance [--level 3] [--bench]
  abe serve [--host 127.0.0.1] [--port 8787] [--token T] [--allow-remote]
  abe keygen [--out-dir .]

Options: --policy (default $ABE_POLICY or ./abe-policy.yaml), --store memory:|file:records.jsonl, --sign-key key.pem, --json, --record, --record-out f.json,
         --shadow (or ABE_MODE=shadow): records marked shadow, not enforced; decisions and exit codes unchanged`);
      return cmd ? 2 : 0;
  }
}

main(process.argv.slice(2)).then((code) => { if (code >= 0) process.exitCode = code; }, (e) => { console.error(e); process.exitCode = 1; });
