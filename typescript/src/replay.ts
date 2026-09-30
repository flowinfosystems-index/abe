/**
 * Replay saved requests through a policy: test rule changes before an agent touches real money.
 *
 *   abe replay cases.jsonl --policy new.yaml --baseline current.yaml
 *
 * A case is a request object, or {"id": ..., "request": {...}, "expected": "ACT|BLOCK|ESCALATE"}.
 * `expected` is what your people decided (or should decide); a case whose decision differs is a mismatch.
 * Input: a .jsonl file (one case per line), a .json file (one case or an array), or a directory of those.
 * Nothing is stored, signed, or sent anywhere. Same behavior and JSON report as the Python SDK.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import { Gate } from "./gate.js";
import type { Policy } from "./policy.js";

export const MAX_CASES = 100_000;
const MAX_FILE_BYTES = 64 * 1_048_576;
const DECISIONS = ["ACT", "BLOCK", "ESCALATE"] as const;
type Decision = (typeof DECISIONS)[number];

export class ReplayInputError extends Error {
  constructor(message: string) { super(message); this.name = "ReplayInputError"; }
}

export interface ReplayCase { id: string; request: Record<string, unknown>; expected: Decision | null }

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function readCases(path: string): [string, unknown][] {
  if (statSync(path).size > MAX_FILE_BYTES) throw new ReplayInputError(`${path}: larger than 64 MiB`);
  const name = basename(path);
  const text = readFileSync(path, "utf8");
  if (path.endsWith(".jsonl")) {
    const out: [string, unknown][] = [];
    text.split("\n").forEach((line, i) => {
      if (!line.trim()) return;
      try { out.push([`${name}:${i + 1}`, JSON.parse(line)]); }
      catch (e) { throw new ReplayInputError(`${name}:${i + 1}: invalid JSON (${(e as Error).message})`); }
    });
    return out;
  }
  let data: unknown;
  try { data = JSON.parse(text); } catch (e) { throw new ReplayInputError(`${name}: invalid JSON (${(e as Error).message})`); }
  return Array.isArray(data) ? data.map((x, i) => [`${name}[${i}]`, x] as [string, unknown]) : [[name, data]];
}

export function loadCases(path: string): ReplayCase[] {
  let raw: [string, unknown][];
  if (statSync(path).isDirectory()) {
    const files = readdirSync(path).filter((f) => f.endsWith(".json") || f.endsWith(".jsonl")).sort().map((f) => join(path, f));
    if (!files.length) throw new ReplayInputError(`${path}: no .json or .jsonl files`);
    raw = files.flatMap(readCases);
  } else raw = readCases(path);
  if (raw.length > MAX_CASES) throw new ReplayInputError(`more than ${MAX_CASES} cases`);
  const cases: ReplayCase[] = [];
  const seen = new Set<string>();
  for (const [where, item] of raw) {
    if (!isObj(item)) throw new ReplayInputError(`${where}: a case must be a JSON object`);
    const wrapped = isObj(item.request) && !("action" in item);
    const req = (wrapped ? item.request : item) as Record<string, unknown>;
    const expected = wrapped ? (item.expected ?? null) : null;
    if (expected !== null && !(DECISIONS as readonly unknown[]).includes(expected))
      throw new ReplayInputError(`${where}: expected must be one of ${JSON.stringify(DECISIONS)}`);
    let id = String((wrapped ? item.id : null) || req.request_id || where);
    if (seen.has(id)) id = `${id} (${where})`;
    seen.add(id);
    cases.push({ id, request: req, expected: expected as Decision | null });
  }
  return cases;
}

export async function replay(cases: ReplayCase[], policy: string | Policy | Record<string, unknown>,
  baseline?: string | Policy | Record<string, unknown> | null) {
  const gate = new Gate({ policy });
  const base = baseline ? new Gate({ policy: baseline }) : null;
  const counts: Record<Decision, number> = { ACT: 0, BLOCK: 0, ESCALATE: 0 };
  const results: Record<string, unknown>[] = [], changed: Record<string, unknown>[] = [], mismatches: Record<string, unknown>[] = [];
  for (const c of cases) {
    const r = await gate.check(c.request);
    counts[r.decision as Decision] += 1;
    const row: Record<string, unknown> = { id: c.id, decision: r.decision, reason_code: r.reasonCode, matched_rules: [...r.matchedRules] };
    if (base) {
      const b = await base.check(c.request);
      row.baseline_decision = b.decision;
      if (b.decision !== r.decision) changed.push({ id: c.id, from: b.decision, to: r.decision, matched_rules: [...r.matchedRules] });
    }
    if (c.expected !== null && c.expected !== undefined) {
      row.expected = c.expected;
      if (c.expected !== r.decision) mismatches.push({ id: c.id, expected: c.expected, decision: r.decision, matched_rules: [...r.matchedRules] });
    }
    results.push(row);
  }
  const expectedN = cases.filter((c) => c.expected !== null && c.expected !== undefined).length;
  return {
    cases: cases.length,
    policy: gate.policy.describe(),
    baseline_policy: base ? base.policy.describe() : null,
    decisions: counts,
    changed,
    expected_cases: expectedN,
    mismatches,
    agreement: expectedN ? Math.round(((expectedN - mismatches.length) / expectedN) * 10_000) / 10_000 : null,
    results,
  };
}

export type ReplayReport = Awaited<ReturnType<typeof replay>>;

export function formatReport(rep: ReplayReport, limit = 50): string {
  const d = rep.decisions;
  const pol = rep.policy as Record<string, unknown>;
  const label = [pol.id, pol.version].filter((x) => x).map(String).join(" ") || "policy";
  const lines = [`Replayed ${rep.cases} case(s) against ${label} (${String(pol.hash).slice(0, 19)})`,
    `  ACT ${d.ACT}   BLOCK ${d.BLOCK}   ESCALATE ${d.ESCALATE}`];
  const rules = (m: Record<string, unknown>) => (m.matched_rules as string[]).join(", ") || "no rule";
  if (rep.baseline_policy) {
    lines.push(`Changed vs baseline (${String((rep.baseline_policy as Record<string, unknown>).hash).slice(0, 19)}): ${rep.changed.length}`);
    for (const c of rep.changed.slice(0, limit)) lines.push(`  ${c.id}: ${c.from} -> ${c.to}  [${rules(c)}]`);
  }
  if (rep.expected_cases) {
    lines.push(`Agreement with expected: ${rep.expected_cases - rep.mismatches.length}/${rep.expected_cases} (${((rep.agreement ?? 0) * 100).toFixed(1)}%)`);
    for (const m of rep.mismatches.slice(0, limit)) lines.push(`  ${m.id}: expected ${m.expected}, got ${m.decision}  [${rules(m)}]`);
  }
  const shown = Math.max(rep.changed.length, rep.mismatches.length);
  if (shown > limit) lines.push(`  ... ${shown - limit} more (use --json for all)`);
  return lines.join("\n");
}
