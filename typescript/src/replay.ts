/**
 * Replay saved requests through a policy: test rule changes before an agent touches real money.
 *
 *   abe replay cases.jsonl --policy new.yaml --baseline current.yaml
 *
 * A case is a request object, or {"id": ..., "request": {...}, "expected": "ACT|BLOCK|ESCALATE"}.
 * `expected` is what your people decided (or should decide); a case whose decision differs is a mismatch.
 * Input: a .jsonl file (one case per line), a .json file (one case or an array), or a directory of those.
 * Raw agent logs work too (OpenAI, Anthropic, LangChain, Claude Code hook events, {"tool", "args"} lines): each tool
 * call becomes a request whose action fields are the call's arguments and whose action.type is the tool name, or the
 * type mapped with actionTypes. Other log lines are skipped. See the Python module for the full list of shapes.
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

const SKIP = Symbol("skip");
type Call = [unknown, Record<string, unknown>, unknown];

function toolArgs(raw: unknown, where: string): Record<string, unknown> {
  if (raw === undefined || raw === null || raw === "") return {};
  if (typeof raw === "string") {
    try { raw = JSON.parse(raw); } catch (e) { throw new ReplayInputError(`${where}: tool arguments are not valid JSON (${(e as Error).message})`); }
  }
  if (!isObj(raw)) throw new ReplayInputError(`${where}: tool arguments must be a JSON object`);
  return raw;
}

/** Same mapping as the Python integrations: arguments become action fields; action.type is the tool name or its mapped type. */
export function toolToAction(name: string, input: Record<string, unknown>, actionTypes?: Record<string, string> | null) {
  const action: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input)) {
    if (k === "directive" || k === "judgment_ref" || k === "tool" || k === "input_type") continue;
    action[k === "type" ? "input_type" : k] = v;
  }
  action.type = (actionTypes && Object.prototype.hasOwnProperty.call(actionTypes, name)) ? actionTypes[name] : name;
  action.tool = name;
  return action;
}

function toolCalls(item: Record<string, unknown>, where: string): Call[] | typeof SKIP | null {
  if ("action" in item || isObj(item.request)) return null;
  const out: Call[] = [];
  if (Array.isArray(item.tool_calls)) {
    for (const tc of item.tool_calls) {
      if (!isObj(tc)) continue;
      if (isObj(tc.function)) out.push([tc.function.name, toolArgs(tc.function.arguments, where), tc.id]);
      else if ("name" in tc) out.push([tc.name, toolArgs(tc.args !== undefined ? tc.args : tc.arguments, where), tc.id]);
    }
    return out.length ? out : SKIP;
  }
  const t = item.type;
  if (t === "function_call") return [[item.name, toolArgs(item.arguments, where), item.call_id || item.id]];
  if (t === "tool_use") return [[item.name, toolArgs(item.input, where), item.id]];
  if ("role" in item) {
    if (Array.isArray(item.content))
      for (const b of item.content) if (isObj(b) && b.type === "tool_use") out.push([b.name, toolArgs(b.input, where), b.id]);
    return out.length ? out : SKIP;
  }
  if ("tool_name" in item) return [[item.tool_name, toolArgs(item.tool_input, where), item.tool_use_id]];
  if (typeof item.tool === "string") {
    const k = ["args", "arguments", "input", "parameters"].find((x) => x in item);
    return [[item.tool, toolArgs(k ? item[k] : undefined, where), item.id || item.call_id]];
  }
  if (["message", "function_call_output", "tool_result", "text", "reasoning"].includes(t as string)) return SKIP;
  return null;
}

export function loadCases(path: string, actionTypes?: Record<string, string> | null, agentId = "replay"): ReplayCase[] {
  let raw: [string, unknown][];
  if (statSync(path).isDirectory()) {
    const files = readdirSync(path).filter((f) => f.endsWith(".json") || f.endsWith(".jsonl")).sort().map((f) => join(path, f));
    if (!files.length) throw new ReplayInputError(`${path}: no .json or .jsonl files`);
    raw = files.flatMap(readCases);
  } else raw = readCases(path);
  raw = raw.flatMap(([where, item]) => (isObj(item) && Array.isArray(item.messages) && !("action" in item))
    ? (item.messages as unknown[]).map((m, i) => [`${where}.messages[${i}]`, m] as [string, unknown])
    : [[where, item] as [string, unknown]]);
  const expanded: [string, unknown][] = [];
  for (const [where, item] of raw) {
    const calls = isObj(item) ? toolCalls(item, where) : null;
    if (calls === SKIP) continue;
    if (calls === null) { expanded.push([where, item]); continue; }
    calls.forEach(([name, args, callId], n) => {
      if (typeof name !== "string" || !name) throw new ReplayInputError(`${where}: tool call has no name`);
      const ctx: Record<string, unknown> = { agent_id: agentId, framework: "replay" };
      if (typeof callId === "string" && callId) ctx.tool_use_id = callId;
      const id = typeof callId === "string" && callId ? callId : (calls.length === 1 ? where : `${where}#${n}`);
      expanded.push([where, { id, request: { action: toolToAction(name, args, actionTypes), context: ctx } }]);
    });
  }
  raw = expanded;
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

const round2 = (x: number) => Math.round(x * 100) / 100;
const money = (x: number) => "$" + (Number.isInteger(x)
  ? x.toLocaleString("en-US") : x.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }));

export async function replay(cases: ReplayCase[], policy: string | Policy | Record<string, unknown>,
  baseline?: string | Policy | Record<string, unknown> | null) {
  const gate = new Gate({ policy });
  const base = baseline ? new Gate({ policy: baseline }) : null;
  const counts: Record<Decision, number> = { ACT: 0, BLOCK: 0, ESCALATE: 0 };
  const results: Record<string, unknown>[] = [], changed: Record<string, unknown>[] = [], mismatches: Record<string, unknown>[] = [];
  const stopped: Record<string, unknown>[] = [];
  const exposure = { BLOCK: 0, ESCALATE: 0 };
  const reasons: Record<string, number> = {};
  for (const c of cases) {
    const r = await gate.check(c.request);
    counts[r.decision as Decision] += 1;
    const row: Record<string, unknown> = { id: c.id, decision: r.decision, reason_code: r.reasonCode, matched_rules: [...r.matchedRules] };
    const action = isObj(c.request) ? c.request.action : undefined;
    if (isObj(action)) {
      if (typeof action.type === "string") row.action_type = action.type;
      const amt = action.amount;
      if (typeof amt === "number" && Number.isFinite(amt)) {
        row.amount = amt;
        if (r.decision === "BLOCK" || r.decision === "ESCALATE") exposure[r.decision] += amt;
      }
    }
    reasons[r.reasonCode] = (reasons[r.reasonCode] || 0) + 1;
    if (r.decision !== "ACT") stopped.push(row);
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
    stopped,
    exposure: { BLOCK: round2(exposure.BLOCK), ESCALATE: round2(exposure.ESCALATE) },
    reasons: Object.fromEntries(Object.entries(reasons).sort((a, b) => b[1] - a[1])),
    results,
  };
}

export type ReplayReport = Awaited<ReturnType<typeof replay>>;

export function formatReport(rep: ReplayReport, limit = 50, stopLimit = 20): string {
  const d = rep.decisions;
  const pol = rep.policy as Record<string, unknown>;
  const label = [pol.id, pol.version].filter((x) => x).map(String).join(" ") || "policy";
  const lines = [`Replayed ${rep.cases} case(s) against ${label} (${String(pol.hash).slice(0, 19)})`,
    `  ACT ${d.ACT}   BLOCK ${d.BLOCK}   ESCALATE ${d.ESCALATE}`];
  const rules = (m: Record<string, unknown>) => (m.matched_rules as string[]).join(", ") || "no rule";
  const ex = rep.exposure;
  if (ex.BLOCK || ex.ESCALATE)
    lines.push(`  Amounts held back: ${money(ex.BLOCK)} blocked, ${money(ex.ESCALATE)} escalated (sum of action.amount)`);
  if (rep.stopped.length) {
    lines.push(`Would have stopped: ${rep.stopped.length}`);
    for (const row of rep.stopped.slice(0, stopLimit)) {
      let what = (row.action_type as string) || "?";
      if (typeof row.amount === "number") what += ` ${money(row.amount)}`;
      lines.push(`  ${row.id}: ${row.decision} ${what}  ${row.reason_code}  [${(row.matched_rules as string[]).join(", ") || "no rule matched"}]`);
    }
    if (rep.stopped.length > stopLimit) lines.push(`  ... ${rep.stopped.length - stopLimit} more (use --json --all for every case)`);
    const unmatched = rep.stopped.filter((row) => !(row.matched_rules as string[]).length).length;
    if (unmatched) lines.push(`  ${unmatched} escalated only because no rule matched them: add rules for those tools, or map them with --action-type TOOL=TYPE`);
  }
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
