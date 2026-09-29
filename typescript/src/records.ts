/**
 * Judgment-Grounded Records: construction, integrity hash, falsifier re-evaluation.
 * Byte-compatible with the Python SDK (same fields, same canonical hash, same control falsifiers).
 */
import { randomBytes } from "node:crypto";
import { deepFreeze, hashValue } from "./canonical.js";
import type { Policy } from "./policy.js";
import { VERSION } from "./version.js";

export const PROTOCOL = "FJP";
export const PROTOCOL_VERSION = "0.1";
export const FJP_CONF_VERSION = "0.1.0";
export const IMPLEMENTATION = "abe-typescript";
export const OUTCOME_STATUSES = ["executed", "failed", "reverted", "cancelled", "approved", "rejected"] as const;
export type OutcomeStatus = (typeof OUTCOME_STATUSES)[number];

/** A Judgment-Grounded Record. Deep-frozen: any mutation throws a TypeError. */
export type JGR = Readonly<Record<string, any>>; // eslint-disable-line @typescript-eslint/no-explicit-any

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export function ulid(ms = Date.now()): string {
  let value = (BigInt(ms) << 80n) | BigInt("0x" + randomBytes(10).toString("hex"));
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = ALPHABET[Number(value & 31n)] + out;
    value >>= 5n;
  }
  return out;
}
export const newId = (prefix: string) => `${prefix}_${ulid()}`;

export const iso = (d: Date) => d.toISOString();

const ISO = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2})$/;

/** Strict RFC 3339 date-time with offset, years 1970-9999 (same grammar as the Python SDK). Throws RangeError. */
export function parseIso(s: string): Date {
  const m = typeof s === "string" ? ISO.exec(s.trim()) : null;
  if (!m) throw new RangeError(`not an RFC 3339 date-time with offset: ${JSON.stringify(s)}`);
  const [, y, mo, d, h, mi, sec, frac, off] = m;
  const Y = +y, M = +mo, D = +d, H = +h, MI = +mi, S = sec ? +sec : 0;
  if (Y < 1970 || Y > 9999) throw new RangeError("year must be between 1970 and 9999");
  const dim = new Date(Date.UTC(Y, M, 0)).getUTCDate();
  if (M < 1 || M > 12 || D < 1 || D > dim || H > 23 || MI > 59 || S > 59) throw new RangeError("date-time out of range");
  const ms = +(frac ?? "0").slice(0, 3).padEnd(3, "0");
  let offsetMin = 0;
  if (off !== "Z") {
    offsetMin = (off[0] === "+" ? 1 : -1) * (+off.slice(1, 3) * 60 + +off.slice(4, 6));
    if (Math.abs(offsetMin) >= 24 * 60) throw new RangeError("offset must be less than 24 hours");
  }
  return new Date(Date.UTC(Y, M - 1, D, H, MI, S, ms) - offsetMin * 60_000);
}

function hashableView(rec: Record<string, unknown>): Record<string, unknown> {
  const d: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rec)) if (k !== "record_hash" && k !== "signature") d[k] = v;
  const f = d.falsifier;
  if (f && typeof f === "object") {
    const ff: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(f)) if (k !== "status") ff[k] = v;
    d.falsifier = ff;
  }
  return d;
}

export function computeRecordHash(rec: Record<string, unknown>): string {
  return hashValue(hashableView(rec));
}

export function verifyHash(rec: Record<string, unknown>): boolean {
  try {
    return typeof rec.record_hash === "string" && rec.record_hash === computeRecordHash(rec);
  } catch {
    return false;
  }
}

export interface Signer {
  keyId: string;
  sign(recordHash: string): { algorithm: "ed25519"; key_id: string; value: string };
}

function finalize(rec: Record<string, unknown>, signer?: Signer | null): JGR {
  rec.record_hash = computeRecordHash(rec);
  if (signer) rec.signature = signer.sign(rec.record_hash as string);
  return deepFreeze(rec);
}

function base(o: { recordId: string; requestId: string; rootId: string; parentId: string | null; eventType: string;
  now: Date; horizonDays: number; policy: unknown; actor: unknown }): [Record<string, unknown>, string] {
  const expires = iso(new Date(o.now.getTime() + o.horizonDays * 86_400_000));
  return [{
    protocol: PROTOCOL, version: PROTOCOL_VERSION, fjp_conf_version: FJP_CONF_VERSION, implementation_version: VERSION,
    producer: "abe", record_id: o.recordId, request_id: o.requestId, root_record_id: o.rootId,
    parent_record_id: o.parentId, event_type: o.eventType, timestamp: iso(o.now), expires_at: expires,
    actor: o.actor, policy: o.policy,
  }, expires];
}

function actionSummary(action: Record<string, unknown>): string {
  const parts = [String(action.type ?? "action")];
  for (const k of ["amount", "total_price", "currency", "target", "destination"]) {
    const v = action[k];
    if (k in action && (typeof v === "string" || typeof v === "number")) parts.push(`${k}=${pyStr(v)}`);
  }
  return parts.join(" ").slice(0, 300);
}

/** Display form of a scalar in the human-readable signal description. */
function pyStr(v: string | number): string {
  return typeof v === "string" ? v : JSON.stringify(v);
}

export interface Finding { id: string; source: string; decision: string; reason_code: string; description?: string }

export function buildDecisionRecord(o: {
  recordId: string; requestId: string; now: Date; evalTime: Date; timeSource: "request" | "system";
  req: Record<string, any>; requestHash: string; policy: Policy | null; decision: string; reasonCode: string; // eslint-disable-line @typescript-eslint/no-explicit-any
  reasonCodes: string[]; matched: Finding[]; risk: unknown; irr: unknown; evidencePresent: string[];
  evidenceMissing: string[]; confidence: unknown; failureDetail?: string | null; signer?: Signer | null;
}): JGR {
  const actor = o.req.actor ?? {};
  const pol = o.policy ? o.policy.describe() : { id: null, version: null, hash: null, format_version: PROTOCOL_VERSION };
  const [rec, expires] = base({ recordId: o.recordId, requestId: o.requestId, rootId: o.recordId, parentId: null,
    eventType: "DECISION", now: o.now, horizonDays: o.policy ? o.policy.falsifier_horizon_days : 30, policy: pol, actor });
  const actionIn: Record<string, unknown> = o.req.action && typeof o.req.action === "object" ? o.req.action : {};
  const atype = actionIn.type ?? "action";
  const agent = actor.agent_id || "agent";
  const sigId = `sig-${o.recordId}`, judId = `jud-${o.recordId}`;
  const ruleDesc = o.matched.map((m) => `${m.id} -> ${m.decision} (${m.reason_code})`).join("; ") || "no rule matched";
  let assessment = `${o.decision} / ${o.reasonCode}. Deterministic policy evaluation: ${ruleDesc}.`;
  if (o.evidenceMissing.length) assessment += ` Missing evidence: ${o.evidenceMissing.join(", ")}.`;
  if (o.failureDetail) assessment += ` Evaluation failure: ${o.failureDetail}.`;
  assessment += " This is a policy result, not an independent judgment that the action is optimal.";

  let directive: string, condition: string;
  if (o.decision === "ACT") {
    directive = `ACT: ${agent} may execute ${atype} as evaluated.`;
    condition = `An OUTCOME record linked to ${o.recordId} reports status failed or reverted, or reports an executed request_hash other than ${o.requestHash}, before ${expires}.`;
  } else if (o.decision === "BLOCK") {
    directive = `BLOCK: ${agent} must not execute ${atype}.`;
    condition = `An OUTCOME record linked to ${o.recordId} reports status executed (the action ran despite BLOCK) before ${expires}.`;
  } else {
    directive = `ESCALATE: ${agent} must hold ${atype} until the configured escalation path resolves it.`;
    condition = `An OUTCOME record linked to ${o.recordId} reports status executed before a RESOLUTION record with decision ACT is linked, before ${expires}.`;
  }
  Object.assign(rec, {
    evaluation_time: iso(o.evalTime), time_source: o.timeSource, request_hash: o.requestHash,
    action: { ...actionIn, directive, judgment_ref: judId },
    decision: o.decision, reason_code: o.reasonCode, reason_codes: [...o.reasonCodes],
    matched_rules: o.matched.map((m) => m.id), rule_results: o.matched.map((m) => ({ ...m })),
    risk: o.risk, irreversibility: o.irr, evidence_present: [...o.evidencePresent],
    evidence_missing: [...o.evidenceMissing], confidence: o.confidence,
    resolver: { type: "FJP_GATE", implementation: IMPLEMENTATION, version: VERSION },
    signal: { id: sigId, description: `${agent} proposed ${actionSummary(actionIn)} (request ${o.requestId}).`,
      sources: [`fjp:agent:${agent}`, `fjp:request:${o.requestId}`, `fjp:policy:${pol.hash}`], observed_at: iso(o.evalTime) },
    judgment: { id: judId, assessment, confidence: o.reasonCode === "EVALUATION_FAILURE" ? 0 : 1,
      basis: "deterministic_policy", signal_ref: sigId },
    falsifier: { condition, checkable: true, status: "open" },
  });
  if (o.failureDetail) rec.evaluation_error = String(o.failureDetail).slice(0, 500);
  return finalize(rec, o.signer);
}

export interface Resolution {
  decision: "ACT" | "BLOCK" | "ESCALATE";
  reason: string;
  reasonCode?: string | null;
  confidence?: number | null;
  falsifiers?: string[];
  resolverType?: string;
  implementation?: string;
  implementationVersion?: string;
  reference?: string | null;
  evidence?: Record<string, unknown>;
  externalRecord?: Record<string, unknown> | null;
}

export function buildResolutionRecord(o: { recordId: string; parent: JGR; now: Date; resolution: Resolution | null;
  finalDecision: "ACT" | "BLOCK" | "ESCALATE"; horizonDays: number; status: string; error?: string | null; signer?: Signer | null }): JGR {
  const p = o.parent;
  const [rec, expires] = base({ recordId: o.recordId, requestId: p.request_id, rootId: p.root_record_id, parentId: p.record_id,
    eventType: "RESOLUTION", now: o.now, horizonDays: o.horizonDays, policy: { ...p.policy }, actor: { ...p.actor } });
  const sigId = `sig-${o.recordId}`, judId = `jud-${o.recordId}`;
  const { directive: _d, judgment_ref: _j, ...pa } = p.action; // eslint-disable-line @typescript-eslint/no-unused-vars
  const atype = pa.type ?? "action";
  const r = o.resolution;
  const reason = r ? r.reason : o.error ? `Resolver unavailable: ${o.error}` : "Resolver unavailable.";
  const conf = r ? r.confidence ?? null : null;
  const meta = r
    ? { type: r.resolverType ?? "EXTERNAL", implementation: r.implementation ?? "custom", version: r.implementationVersion ?? "0", reference: r.reference ?? null }
    : { type: "EXTERNAL", implementation: "unknown", version: "0", reference: null };
  const falsifiers = r?.falsifiers ? [...r.falsifiers] : [];
  const condition = typeof falsifiers[0] === "string" && falsifiers[0]
    ? falsifiers[0]
    : `An OUTCOME record linked to ${p.record_id} reports status failed or reverted before ${expires}.`;
  const directive = { ACT: `ACT: execute ${atype} as evaluated in ${p.record_id}.`, BLOCK: `BLOCK: do not execute ${atype}.`,
    ESCALATE: `ESCALATE: ${atype} still requires a human or another resolver.` }[o.finalDecision];
  Object.assign(rec, {
    decision: o.finalDecision, original_gate_decision: p.decision,
    reason_code: r && r.reasonCode ? r.reasonCode : p.reason_code, resolution_status: o.status, request_hash: p.request_hash,
    action: { ...pa, directive, judgment_ref: judId }, resolver: meta,
    judgment_detail: { reason, confidence: conf, falsifiers, evidence: r?.evidence ? { ...r.evidence } : {} },
    external_record: r?.externalRecord ? { ...r.externalRecord } : null,
    signal: { id: sigId, description: `Gate record ${p.record_id} escalated (${p.reason_code}); resolver consulted.`,
      sources: [`fjp:record:${p.record_id}`, `fjp:resolver:${meta.type.toLowerCase()}`, ...(meta.reference ? [`fjp:resolver-ref:${meta.reference}`] : [])],
      observed_at: iso(o.now) },
    judgment: { id: judId, assessment: reason || "No reason supplied.",
      confidence: typeof conf === "number" && conf >= 0 && conf <= 1 ? conf : 0,
      basis: r ? "external_resolver" : "resolver_unavailable", signal_ref: sigId },
    falsifier: { condition, checkable: true, status: "open" },
  });
  if (o.error) rec.resolution_error = String(o.error).slice(0, 500);
  return finalize(rec, o.signer);
}

export function buildOutcomeRecord(o: { recordId: string; parent: JGR; now: Date; status: string; details: Record<string, unknown>;
  horizonDays: number; signer?: Signer | null }): JGR {
  const p = o.parent;
  const [rec, expires] = base({ recordId: o.recordId, requestId: p.request_id, rootId: p.root_record_id, parentId: p.record_id,
    eventType: "OUTCOME", now: o.now, horizonDays: o.horizonDays, policy: { ...p.policy }, actor: { ...p.actor } });
  const sigId = `sig-${o.recordId}`, judId = `jud-${o.recordId}`;
  Object.assign(rec, {
    status: o.status, details: o.details, decision: p.decision, request_hash: p.request_hash,
    action: { directive: `RECORD: outcome ${o.status} for ${p.record_id}.`, judgment_ref: judId },
    signal: { id: sigId, description: `Outcome reported for ${p.record_id}: ${o.status}.`, sources: [`fjp:record:${p.record_id}`], observed_at: iso(o.now) },
    judgment: { id: judId, assessment: `Reported outcome: ${o.status}.`, confidence: 1, basis: "reported_outcome", signal_ref: sigId },
    falsifier: { condition: `A later OUTCOME record linked to ${p.record_id} reports a status other than ${o.status} before ${expires}.`,
      checkable: true, status: "open" },
  });
  return finalize(rec, o.signer);
}

/** open | triggered | expired, from the record and every record sharing its root. Deterministic. */
export function evaluateFalsifier(record: JGR, linked: JGR[], now: Date = new Date()): "open" | "triggered" | "expired" {
  const r = record;
  const others = linked.filter((x) => x.record_id !== r.record_id)
    .sort((a, b) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : a.record_id < b.record_id ? -1 : 1));
  const root = r.root_record_id ?? r.record_id;
  const outcomes = others.filter((x) => x.event_type === "OUTCOME" && x.root_record_id === root);
  const resolutions = others.filter((x) => x.event_type === "RESOLUTION" && x.root_record_id === root);
  const expired = r.expires_at ? now.getTime() > parseIso(r.expires_at).getTime() : false;
  const done = (): "open" | "expired" => (expired ? "expired" : "open");

  if (r.event_type === "OUTCOME") {
    const later = outcomes.filter((x) => x.timestamp > r.timestamp);
    return later.some((x) => x.status !== r.status) ? "triggered" : done();
  }
  if (r.event_type === "RESOLUTION" || r.decision === "ACT") {
    for (const x of outcomes) {
      if (x.status === "failed" || x.status === "reverted") return "triggered";
      const rh = x.details?.request_hash;
      if (x.status === "executed" && rh && rh !== r.request_hash) return "triggered";
    }
    if (outcomes.some((x) => x.status === "executed" || x.status === "cancelled")) return "expired";
    return done();
  }
  if (r.decision === "BLOCK") return outcomes.some((x) => x.status === "executed") ? "triggered" : done();
  const executed = outcomes.filter((x) => x.status === "executed");
  if (executed.length) {
    const first = executed[0];
    const prior = resolutions.filter((x) => x.timestamp <= first.timestamp);
    const approvals = outcomes.filter((x) => x.status === "approved" && x.timestamp <= first.timestamp);
    return (prior.length && prior[prior.length - 1].decision === "ACT") || approvals.length ? "expired" : "triggered";
  }
  return done();
}

export function newRecordId() {
  return newId("jgr");
}
