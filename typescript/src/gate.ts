/**
 * Abe: one control point before an AI agent acts. Mirrors the Python SDK exactly.
 *
 *   const gate = new Gate({ policy: "./abe-policy.yaml" });
 *   const result = await gate.check({ action: { type: "purchase", amount: 12500 }, context: { agent_id: "procurement-agent" } });
 *   result.decision // "ACT" | "BLOCK" | "ESCALATE"
 */
import { canonicalJson, hashValue, toPlain } from "./canonical.js";
import { EvaluationError, PolicyError, RequestError } from "./errors.js";
import { type Condition, matches, present, resolvePath } from "./evaluator.js";
import { DECISIONS, type Decision, LEVELS, LEVEL_RANK, type Policy, type Scale, loadPolicy } from "./policy.js";
import { isValidReasonCode } from "./reasonCodes.js";
import {
  type Finding, type JGR, OUTCOME_STATUSES, type OutcomeStatus, type Resolution, type Signer, buildDecisionRecord,
  buildOutcomeRecord, buildResolutionRecord, evaluateFalsifier as evalFalsifier, newId, parseIso,
} from "./records.js";
import type { RecordStore } from "./stores.js";

export const MAX_REQUEST_BYTES = 262_144;
const SEVERITY: Record<string, number> = { ACT: 0, ESCALATE: 1, BLOCK: 2 };
const REQUEST_KEYS = ["protocol", "version", "request_id", "actor", "action", "context", "evidence", "confidence",
  "risk", "irreversibility", "metadata"];

export interface FJPRequest {
  protocol?: "FJP";
  version?: "0.1";
  request_id?: string;
  actor?: { agent_id?: string; principal_id?: string; organization_id?: string; [k: string]: unknown };
  action: { type: string; [k: string]: unknown };
  context?: Record<string, unknown>;
  evidence?: Record<string, unknown>;
  confidence?: number;
  risk?: { level: string } | string;
  irreversibility?: { level: string } | string;
  metadata?: Record<string, unknown>;
}

export interface ScaleResult { level: string; source: string; supplied?: string | null; mapped?: string | null }

export interface GateResult {
  decision: Decision;
  reasonCode: string;
  record: JGR;
  recordId: string;
  timestamp: string;
  riskLevel: string;
  irreversibilityLevel: string;
  matchedRules: string[];
  reasonCodes: string[];
  missingEvidence: string[];
  /** The Gate's own decision (differs from `decision` only when a resolver changed it). */
  gateDecision: Decision;
  records: JGR[];
  resolution: Record<string, unknown> | null;
  warnings: string[];
  /** True only for ACT. BLOCK and ESCALATE both mean: do not execute now. */
  allowed: boolean;
  /** The FJP v0.1 response format (snake_case, as on the wire). */
  toResponse(): Record<string, unknown>;
}

/** Optional resolver for ESCALATE results. Return null if it cannot resolve. Throwing keeps the result ESCALATE. */
export interface Resolver {
  resolve(request: Record<string, unknown>, gateResult: GateResult): Promise<Resolution | null> | Resolution | null;
}

export interface GateOptions {
  policy: Policy | Record<string, unknown> | string;
  resolver?: Resolver | null;
  store?: RecordStore | null;
  signer?: Signer | null;
  clock?: () => Date;
  maxRequestBytes?: number;
  /** Upper bound on a resolver call; on timeout the result stays ESCALATE. Default 15 s. */
  resolverTimeoutMs?: number;
}

type Req = { actor: Record<string, unknown>; action: Record<string, unknown>; context: Record<string, unknown>;
  evidence: Record<string, unknown>; confidence?: number; risk?: { level: string }; irreversibility?: { level: string };
  metadata?: Record<string, unknown>; request_id: string };

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function level(v: unknown, where: string): string | null {
  if (v === undefined || v === null) return null;
  if (isObj(v)) v = v.level;
  if (v === undefined || v === null) return null;
  if (!(LEVELS as readonly string[]).includes(v as string)) throw new RequestError(`${where} must be one of ${JSON.stringify(LEVELS)}`);
  return v as string;
}

export function normalizeRequest(src: unknown): { req: Req; ignored: string[] } {
  if (!isObj(src)) throw new RequestError("request must be an object");
  if ((src.protocol ?? "FJP") !== "FJP") throw new RequestError('protocol must be "FJP"');
  if (String(src.version ?? "0.1") !== "0.1") throw new RequestError('version must be "0.1"');
  const action = src.action;
  if (!isObj(action)) throw new RequestError("action must be an object");
  if (typeof action.type !== "string" || !action.type.trim()) throw new RequestError("action.type must be a non-empty string");
  for (const k of ["directive", "judgment_ref"]) if (k in action) throw new RequestError(`action.${k} is reserved by FJP records`);
  for (const k of ["context", "evidence", "metadata", "actor"])
    if (k in src && src[k] !== null && src[k] !== undefined && !isObj(src[k])) throw new RequestError(`${k} must be an object`);
  const context = { ...((src.context as object) ?? {}) } as Record<string, unknown>;
  const actor = { ...((src.actor as object) ?? {}) } as Record<string, unknown>;
  for (const k of ["agent_id", "principal_id", "organization_id"])
    if (!(k in actor) && typeof context[k] === "string") actor[k] = context[k];
  for (const k of ["agent_id", "principal_id", "organization_id"])
    if (actor[k] !== undefined && actor[k] !== null && typeof actor[k] !== "string") throw new RequestError(`actor.${k} must be a string`);
  const conf = src.confidence;
  if (conf !== undefined && conf !== null && (typeof conf !== "number" || !(conf >= 0 && conf <= 1)))
    throw new RequestError("confidence must be a number in [0, 1]");
  const rid = src.request_id;
  if (rid !== undefined && rid !== null && (typeof rid !== "string" || !rid.trim() || rid.length > 128))
    throw new RequestError("request_id must be a non-empty string of at most 128 characters");
  const req: Req = { actor, action: { ...action }, context, evidence: { ...((src.evidence as object) ?? {}) } as Record<string, unknown>,
    request_id: (rid as string) || newId("req") };
  if (typeof conf === "number") req.confidence = conf;
  const rl = level(src.risk, "risk.level");
  if (rl) req.risk = { level: rl };
  const il = level(src.irreversibility, "irreversibility.level");
  if (il) req.irreversibility = { level: il };
  if (isObj(src.metadata) && Object.keys(src.metadata).length) req.metadata = { ...src.metadata };
  const ignored = Object.keys(src).filter((k) => !REQUEST_KEYS.includes(k)).sort();
  return { req, ignored };
}

function scaleLevel(req: Req, cfg: Scale | null, key: "risk" | "irreversibility"): ScaleResult {
  const supplied = req[key]?.level ?? null;
  let mapped: string | null = null, source: string | null = null;
  if (cfg) {
    for (const [cond, lvl] of cfg.mappings) if (matches(req, cond)) { mapped = lvl; source = "policy_mapping"; break; }
    if (mapped === null && cfg.default) { mapped = cfg.default; source = "policy_default"; }
  }
  const cands = [supplied, mapped].filter((x): x is string => !!x);
  if (!cands.length) return { level: "UNSPECIFIED", source: "none" };
  const lvl = cands.reduce((a, b) => (LEVEL_RANK[b] > LEVEL_RANK[a] ? b : a));
  let src: string;
  if (supplied && mapped) src = supplied === mapped ? "request+policy" : LEVEL_RANK[supplied] > LEVEL_RANK[mapped] ? "request" : (source as string);
  else src = supplied ? "request" : (source as string);
  return { level: lvl, source: src, supplied, mapped };
}

function makeResult(f: Omit<GateResult, "recordId" | "timestamp" | "allowed" | "toResponse">): GateResult {
  const r: GateResult = {
    ...f,
    recordId: f.record.record_id,
    timestamp: f.record.timestamp,
    allowed: f.decision === "ACT",
    toResponse() {
      const out: Record<string, unknown> = { protocol: "FJP", version: "0.1", decision: r.decision, reason_code: r.reasonCode,
        risk_level: r.riskLevel, record_id: r.recordId, timestamp: r.timestamp };
      if (r.matchedRules.length) out.matched_rules = [...r.matchedRules];
      if (r.missingEvidence.length) out.missing_evidence = [...r.missingEvidence];
      if ((r.gateDecision && r.gateDecision !== r.decision) || r.resolution) {
        out.original_gate_decision = r.gateDecision;
        out.gate_record_id = r.records[0].record_id;
      }
      if (r.resolution) out.resolution = { ...r.resolution };
      return out;
    },
  };
  return Object.freeze(r);
}

export class Gate {
  readonly policy: Policy;
  readonly resolver: Resolver | null;
  readonly store: RecordStore | null;
  readonly signer: Signer | null;
  private readonly clock: () => Date;
  private readonly maxRequestBytes: number;
  private readonly resolverTimeoutMs: number;

  /** Throws PolicyError at construction if the policy is invalid: loud, at startup, before any action. */
  constructor(opts: GateOptions | string) {
    const o: GateOptions = typeof opts === "string" ? { policy: opts } : opts;
    this.policy = loadPolicy(o.policy);
    if (o.resolver && typeof o.resolver.resolve !== "function") throw new TypeError("resolver must have a resolve() method");
    this.resolver = o.resolver ?? null;
    this.store = o.store ?? null;
    this.signer = o.signer ?? null;
    this.clock = o.clock ?? (() => new Date());
    this.maxRequestBytes = o.maxRequestBytes ?? MAX_REQUEST_BYTES;
    this.resolverTimeoutMs = o.resolverTimeoutMs ?? 15_000;
  }

  private evaluate(req: Req) {
    const p = this.policy;
    const findings: Finding[] = [];
    const add = (id: string, source: string, decision: string, reason_code: string, description = "") =>
      findings.push({ id, source, decision, reason_code, ...(description ? { description } : {}) });

    if (p.authorization) {
      const agent = req.actor.agent_id;
      const spec = typeof agent === "string" && Object.prototype.hasOwnProperty.call(p.authorization.agents, agent)
        ? p.authorization.agents[agent] : undefined;
      const atype = req.action.type as string;
      if (spec === undefined) {
        if (p.authorization.default === "deny") add("authorization", "authorization", "BLOCK", "AUTHORIZATION_FAILED",
          `agent ${pyRepr(agent)} is not authorized by this policy`);
      } else {
        const allow = spec.allow ?? ["*"], deny = spec.deny ?? [];
        if (deny.includes(atype) || deny.includes("*") || !(allow.includes(atype) || allow.includes("*")))
          add("authorization", "authorization", "BLOCK", "AUTHORIZATION_FAILED", `agent ${pyRepr(agent)} is not authorized for ${pyRepr(atype)}`);
      }
    }
    for (const r of p.rules) if (matches(req, r.when)) add(r.id, "rule", r.decision, r.reason_code, r.description);
    for (const j of p.judgment_required) if (matches(req, j.when)) add(j.id, "judgment_required", "ESCALATE", j.reason_code);
    const presentKeys = Object.keys(req.evidence).filter((k) => req.evidence[k] !== null && req.evidence[k] !== undefined).sort();
    const missing: string[] = [];
    for (const e of p.evidence_requirements) {
      if (e.when === null || matches(req, e.when as Condition)) {
        const miss = e.require.filter((path) => !present(resolvePath(req, path)));
        if (miss.length) {
          for (const m of miss) if (!missing.includes(m)) missing.push(m);
          add(e.id, "evidence", e.decision, e.reason_code, "missing " + miss.join(", "));
        }
      }
    }
    const risk = scaleLevel(req, p.risk, "risk");
    const irr = scaleLevel(req, p.irreversibility, "irreversibility");
    for (const [key, lv, cfg, reason] of [["risk", risk, p.risk, "RISK_THRESHOLD_EXCEEDED"],
      ["irreversibility", irr, p.irreversibility, "HIGH_IRREVERSIBILITY"]] as const) {
      if (cfg && (cfg.block_at as string[]).includes(lv.level)) add(`${key}.block_at`, key, "BLOCK", reason, `${key} ${lv.level}`);
      else if (cfg && (cfg.escalate_at as string[]).includes(lv.level)) add(`${key}.escalate_at`, key, "ESCALATE", reason, `${key} ${lv.level}`);
    }
    const confInfo: Record<string, unknown> = { supplied: req.confidence ?? null, calibrated: false };
    if (p.confidence) {
      confInfo.minimum_to_act = p.confidence.minimum;
      const c = req.confidence;
      if (c === undefined) {
        if (p.confidence.when_missing === "escalate")
          add("confidence.missing", "confidence", p.confidence.decision, p.confidence.reason_code, "no confidence supplied");
      } else if (c < p.confidence.minimum) {
        add("confidence.minimum_to_act", "confidence", p.confidence.decision, p.confidence.reason_code, `${c} < ${p.confidence.minimum}`);
      }
    }
    const top = findings.length ? Math.max(...findings.map((f) => SEVERITY[f.decision])) : null;
    const ruleDecisions = new Set(findings.filter((f) => f.source === "rule").map((f) => f.decision));
    let decision: Decision, reason: string;
    if (top === SEVERITY.BLOCK) {
      decision = "BLOCK";
      reason = findings.find((f) => f.decision === "BLOCK")!.reason_code;
    } else if (top === SEVERITY.ESCALATE) {
      decision = "ESCALATE";
      reason = ruleDecisions.has("ACT") && ruleDecisions.has("ESCALATE") ? "CONFLICTING_RULES"
        : findings.find((f) => f.decision === "ESCALATE")!.reason_code;
    } else if (top === SEVERITY.ACT) {
      decision = "ACT";
      reason = findings.find((f) => f.decision === "ACT")!.reason_code;
    } else {
      decision = p.unmatched_decision;
      reason = p.unmatched_reason;
      findings.push({ id: "defaults.unmatched", source: "default", decision, reason_code: reason, description: "no rule matched" });
    }
    const codes = [...new Set([reason, ...findings.map((f) => f.reason_code)])];
    return { decision, reason, codes, findings, risk, irr, presentKeys, missing, confInfo };
  }

  private evalTime(req: Req, now: Date): [Date, "request" | "system"] {
    for (const key of ["current_time", "time"]) {
      if (key in req.context) {
        const v = req.context[key];
        if (typeof v !== "string") throw new RequestError(`context.${key} must be an ISO 8601 string`);
        try {
          return [parseIso(v), "request"];
        } catch {
          throw new RequestError(`context.${key} is not valid ISO 8601`);
        }
      }
    }
    return [now, "system"];
  }

  /** Evaluate a proposed action. Never throws for bad input: fails closed to ESCALATE / EVALUATION_FAILURE. */
  async check(request: FJPRequest | Record<string, unknown>): Promise<GateResult> {
    const now = this.clock();
    let req: Req, ignored: string[], requestHash: string, evalTime: Date, timeSource: "request" | "system";
    let ev: ReturnType<Gate["evaluate"]>;
    try {
      ({ req, ignored } = normalizeRequest(request));
      const { request_id: _rid, ...hashed } = req; // eslint-disable-line @typescript-eslint/no-unused-vars
      const body = canonicalJson(hashed);
      if (Buffer.byteLength(body, "utf8") > this.maxRequestBytes) throw new RequestError(`request exceeds ${this.maxRequestBytes} bytes`);
      requestHash = hashValue(hashed);
      [evalTime, timeSource] = this.evalTime(req, now);
      ev = this.evaluate(req);
    } catch (e) {
      return this.failure(request, now, e);
    }
    const rec = buildDecisionRecord({ recordId: newId("jgr"), requestId: req.request_id, now, evalTime, timeSource, req,
      requestHash, policy: this.policy, decision: ev.decision, reasonCode: ev.reason, reasonCodes: ev.codes,
      matched: ev.findings.filter((f) => f.source !== "default"), risk: ev.risk, irr: ev.irr, evidencePresent: ev.presentKeys,
      evidenceMissing: ev.missing, confidence: ev.confInfo, signer: this.signer });
    const warnings = ignored.map((k) => `ignored unknown request field '${k}'`);
    const err = await this.persist(rec);
    if (err) return this.failure(request, now, err, rec);
    const result = makeResult({ decision: ev.decision, reasonCode: ev.reason, record: rec, riskLevel: ev.risk.level,
      irreversibilityLevel: ev.irr.level, matchedRules: [...rec.matched_rules], reasonCodes: ev.codes,
      missingEvidence: ev.missing, gateDecision: ev.decision, records: [rec], resolution: null, warnings });
    if (result.decision === "ESCALATE" && this.resolver && this.policy.resolver.enabled) {
      const esc = new Set([ev.reason, ...ev.findings.filter((f) => f.decision === "ESCALATE").map((f) => f.reason_code)]);
      if (this.policy.resolver.not_resolvable.some((c) => esc.has(c))) return result;
      return this.resolve(req, result, now);
    }
    return result;
  }

  private async resolve(req: Req, result: GateResult, now: Date): Promise<GateResult> {
    const parent = result.record;
    let resolution: Resolution | null = null, status = "resolved", error: string | null = null;
    try {
      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<never>((_, rej) => {
        timer = setTimeout(() => rej(new Error(`resolver timed out after ${this.resolverTimeoutMs} ms`)), this.resolverTimeoutMs);
      });
      try {
        resolution = await Promise.race([Promise.resolve(this.resolver!.resolve(toPlain(req), result)), timeout]);
      } finally {
        clearTimeout(timer);
      }
      if (resolution === null || resolution === undefined) { resolution = null; status = "unresolved"; }
      else if (!isObj(resolution) || typeof resolution.reason !== "string") throw new TypeError("resolver must return a Resolution or null");
      else if (!(DECISIONS as readonly string[]).includes(resolution.decision)) throw new Error(`resolver returned invalid decision ${JSON.stringify(resolution.decision)}`);
      else if (resolution.reasonCode != null && !isValidReasonCode(resolution.reasonCode)) throw new Error(`resolver returned invalid reason_code ${JSON.stringify(resolution.reasonCode)}`);
    } catch (e) {
      resolution = null;
      status = "unavailable";
      error = `${(e as Error).name ?? "Error"}: ${(e as Error).message ?? String(e)}`;
    }
    const final = resolution ? resolution.decision : "ESCALATE";
    const rrec = buildResolutionRecord({ recordId: newId("jgr"), parent, now: this.clock(), resolution, finalDecision: final,
      horizonDays: this.policy.falsifier_horizon_days, status, error, signer: this.signer });
    const err = await this.persist(rrec);
    if (err) return this.failure(req, now, err, rrec);
    const summary: Record<string, unknown> = { status, decision: final, record_id: rrec.record_id, resolver: { ...rrec.resolver } };
    if (resolution) Object.assign(summary, { reason: resolution.reason, confidence: resolution.confidence ?? null, falsifiers: [...(resolution.falsifiers ?? [])] });
    if (error) summary.error = error;
    return makeResult({ ...result, decision: final, reasonCode: rrec.reason_code, record: rrec, gateDecision: result.decision,
      records: [parent, rrec], resolution: summary });
  }

  private async persist(rec: JGR): Promise<Error | null> {
    if (!this.store) return null;
    try {
      await this.store.save(rec);
      return null;
    } catch (e) {
      return new Error(`record store failed: ${(e as Error).message}`);
    }
  }

  private async failure(raw: unknown, now: Date, error: unknown, parent?: JGR): Promise<GateResult> {
    const src = isObj(raw) ? raw : {};
    const a = isObj(src.action) ? src.action : {};
    const atype = typeof a.type === "string" ? a.type : "unknown";
    const ctx = isObj(src.context) ? src.context : {};
    const actorIn = isObj(src.actor) ? src.actor : {};
    const merged: Record<string, unknown> = { agent_id: ctx.agent_id, principal_id: ctx.principal_id, ...actorIn };
    const safeActor: Record<string, string> = {};
    for (const k of ["agent_id", "principal_id", "organization_id"])
      if (merged[k] !== undefined && merged[k] !== null) safeActor[k] = String(merged[k]).slice(0, 128);
    const rid = typeof src.request_id === "string" && src.request_id.length <= 128 && src.request_id ? src.request_id : newId("req");
    let requestHash: string;
    try { requestHash = hashValue(src); } catch { requestHash = "unavailable"; }
    const e = error as Error;
    const name = e instanceof RequestError || e instanceof EvaluationError || e instanceof PolicyError ? e.name
      : e instanceof RangeError ? "ValueError" : e?.name ?? "Error";
    const detail = `${name}: ${e?.message ?? String(error)}`;
    const finding: Finding = { id: "evaluation", source: "gate", decision: "ESCALATE", reason_code: "EVALUATION_FAILURE",
      description: parent ? `${e?.message} (unpersisted record ${parent.record_id})` : String(e?.message ?? error).slice(0, 300) };
    const rec = buildDecisionRecord({ recordId: newId("jgr"), requestId: rid, now, evalTime: now, timeSource: "system",
      req: { actor: safeActor, action: { type: atype.slice(0, 128) } }, requestHash, policy: this.policy, decision: "ESCALATE",
      reasonCode: "EVALUATION_FAILURE", reasonCodes: ["EVALUATION_FAILURE"], matched: [finding],
      risk: { level: "UNSPECIFIED", source: "none" }, irr: { level: "UNSPECIFIED", source: "none" }, evidencePresent: [],
      evidenceMissing: [], confidence: { supplied: null, calibrated: false }, failureDetail: detail, signer: this.signer });
    if (!parent) await this.persist(rec);
    return makeResult({ decision: "ESCALATE", reasonCode: "EVALUATION_FAILURE", record: rec, riskLevel: "UNSPECIFIED",
      irreversibilityLevel: "UNSPECIFIED", matchedRules: ["evaluation"], reasonCodes: ["EVALUATION_FAILURE"], missingEvidence: [],
      gateDecision: "ESCALATE", records: [rec], resolution: null, warnings: [detail] });
  }

  private async get(recordOrId: JGR | GateResult | string): Promise<JGR> {
    if (typeof recordOrId !== "string") return "records" in recordOrId && "gateDecision" in recordOrId ? recordOrId.records[0] : (recordOrId as JGR);
    if (!this.store) throw new Error("pass the record itself, or configure a store to look records up by id");
    const rec = await this.store.get(recordOrId);
    if (!rec) throw new RangeError(`record '${recordOrId}' not found`);
    return rec;
  }

  /** Append a linked OUTCOME record (never mutates the original). */
  async recordOutcome(recordOrId: JGR | GateResult | string, status: OutcomeStatus, details: Record<string, unknown> = {}): Promise<JGR> {
    if (!(OUTCOME_STATUSES as readonly string[]).includes(status)) throw new TypeError(`status must be one of ${OUTCOME_STATUSES.join(", ")}`);
    const d = toPlain(details);
    let target = await this.get(recordOrId);
    if (target.event_type !== "DECISION") {
      const root = this.store ? await this.store.get(target.root_record_id) : null;
      if (!root) throw new Error("outcomes attach to the Gate's DECISION record; pass result.records[0] or configure a store");
      target = root;
    }
    const rec = buildOutcomeRecord({ recordId: newId("jgr"), parent: target, now: this.clock(), status, details: d,
      horizonDays: this.policy.falsifier_horizon_days, signer: this.signer });
    const err = await this.persist(rec);
    if (err) throw err;
    return rec;
  }

  getRecord(recordId: string): Promise<JGR> {
    return this.get(recordId);
  }

  async evaluateFalsifier(recordOrId: JGR | string, now?: Date): Promise<"open" | "triggered" | "expired"> {
    const rec = await this.get(recordOrId);
    const linked = this.store ? await this.store.linked(rec.root_record_id) : [];
    return evalFalsifier(rec, linked, now ?? this.clock());
  }
}

function pyRepr(v: unknown): string {
  return typeof v === "string" ? `'${v}'` : v === undefined || v === null ? "None" : String(v);
}

