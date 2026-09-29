/** Policy loading and strict validation (same rules and hash as the Python SDK). */
import { readFileSync, statSync } from "node:fs";
import { hashValue } from "./canonical.js";
import { PolicyError, RequestError } from "./errors.js";
import { type Condition, OPS, ROOTS } from "./evaluator.js";
import { DEFAULT_FOR_DECISION, NOT_AUTO_RESOLVABLE, isValidReasonCode } from "./reasonCodes.js";
import { loadYaml } from "./yamlSafe.js";

export const POLICY_FORMAT_VERSION = "0.1";
export const DECISIONS = ["ACT", "BLOCK", "ESCALATE"] as const;
export type Decision = (typeof DECISIONS)[number];
export const LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type Level = (typeof LEVELS)[number];
export const LEVEL_RANK: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
export const MAX_POLICY_BYTES = 1_048_576;
const MAX_RULES = 1000;
const MAX_COND_DEPTH = 16;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const PATH = /^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+){0,15}$/;
const TOP_KEYS = ["version", "policy_id", "policy_version", "description", "defaults", "authorization", "rules",
  "risk", "irreversibility", "evidence_requirements", "confidence", "judgment_required", "resolver", "records"];

export interface Rule { id: string; when: Condition; decision: Decision; reason_code: string; description: string }
export interface Scale { default: Level | null; mappings: [Condition, Level][]; escalate_at: Level[]; block_at: Level[] }
export interface Policy {
  raw: Record<string, unknown>;
  hash: string;
  policy_id: string | null;
  policy_version: string | null;
  unmatched_decision: Decision;
  unmatched_reason: string;
  rules: Rule[];
  authorization: { default: "allow" | "deny"; agents: Record<string, { allow?: string[]; deny?: string[] }> } | null;
  risk: Scale | null;
  irreversibility: Scale | null;
  evidence_requirements: { id: string; when: Condition | null; require: string[]; decision: Decision; reason_code: string }[];
  confidence: { minimum: number; decision: Decision; reason_code: string; when_missing: "ignore" | "escalate" } | null;
  judgment_required: { id: string; when: Condition; reason_code: string }[];
  resolver: { enabled: boolean; mode: string; not_resolvable: string[] };
  falsifier_horizon_days: number;
  source: string | null;
  describe(): { id: string | null; version: string | null; hash: string; format_version: string };
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const fail = (where: string, msg: string): never => { throw new PolicyError(`${where}: ${msg}`); };

function keys(obj: unknown, allowed: string[], where: string, required: string[] = []): Record<string, unknown> {
  if (!isObj(obj)) fail(where, "must be a mapping");
  const o = obj as Record<string, unknown>;
  const extra = Object.keys(o).filter((k) => !allowed.includes(k)).sort();
  if (extra.length) fail(where, `unknown key(s) ${JSON.stringify(extra)}; allowed: ${JSON.stringify([...allowed].sort())}`);
  for (const r of required) if (!(r in o)) fail(where, `missing required key '${r}'`);
  return o;
}

function path(p: unknown, where: string) {
  if (typeof p !== "string" || !PATH.test(p)) fail(where, `invalid field path ${JSON.stringify(p)}`);
  if (!(ROOTS as readonly string[]).includes((p as string).split(".")[0]))
    fail(where, `field '${p}' must start with one of ${JSON.stringify(ROOTS)}`);
}

const scalar = (v: unknown) => v === null || ["string", "number", "boolean"].includes(typeof v);

export function validateCondition(c: unknown, where: string, depth = 0): void {
  if (depth > MAX_COND_DEPTH) fail(where, `condition nested deeper than ${MAX_COND_DEPTH}`);
  if (!isObj(c)) fail(where, "condition must be a mapping");
  const o = c as Record<string, unknown>;
  const forms = ["all", "any", "not"].filter((k) => k in o);
  if (forms.length) {
    const k = forms[0];
    if (Object.keys(o).length !== 1) fail(where, `a '${k}' condition cannot have other keys`);
    if (k === "not") return validateCondition(o.not, `${where}.not`, depth + 1);
    const list = o[k];
    if (!Array.isArray(list) || !list.length) fail(where, `'${k}' must be a non-empty list`);
    (list as unknown[]).forEach((sub, i) => validateCondition(sub, `${where}.${k}[${i}]`, depth + 1));
    return;
  }
  keys(o, ["field", "op", "value"], where, ["field", "op"]);
  path(o.field, where);
  const op = o.op as string;
  if (!(OPS as readonly string[]).includes(op)) fail(where, `unknown op '${op}'; allowed: ${JSON.stringify(OPS)}`);
  if (op === "exists" || op === "not_exists") {
    if ("value" in o) fail(where, `'${op}' takes no value`);
    return;
  }
  if (!("value" in o)) fail(where, `'${op}' requires a value`);
  const v = o.value;
  if (op === "in" || op === "not_in") {
    if (!Array.isArray(v) || !v.length) fail(where, `'${op}' value must be a non-empty list`);
  } else if (["gt", "gte", "lt", "lte"].includes(op)) {
    if (typeof v !== "number" && typeof v !== "string") fail(where, `'${op}' value must be a number or string`);
  } else if (op === "contains") {
    if (!scalar(v) || v === null) fail(where, "'contains' value must be a string, number or boolean");
  }
}

function decision(v: unknown, where: string, allowed: readonly string[] = DECISIONS): Decision {
  if (!allowed.includes(v as string)) fail(where, `decision must be one of ${JSON.stringify(allowed)}, got ${JSON.stringify(v)}`);
  return v as Decision;
}

function reason(v: unknown, where: string): string {
  if (!isValidReasonCode(v)) fail(where, `reason_code ${JSON.stringify(v)} is not a standard code or a namespaced custom code (namespace.identifier)`);
  return v as string;
}

function levels(v: unknown, where: string): Level[] {
  if (!Array.isArray(v) || v.some((x) => !(LEVELS as readonly string[]).includes(x))) fail(where, `must be a list of ${JSON.stringify(LEVELS)}`);
  return [...(v as Level[])];
}

function scale(obj: unknown, where: string): Scale | null {
  if (obj === undefined || obj === null) return null;
  const o = keys(obj, ["defaults", "mappings", "escalate_at", "block_at"], where);
  let def: Level | null = null;
  if ("defaults" in o) {
    const d = keys(o.defaults, ["level"], `${where}.defaults`, ["level"]);
    if (!(LEVELS as readonly string[]).includes(d.level as string)) fail(`${where}.defaults.level`, `must be one of ${JSON.stringify(LEVELS)}`);
    def = d.level as Level;
  }
  const mappings: [Condition, Level][] = [];
  ((o.mappings as unknown[]) || []).forEach((m, i) => {
    const w = `${where}.mappings[${i}]`;
    const mm = keys(m, ["when", "level"], w, ["when", "level"]);
    validateCondition(mm.when, `${w}.when`);
    if (!(LEVELS as readonly string[]).includes(mm.level as string)) fail(`${w}.level`, `must be one of ${JSON.stringify(LEVELS)}`);
    mappings.push([mm.when as Condition, mm.level as Level]);
  });
  return { default: def, mappings, escalate_at: levels(o.escalate_at ?? [], `${where}.escalate_at`),
    block_at: levels(o.block_at ?? [], `${where}.block_at`) };
}

export function parsePolicy(data: unknown, source: string | null = null): Policy {
  if (!isObj(data)) throw new PolicyError("policy must be a mapping at the top level");
  keys(data, TOP_KEYS, "policy", ["version"]);
  if (data.version !== POLICY_FORMAT_VERSION)
    throw new PolicyError(`policy.version must be the string "${POLICY_FORMAT_VERSION}" (quote it in YAML)`);
  let phash: string;
  try {
    phash = hashValue(data);
  } catch (e) {
    if (e instanceof RequestError) throw new PolicyError(`policy is not canonical JSON-compatible: ${e.message}`);
    throw e;
  }
  for (const k of ["policy_id", "policy_version", "description"])
    if (k in data && typeof data[k] !== "string") fail(`policy.${k}`, "must be a string");

  const d = keys(data.defaults ?? {}, ["unmatched", "unmatched_reason_code"], "policy.defaults");
  const unmatched = decision(d.unmatched ?? "ESCALATE", "policy.defaults.unmatched");
  const unmatchedReason = reason(d.unmatched_reason_code ?? DEFAULT_FOR_DECISION[unmatched], "policy.defaults.unmatched_reason_code");

  const rulesIn = data.rules ?? [];
  if (!Array.isArray(rulesIn)) fail("policy.rules", "must be a list");
  if ((rulesIn as unknown[]).length > MAX_RULES) fail("policy.rules", `at most ${MAX_RULES} rules`);
  const rules: Rule[] = [];
  const seen = new Set<string>();
  (rulesIn as unknown[]).forEach((r, i) => {
    let w = `policy.rules[${i}]`;
    const rr = keys(r, ["id", "description", "when", "decision", "reason_code"], w, ["id", "when", "decision"]);
    if (typeof rr.id !== "string" || !ID.test(rr.id)) fail(`${w}.id`, "must match [A-Za-z0-9][A-Za-z0-9_.:-]*");
    const id = rr.id as string;
    if (seen.has(id)) fail(`${w}.id`, `duplicate rule id '${id}'`);
    seen.add(id);
    w = `policy.rules[${id}]`;
    validateCondition(rr.when, `${w}.when`);
    const dec = decision(rr.decision, `${w}.decision`);
    const rc = reason(rr.reason_code ?? DEFAULT_FOR_DECISION[dec], `${w}.reason_code`);
    if ("description" in rr && typeof rr.description !== "string") fail(`${w}.description`, "must be a string");
    rules.push({ id, when: rr.when as Condition, decision: dec, reason_code: rc, description: (rr.description as string) ?? "" });
  });

  let authorization: Policy["authorization"] = null;
  if (data.authorization !== undefined && data.authorization !== null) {
    const a = keys(data.authorization, ["default", "agents"], "policy.authorization");
    const def = a.default ?? "deny";
    if (def !== "allow" && def !== "deny") fail("policy.authorization.default", "must be 'allow' or 'deny'");
    const agents = a.agents ?? {};
    if (!isObj(agents)) fail("policy.authorization.agents", "must be a mapping of agent_id -> {allow, deny}");
    for (const [aid, spec] of Object.entries(agents as object)) {
      const w = `policy.authorization.agents[${aid}]`;
      const s = keys(spec, ["allow", "deny"], w);
      for (const k of ["allow", "deny"])
        if (k in s && (!Array.isArray(s[k]) || !(s[k] as unknown[]).every((x) => typeof x === "string")))
          fail(`${w}.${k}`, "must be a list of action types ('*' for all)");
    }
    authorization = { default: def as "allow" | "deny", agents: agents as Record<string, { allow?: string[]; deny?: string[] }> };
  }

  const risk = scale(data.risk, "policy.risk");
  const irr = scale(data.irreversibility, "policy.irreversibility");

  const evIn = data.evidence_requirements ?? [];
  if (!Array.isArray(evIn)) fail("policy.evidence_requirements", "must be a list");
  const evs: Policy["evidence_requirements"] = (evIn as unknown[]).map((e, i) => {
    const w = `policy.evidence_requirements[${i}]`;
    const ee = keys(e, ["id", "when", "require", "missing_decision", "reason_code"], w, ["id", "require"]);
    if ("when" in ee) validateCondition(ee.when, `${w}.when`);
    if (!Array.isArray(ee.require) || !ee.require.length) fail(`${w}.require`, "must be a non-empty list of field paths");
    (ee.require as unknown[]).forEach((p) => path(p, `${w}.require`));
    return { id: String(ee.id), when: (ee.when as Condition) ?? null, require: [...(ee.require as string[])],
      decision: decision(ee.missing_decision ?? "ESCALATE", `${w}.missing_decision`, ["BLOCK", "ESCALATE"]),
      reason_code: reason(ee.reason_code ?? "EVIDENCE_MISSING", `${w}.reason_code`) };
  });

  let confidence: Policy["confidence"] = null;
  if (data.confidence !== undefined && data.confidence !== null) {
    const c = keys(data.confidence, ["minimum_to_act", "below_minimum", "when_missing"], "policy.confidence", ["minimum_to_act"]);
    const m = c.minimum_to_act;
    if (typeof m !== "number" || m < 0 || m > 1) fail("policy.confidence.minimum_to_act", "must be a number in [0, 1]");
    const below = keys(c.below_minimum ?? {}, ["decision", "reason_code"], "policy.confidence.below_minimum");
    const wm = c.when_missing ?? "ignore";
    if (wm !== "ignore" && wm !== "escalate") fail("policy.confidence.when_missing", "must be 'ignore' or 'escalate'");
    confidence = { minimum: m as number,
      decision: decision(below.decision ?? "ESCALATE", "policy.confidence.below_minimum.decision", ["BLOCK", "ESCALATE"]),
      reason_code: reason(below.reason_code ?? "INSUFFICIENT_CONFIDENCE", "policy.confidence.below_minimum.reason_code"),
      when_missing: wm as "ignore" | "escalate" };
  }

  const jrIn = data.judgment_required ?? [];
  if (!Array.isArray(jrIn)) fail("policy.judgment_required", "must be a list");
  const jr: Policy["judgment_required"] = (jrIn as unknown[]).map((j, i) => {
    const w = `policy.judgment_required[${i}]`;
    if (!isObj(j) || !Object.keys(j).length) fail(w, "must be a mapping");
    const jj = j as Record<string, unknown>;
    if ("when" in jj) {
      keys(jj, ["id", "when", "reason_code"], w, ["when"]);
      validateCondition(jj.when, `${w}.when`);
      return { id: String(jj.id ?? `judgment_required[${i}]`), when: jj.when as Condition,
        reason_code: reason(jj.reason_code ?? "JUDGMENT_REQUIRED", `${w}.reason_code`) };
    }
    const leaves: Condition[] = Object.entries(jj).map(([p, v]) => {
      path(p, w);
      if (!scalar(v)) fail(w, `${p}: shorthand value must be a scalar (use 'when' for complex conditions)`);
      return { field: p, op: "eq", value: v } as Condition;
    });
    return { id: `judgment_required[${i}]`, when: leaves.length === 1 ? leaves[0] : { all: leaves }, reason_code: "JUDGMENT_REQUIRED" };
  });

  const res = keys(data.resolver ?? {}, ["enabled", "mode", "not_resolvable"], "policy.resolver");
  if ("enabled" in res && typeof res.enabled !== "boolean") fail("policy.resolver.enabled", "must be true or false");
  const nr = res.not_resolvable ?? NOT_AUTO_RESOLVABLE;
  if (!Array.isArray(nr) || nr.some((x) => !isValidReasonCode(x))) fail("policy.resolver.not_resolvable", "must be a list of reason codes");

  const recs = keys(data.records ?? {}, ["falsifier_horizon_days"], "policy.records");
  const horizon = recs.falsifier_horizon_days ?? 30;
  if (typeof horizon !== "number" || !Number.isInteger(horizon) || horizon < 1 || horizon > 3650)
    fail("policy.records.falsifier_horizon_days", "must be an integer 1..3650");

  const policy: Policy = {
    raw: data, hash: phash, policy_id: (data.policy_id as string) ?? null, policy_version: (data.policy_version as string) ?? null,
    unmatched_decision: unmatched, unmatched_reason: unmatchedReason, rules, authorization, risk, irreversibility: irr,
    evidence_requirements: evs, confidence, judgment_required: jr,
    resolver: { enabled: (res.enabled as boolean) ?? true, mode: (res.mode as string) ?? "external", not_resolvable: [...(nr as string[])] },
    falsifier_horizon_days: horizon as number, source,
    describe() {
      return { id: this.policy_id, version: this.policy_version, hash: this.hash, format_version: POLICY_FORMAT_VERSION };
    },
  };
  return policy;
}

/** Accepts a Policy, a plain object, a path to a .yaml/.yml/.json file, or YAML text. */
export function loadPolicy(policy: Policy | Record<string, unknown> | string): Policy {
  if (isObj(policy) && typeof (policy as unknown as Policy).describe === "function" && "hash" in policy) return policy as unknown as Policy;
  if (isObj(policy)) return parsePolicy(policy);
  if (typeof policy !== "string") throw new PolicyError(`unsupported policy type ${typeof policy}`);
  if (!policy.includes("\n")) {
    let size: number;
    try {
      size = statSync(policy).size;
    } catch {
      throw new PolicyError(`policy file not found: ${policy}`);
    }
    if (size > MAX_POLICY_BYTES) throw new PolicyError(`policy file exceeds ${MAX_POLICY_BYTES} bytes`);
    const text = readFileSync(policy, "utf8");
    let data: unknown;
    if (policy.endsWith(".json")) {
      try {
        data = JSON.parse(text, (_k, v) => v);
      } catch (e) {
        throw new PolicyError(`invalid JSON: ${(e as Error).message}`);
      }
      // JSON.parse silently keeps the last duplicate key; parse again as YAML (a JSON superset) to detect duplicates.
      loadYaml(text);
    } else data = loadYaml(text);
    return parsePolicy(data, policy);
  }
  if (Buffer.byteLength(policy, "utf8") > MAX_POLICY_BYTES) throw new PolicyError(`policy text exceeds ${MAX_POLICY_BYTES} bytes`);
  return parsePolicy(loadYaml(policy));
}
