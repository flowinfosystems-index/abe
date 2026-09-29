/**
 * FJP-CONF v0.1 checks — TypeScript port of github.com/flowinfosystems-index/fjp-conformance (Apache-2.0).
 * Same check ids, blocklists and markers as the reference Python suite.
 */
export const SPEC_VERSION = "0.1.0";
export const VALID_STATUSES = ["open", "triggered", "expired"];
export const VACUITY_BLOCKLIST = ["circumstances change", "things change", "the world changes", "the situation changes",
  "conditions change", "new information", "it becomes clear", "anything changes", "something changes", "market changes",
  "sentiment changes"];
export const CONCRETENESS_MARKERS = ["exceeds", "falls", "drops", "rises", "above", "below", "reaches", "within", "by ",
  "before", "after", "greater than", "less than", "more than", "fewer than", "at least", "at most", "declines", "increases",
  "%", "$", "per ", "no later than", "if not", "unless", "announces", "files", "confirms", "denies", "misses", "beats",
  "resign", "cancel", "reject", "approv", "closes", "terminat", "withdraw", "delay", "acquir", "launch", "recall",
  "default", "downgrade", "upgrade", "steps down", "departs", "reaffirm", "raises", "cuts", "suspend", "rules", "votes",
  "signs", "expires", "settle"];

export interface CheckResult { check_id: string; level: number; passed: boolean; detail: string }

const nonEmpty = (v: unknown) => typeof v === "string" && v.trim() !== "";
const isObj = (v: unknown): v is Record<string, any> => !!v && typeof v === "object" && !Array.isArray(v); // eslint-disable-line @typescript-eslint/no-explicit-any
const obj = (r: Record<string, unknown>, k: string) => (isObj(r[k]) ? (r[k] as Record<string, any>) : {}); // eslint-disable-line @typescript-eslint/no-explicit-any

function validIso(v: unknown): boolean {
  if (typeof v !== "string" || !v.trim()) return false;
  // Python's datetime.fromisoformat (3.11) accepts these shapes; keep to the common RFC 3339 subset.
  return /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?)?(Z|[+-]\d{2}:?\d{2})?$/.test(v.trim()) && !Number.isNaN(Date.parse(v.trim().replace(" ", "T")));
}

export const canonicalSignalId = (s: unknown) => (isObj(s) ? String(s.id || s.description || "").trim() : "");
export const canonicalJudgmentId = (j: unknown) => (isObj(j) ? String(j.id || j.assessment || "").trim() : "");

export function checkL0(record: unknown): CheckResult[] {
  const r: CheckResult[] = [];
  const add = (id: string, ok: boolean, msg: string) => r.push({ check_id: id, level: 0, passed: ok, detail: msg });
  if (!isObj(record)) {
    add("L0.record.is_object", false, "record must be a JSON object");
    return r;
  }
  add("L0.record_id", nonEmpty(record.record_id), "record_id must be a non-empty string");
  add("L0.timestamp", validIso(record.timestamp), "timestamp must be valid ISO 8601");
  for (const c of ["signal", "judgment", "action", "falsifier"]) add(`L0.${c}.present`, isObj(record[c]), `${c} must be present and an object`);
  const sig = obj(record, "signal"), jud = obj(record, "judgment"), act = obj(record, "action"), fal = obj(record, "falsifier");
  add("L0.signal.description", nonEmpty(sig.description), "signal.description must be a non-empty string");
  add("L0.signal.observed_at", validIso(sig.observed_at), "signal.observed_at must be valid ISO 8601");
  add("L0.judgment.assessment", nonEmpty(jud.assessment), "judgment.assessment must be a non-empty string");
  const conf = jud.confidence;
  add("L0.judgment.confidence", typeof conf === "number" && conf >= 0 && conf <= 1, "judgment.confidence must be a number in [0, 1]");
  add("L0.action.directive", nonEmpty(act.directive), "action.directive must be a non-empty string");
  add("L0.falsifier.condition", nonEmpty(fal.condition), "falsifier.condition must be a non-empty string");
  return r;
}

export function checkL1(record: Record<string, unknown>): CheckResult[] {
  const r: CheckResult[] = [];
  const add = (id: string, ok: boolean, msg: string) => r.push({ check_id: id, level: 1, passed: ok, detail: msg });
  const sig = obj(record, "signal"), jud = obj(record, "judgment"), act = obj(record, "action");
  add("L1.signal.sources", Array.isArray(sig.sources) && sig.sources.some(nonEmpty), "signal.sources must be a non-empty list of identifiers");
  add("L1.judgment.signal_ref", nonEmpty(jud.signal_ref) && jud.signal_ref === canonicalSignalId(sig),
    "judgment.signal_ref must match the signal's canonical identity");
  add("L1.action.judgment_ref", nonEmpty(act.judgment_ref) && act.judgment_ref === canonicalJudgmentId(jud),
    "action.judgment_ref must match the judgment's canonical identity");
  return r;
}

function isVacuous(condition: string): boolean {
  const c = condition.replace(/\(\s*per\s[^)]*\)/gi, " ").toLowerCase();
  if (VACUITY_BLOCKLIST.some((b) => c.includes(b))) return true;
  return !(CONCRETENESS_MARKERS.some((m) => c.includes(m)) || /\d/.test(c));
}

export function checkL2(record: Record<string, unknown>): CheckResult[] {
  const r: CheckResult[] = [];
  const add = (id: string, ok: boolean, msg: string) => r.push({ check_id: id, level: 2, passed: ok, detail: msg });
  const fal = obj(record, "falsifier");
  const cond = fal.condition ?? "";
  add("L2.falsifier.checkable", fal.checkable === true, "falsifier.checkable must be exactly true");
  add("L2.falsifier.status", VALID_STATUSES.includes(fal.status), `falsifier.status must be one of ${VALID_STATUSES.join(", ")}`);
  add("L2.falsifier.concrete", nonEmpty(cond) && !isVacuous(cond),
    "falsifier.condition must be concrete (references a threshold, quantity, dated bound, or event) and not a vacuous catch-all");
  return r;
}

export interface L3Adapter {
  getRecord(recordId: string): Promise<Record<string, unknown>> | Record<string, unknown>;
  evaluateFalsifier(recordId: string): Promise<string> | string;
}

export async function checkL3(adapter: L3Adapter, recordId: string): Promise<CheckResult[]> {
  const r: CheckResult[] = [];
  const add = (id: string, ok: boolean, msg: string) => r.push({ check_id: id, level: 3, passed: ok, detail: msg });
  let rec: Record<string, unknown>;
  try {
    rec = await adapter.getRecord(recordId);
  } catch (e) {
    add("L3.get_record", false, `get_record raised: ${String(e)}`);
    return r;
  }
  add("L3.get_record.returns_record", isObj(rec) && rec.record_id === recordId, "get_record must return the JGR with the requested record_id");
  add("L3.get_record.valid_jgr", isObj(rec) && checkL0(rec).every((x) => x.passed), "retrieved record must still be a valid (L0) JGR");
  try {
    const status = await adapter.evaluateFalsifier(recordId);
    add("L3.evaluate_falsifier", VALID_STATUSES.includes(status), `evaluate_falsifier must return one of ${VALID_STATUSES.join(", ")}`);
  } catch (e) {
    add("L3.evaluate_falsifier", false, `evaluate_falsifier raised: ${String(e)}`);
  }
  return r;
}

export function evaluate(record: unknown, level: number): CheckResult[] {
  let out = checkL0(record);
  if (!isObj(record)) return out;
  if (level >= 1) out = out.concat(checkL1(record));
  if (level >= 2) out = out.concat(checkL2(record));
  return out;
}

export const conforms = (results: CheckResult[]) => results.every((r) => r.passed);
