/**
 * Deterministic condition evaluation (identical semantics to the Python SDK). No eval().
 * Missing fields never match (except not_exists). Type mismatches throw EvaluationError -> fail closed.
 */
import { EvaluationError } from "./errors.js";

export const OPS = ["eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in", "exists", "not_exists", "contains"] as const;
export const ROOTS = ["actor", "action", "context", "evidence", "risk", "irreversibility", "confidence", "metadata"] as const;

export type Condition =
  | { all: Condition[] }
  | { any: Condition[] }
  | { not: Condition }
  | { field: string; op: (typeof OPS)[number]; value?: unknown };

export const MISSING = Symbol("missing");

export function resolvePath(doc: unknown, path: string): unknown {
  let cur: unknown = doc;
  for (const part of path.split(".")) {
    if (cur && typeof cur === "object" && !Array.isArray(cur) && Object.prototype.hasOwnProperty.call(cur, part)) {
      cur = (cur as Record<string, unknown>)[part];
    } else return MISSING;
  }
  return cur;
}

export const present = (v: unknown) => v !== MISSING && v !== null && v !== undefined;
const isNum = (v: unknown): v is number => typeof v === "number";

export function jsonEq(a: unknown, b: unknown): boolean {
  if (isNum(a) && isNum(b)) return a === b;
  if (typeof a === "boolean" || typeof b === "boolean") return a === b;
  if (a === null || b === null) return a === b;
  if (typeof a === "string" && typeof b === "string") return a === b;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => jsonEq(x, b[i]));
  if (a && b && typeof a === "object" && typeof b === "object" && !Array.isArray(a) && !Array.isArray(b)) {
    const ka = Object.keys(a), kb = Object.keys(b);
    return ka.length === kb.length && ka.every((k) => Object.prototype.hasOwnProperty.call(b, k)
      && jsonEq((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
  }
  return false;
}

function order(a: unknown, b: unknown, field: string, op: string): number {
  if (isNum(a) && isNum(b)) return a > b ? 1 : a < b ? -1 : 0;
  if (typeof a === "string" && typeof b === "string") return a > b ? 1 : a < b ? -1 : 0; // UTF-16 code units
  throw new EvaluationError(`${field} ${op}: cannot compare ${typeName(a)} with ${typeName(b)}`);
}

function typeName(v: unknown) {
  return v === null ? "null" : Array.isArray(v) ? "list" : typeof v;
}

function leaf(doc: unknown, c: { field: string; op: string; value?: unknown }): boolean {
  const v = resolvePath(doc, c.field);
  if (c.op === "exists") return present(v);
  if (c.op === "not_exists") return !present(v);
  if (!present(v)) return false;
  const t = c.value;
  switch (c.op) {
    case "eq": return jsonEq(v, t);
    case "neq": return !jsonEq(v, t);
    case "gt": return order(v, t, c.field, c.op) > 0;
    case "gte": return order(v, t, c.field, c.op) >= 0;
    case "lt": return order(v, t, c.field, c.op) < 0;
    case "lte": return order(v, t, c.field, c.op) <= 0;
    case "in": return (t as unknown[]).some((x) => jsonEq(v, x));
    case "not_in": return !(t as unknown[]).some((x) => jsonEq(v, x));
    case "contains":
      if (typeof v === "string") {
        if (typeof t !== "string") throw new EvaluationError(`${c.field} contains: string field needs a string value`);
        return v.includes(t);
      }
      if (Array.isArray(v)) return v.some((x) => jsonEq(x, t));
      throw new EvaluationError(`${c.field} contains: field must be a string or list, got ${typeName(v)}`);
    default:
      throw new EvaluationError(`unknown operator ${JSON.stringify(c.op)}`);
  }
}

export function matches(doc: unknown, c: Condition): boolean {
  if ("all" in c) return c.all.every((x) => matches(doc, x));
  if ("any" in c) return c.any.some((x) => matches(doc, x));
  if ("not" in c) return !matches(doc, c.not);
  return leaf(doc, c);
}
