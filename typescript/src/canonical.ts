/**
 * Canonical JSON + SHA-256, byte-identical to the Python SDK:
 * keys sorted by UTF-16 code units, no whitespace, JSON.stringify string escaping, ECMAScript number
 * formatting; NaN/Infinity, integral numbers beyond 2^53-1, lone surrogates and non-JSON values rejected.
 */
import { createHash } from "node:crypto";
import { RequestError } from "./errors.js";

export const MAX_DEPTH = 32;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export function formatNumber(n: number): string {
  if (!Number.isFinite(n)) throw new RequestError("NaN and Infinity are not valid JSON");
  if (Number.isInteger(n) && Math.abs(n) > Number.MAX_SAFE_INTEGER)
    throw new RequestError("number exceeds the safe JSON integer range (2^53 - 1)");
  return JSON.stringify(n); // -0 -> "0"
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object") return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function enc(v: unknown, depth: number, out: string[]): void {
  if (depth > MAX_DEPTH) throw new RequestError(`nesting deeper than ${MAX_DEPTH}`);
  if (v === null) out.push("null");
  else if (v === true) out.push("true");
  else if (v === false) out.push("false");
  else if (typeof v === "string") {
    if (LONE_SURROGATE.test(v)) throw new RequestError("string contains invalid Unicode (lone surrogate)");
    out.push(JSON.stringify(v));
  } else if (typeof v === "number") out.push(formatNumber(v));
  else if (typeof v === "bigint") {
    if (v > BigInt(Number.MAX_SAFE_INTEGER) || v < -BigInt(Number.MAX_SAFE_INTEGER))
      throw new RequestError("integer exceeds the safe JSON range (2^53 - 1)");
    out.push(v.toString());
  } else if (Array.isArray(v)) {
    out.push("[");
    v.forEach((item, i) => {
      if (i) out.push(",");
      if (item === undefined) throw new RequestError("undefined is not JSON");
      enc(item, depth + 1, out);
    });
    out.push("]");
  } else if (isPlainObject(v)) {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    out.push("{");
    keys.forEach((k, i) => {
      if (i) out.push(",");
      if (LONE_SURROGATE.test(k)) throw new RequestError("key contains invalid Unicode (lone surrogate)");
      out.push(JSON.stringify(k), ":");
      enc(v[k], depth + 1, out);
    });
    out.push("}");
  } else {
    throw new RequestError(`value of type ${v === undefined ? "undefined" : (v as object).constructor?.name ?? typeof v} is not JSON`);
  }
}

export function canonicalJson(value: unknown): string {
  const out: string[] = [];
  enc(value, 0, out);
  return out.join("");
}

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** "sha256:<hex>" of the canonical JSON of value. */
export function hashValue(value: unknown): string {
  return "sha256:" + sha256Hex(canonicalJson(value));
}

/** Deep plain copy (drops frozenness). */
export function toPlain<T>(value: T): T {
  return JSON.parse(canonicalJson(value)) as T;
}

export function deepFreeze<T>(v: T): T {
  if (v && typeof v === "object" && !Object.isFrozen(v)) {
    for (const k of Object.keys(v as object)) deepFreeze((v as Record<string, unknown>)[k]);
    Object.freeze(v);
  }
  return v;
}
