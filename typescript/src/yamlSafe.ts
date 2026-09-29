/**
 * Safe YAML for policies: YAML 1.2 core schema (same scalars as the Python SDK), single document,
 * no anchors/aliases, no duplicate keys, string keys only, no custom tags, no NaN/Infinity.
 */
import { isScalar, parseDocument, visit } from "yaml";
import { PolicyError } from "./errors.js";

const ALLOWED_TAGS = new Set([
  "tag:yaml.org,2002:str", "tag:yaml.org,2002:int", "tag:yaml.org,2002:float", "tag:yaml.org,2002:bool",
  "tag:yaml.org,2002:null", "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq",
]);

function normalize(v: unknown): unknown {
  if (typeof v === "bigint") {
    if (v > BigInt(Number.MAX_SAFE_INTEGER) || v < -BigInt(Number.MAX_SAFE_INTEGER))
      throw new PolicyError("integer exceeds the safe JSON range (2^53 - 1)");
    return Number(v);
  }
  if (typeof v === "number" && !Number.isFinite(v)) throw new PolicyError("NaN and Infinity are not allowed in a policy");
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = normalize(x);
    return out;
  }
  return v;
}

export function loadYaml(text: string): unknown {
  const doc = parseDocument(text, { version: "1.2", schema: "core", uniqueKeys: true, intAsBigInt: true, merge: false });
  if (doc.errors.length) throw new PolicyError(`invalid YAML: ${doc.errors[0].message.split("\n")[0]}`);
  if (doc.warnings.length) throw new PolicyError(`invalid YAML: ${doc.warnings[0].message.split("\n")[0]}`);
  visit(doc, {
    Alias() {
      throw new PolicyError("YAML anchors/aliases are not allowed in FJP policies");
    },
    Pair(_, pair) {
      const k = pair.key;
      if (!isScalar(k) || typeof k.value !== "string") throw new PolicyError("mapping keys must be strings");
    },
    Node(_, node) {
      const tag = (node as { tag?: string }).tag;
      if (tag && !ALLOWED_TAGS.has(tag)) throw new PolicyError(`invalid YAML: tag ${tag} is not allowed`);
    },
  });
  return normalize(doc.toJS({ maxAliasCount: 0 }));
}
