// FlowResolver for abe-ai (TypeScript/Node). Copy into your project; zero dependencies (uses fetch).
// Same behavior as the Python abe-flow package: only ESCALATE results are sent to Flow.
//
//   import { Gate } from "abe-ai";
//   import { FlowResolver } from "./flow-resolver.mjs";
//   const gate = new Gate({ policy: "./abe-policy.yaml", resolver: new FlowResolver({ apiKey: process.env.FLOW_API_KEY }) });
import { createHash } from "node:crypto";

const VERB = { REACH: "ACT", SKIP: "BLOCK", WAIT: "ESCALATE", RESEARCH_FIRST: "ESCALATE", ESCALATE: "ESCALATE" };
const CONF = { high: 0.8, medium: 0.55, low: 0.3 };
const REDACT = ["card_number", "cvv", "cvc", "account_number", "routing_number", "iban", "ssn", "password", "secret", "api_key", "token", "authorization", "private_key"];

export function redact(v, keys = REDACT) {
  if (Array.isArray(v)) return v.map((x) => redact(x, keys));
  if (v && typeof v === "object")
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, keys.some((r) => k.toLowerCase().includes(r)) ? "[REDACTED]" : redact(x, keys)]));
  return v;
}

export class FlowResolver {
  constructor({ apiKey = process.env.FLOW_API_KEY, baseUrl = process.env.FLOW_RESOLVER_URL || "https://resolve.flowinfo.co",
    timeoutMs = 10_000, acceptActConfidence = ["high", "medium"], fetchImpl = globalThis.fetch } = {}) {
    if (!apiKey) throw new Error("FlowResolver needs an API key (apiKey or FLOW_API_KEY)");
    this.apiKey = apiKey; this.baseUrl = baseUrl.replace(/\/$/, ""); this.timeoutMs = timeoutMs;
    this.accept = new Set(acceptActConfidence); this.fetch = fetchImpl;
  }

  async resolve(request, gateResult) {
    const rec = gateResult.record, safe = redact(request);
    const context = [
      "PRE-EXECUTION JUDGMENT (FJP Gate escalation).",
      `The agent's proposed action passed hard policy limits but the Gate escalated it: ${rec.reason_code} (all reasons: ${rec.reason_codes.join(", ")}). Matched: ${rec.matched_rules.join(", ") || "none"}.`,
      "Question: is this permitted action justified by the evidence, intent and context? REACH = proceed, SKIP = do not proceed, WAIT = not now, RESEARCH_FIRST = establish more first, ESCALATE = a human must decide.",
      `Actor: ${JSON.stringify(safe.actor ?? {})}`, `Proposed action: ${JSON.stringify(safe.action ?? {})}`,
      `Risk: ${gateResult.riskLevel}. Irreversibility: ${gateResult.irreversibilityLevel}. Agent-supplied confidence (uncalibrated): ${safe.confidence ?? "not supplied"}.`,
      ...(gateResult.missingEvidence.length ? [`Missing evidence: ${gateResult.missingEvidence.join(", ")}.`] : []),
      ...(Object.keys(safe.evidence ?? {}).length ? [`Evidence: ${JSON.stringify(safe.evidence)}`] : []),
      ...(Object.keys(safe.context ?? {}).length ? [`Context: ${JSON.stringify(safe.context)}`] : []),
    ].join("\n").slice(0, 19_000);
    const res = await this.fetch(`${this.baseUrl}/api/v1/tools/judge`, {
      method: "POST", signal: AbortSignal.timeout(this.timeoutMs),
      headers: { Authorization: `Bearer ${this.apiKey}`, "Content-Type": "application/json",
        "X-Idempotency-Key": createHash("sha256").update(`${rec.request_id}|${rec.request_hash}|${rec.policy.hash}`).digest("hex") },
      body: JSON.stringify({ context, background: `Policy ${rec.policy.id ?? "unnamed"} version ${rec.policy.version ?? "unversioned"} (${rec.policy.hash}).`,
        sources: [`fjp:gate-record:${rec.record_id}`, `fjp:policy:${rec.policy.hash}`, `fjp:request:${rec.request_id}`], observed_at: rec.evaluation_time }),
    });
    if (res.status !== 200) throw new Error(`Flow returned HTTP ${res.status}`); // Gate keeps ESCALATE
    const out = await res.json();
    if (!(out.verb in VERB)) throw new Error(`Flow returned an unknown verb ${out.verb}`);
    const bucket = out.confidence in CONF ? out.confidence : "low";
    const base = { resolverType: "FLOW", implementation: "abe-flow-js", implementationVersion: "0.1.0", reference: out.request_id,
      evidence: { flow_verb: out.verb, flow_timing: out.timing, flow_confidence: bucket, flow_request_id: out.request_id } };
    if (!out.jgr) return { ...base, decision: "ESCALATE", reason: "Flow returned degraded output without a record; not acted on.", reasonCode: "flow.degraded" };
    let decision = VERB[out.verb], reason = out.framing || `Flow verb ${out.verb}.`;
    if (decision === "ACT" && !this.accept.has(bucket)) { decision = "ESCALATE"; reason = `Flow leaned REACH with ${bucket} confidence, below this resolver's bar; escalating. ` + reason; }
    const falsifier = out.jgr.falsifier?.condition || out.counter_signal;
    return { ...base, decision, reason, reasonCode: `flow.${out.verb.toLowerCase()}`, confidence: out.jgr.judgment?.confidence ?? CONF[bucket],
      falsifiers: falsifier ? [falsifier] : [], externalRecord: out.jgr };
  }
}
