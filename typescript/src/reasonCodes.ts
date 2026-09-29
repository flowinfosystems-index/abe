/** FJP v0.1 standard reason codes. */
export const STANDARD_REASON_CODES = [
  "POLICY_SATISFIED", "HARD_POLICY_VIOLATION", "AUTHORIZATION_FAILED", "EVIDENCE_MISSING",
  "RISK_THRESHOLD_EXCEEDED", "FINANCIAL_THRESHOLD_EXCEEDED", "HIGH_CONSEQUENCE_ACTION", "HIGH_IRREVERSIBILITY",
  "INSUFFICIENT_CONFIDENCE", "CONFLICTING_RULES", "USER_CONFIRMATION_REQUIRED", "HUMAN_APPROVAL_REQUIRED",
  "JUDGMENT_REQUIRED", "EVALUATION_FAILURE",
] as const;
export type StandardReasonCode = (typeof STANDARD_REASON_CODES)[number];

const STANDARD = new Set<string>(STANDARD_REASON_CODES);
/** Custom codes: namespace.identifier, e.g. acme.vendor_credit_risk */
export const CUSTOM_PATTERN = /^[a-z][a-z0-9_-]{0,63}\.[a-z0-9][a-z0-9_.-]{0,127}$/;
/** Escalations an automated resolver may NOT resolve by default: a human must. */
export const NOT_AUTO_RESOLVABLE = ["EVALUATION_FAILURE", "HUMAN_APPROVAL_REQUIRED", "USER_CONFIRMATION_REQUIRED"];

export const DEFAULT_FOR_DECISION = { ACT: "POLICY_SATISFIED", BLOCK: "HARD_POLICY_VIOLATION", ESCALATE: "JUDGMENT_REQUIRED" } as const;

export function isValidReasonCode(code: unknown): code is string {
  return typeof code === "string" && (STANDARD.has(code) || CUSTOM_PATTERN.test(code));
}
