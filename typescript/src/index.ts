/**
 * abe-ai — Abe is one control point before an AI agent acts.
 * Deterministic ACT / BLOCK / ESCALATE plus an immutable Judgment-Grounded Record. Local, offline, no account.
 */
export { Gate, Gate as Abe, normalizeRequest, MODES, type Mode, type FJPRequest, type GateOptions, type GateResult, type Resolver } from "./gate.js";
export { replay, loadCases, formatReport, ReplayInputError, type ReplayCase, type ReplayReport } from "./replay.js";
export { loadPolicy, parsePolicy, type Policy, type Decision, LEVELS, DECISIONS } from "./policy.js";
export { type JGR, type Resolution, type Signer, verifyHash, computeRecordHash, evaluateFalsifier, OUTCOME_STATUSES, type OutcomeStatus } from "./records.js";
export { MemoryStore, FileStore, CallbackStore, storeFromUri, type RecordStore } from "./stores.js";
export { Ed25519Signer, generateKeyPair, verifySignature } from "./signing.js";
export { canonicalJson, hashValue } from "./canonical.js";
export { STANDARD_REASON_CODES, isValidReasonCode } from "./reasonCodes.js";
export { FJPError, PolicyError, RequestError, EvaluationError, RecordImmutableError, SigningError } from "./errors.js";
export { createGateServer, serve } from "./server.js";
export * as conformance from "./conformance.js";
export * as fjpConf from "./fjpConf.js";
export { VERSION } from "./version.js";
export const ACT = "ACT", BLOCK = "BLOCK", ESCALATE = "ESCALATE";
