# FJP Gate v0.1 — Specification

**Status:** v0.2.0 · 2026-09-30 · Flow Information Systems (v0.2 adds shadow mode §7.1 and replay §9)
**Canonical URI:** https://fjp.flowinfo.co/abe/spec
**Conformance:** FJP-CONF v0.1, Gate profile (`abe conformance`)
**Reference implementation:** **Abe** — *Act. Block. Escalate.* (`pip install abe-ai` · `npm install abe-ai`)

> **FJP Gate is one control point before an AI agent acts.**
> It answers one question: *can this action be resolved deterministically, or does it require judgment?*

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

---

## 1. Scope

A Gate evaluates a **proposed** action before execution and returns exactly one of:

| Decision | Meaning | The agent |
|---|---|---|
| `ACT` | The deterministic policy found no reason to prevent or escalate. It does **not** mean the action is optimal. | may execute exactly as evaluated |
| `BLOCK` | A deterministic rule clearly forbids the action. | MUST NOT execute |
| `ESCALATE` | Rules conflict, evidence is missing, consequence/irreversibility/risk is high, confidence is low, approval is required, or judgment is required. **Not an error.** | MUST NOT execute until resolved |

A Gate MUST run entirely in the caller's environment, MUST NOT require any network call, account, or model, and MUST NOT
contain contextual judgment. Judgment belongs above the Gate (§11).

## 2. Request

Minimum: `{"action": {"type": "<string>"}}`. Full shape (`schemas/fjp-request.schema.json`):

```json
{
  "protocol": "FJP", "version": "0.1", "request_id": "req_...",
  "actor":   { "agent_id": "...", "principal_id": "...", "organization_id": "..." },
  "action":  { "type": "purchase", "...domain fields...": "..." },
  "context": { "current_time": "2026-09-29T16:00:00Z", "...": "..." },
  "evidence": { "...": "..." },
  "confidence": 0.91,
  "risk": { "level": "HIGH" }, "irreversibility": { "level": "MEDIUM" },
  "metadata": {}
}
```

- Domain-specific fields are allowed inside `action`, `context`, `evidence`, `metadata`. One protocol serves finance,
  travel, software and physical agents.
- `actor.*` MAY be supplied in `context.agent_id` / `context.principal_id` / `context.organization_id`.
- `action.directive` and `action.judgment_ref` are reserved (they are written into records).
- `confidence` is caller-supplied, stored as evidence, and MUST NOT be treated as calibrated.
- Time: the Gate uses `context.current_time` (or `context.time`) when present; otherwise system time, and the record
  says which (`time_source`). Accepted format: RFC 3339 with offset, years 1970–9999.
- Limits: canonical request ≤ 256 KiB, nesting ≤ 32, integral numbers within ±(2^53−1), no NaN/Infinity.

## 3. Response

```json
{ "protocol": "FJP", "version": "0.1", "decision": "ESCALATE", "reason_code": "FINANCIAL_THRESHOLD_EXCEEDED",
  "risk_level": "HIGH", "record_id": "jgr_01M...", "timestamp": "2026-09-29T16:00:00.000Z",
  "matched_rules": ["wire_review"], "missing_evidence": [] }
```

When a resolver changed the result, the response also carries `original_gate_decision`, `gate_record_id` and
`resolution`. `risk_level` is `UNSPECIFIED` when neither the request nor the policy sets one.

## 4. Policy (`schemas/fjp-policy.schema.json`)

YAML (YAML 1.2 core schema) or JSON. `version: "0.1"` is required and MUST be a string.

| Section | Purpose |
|---|---|
| `defaults.unmatched` | Decision when nothing matches. Default `ESCALATE` / `JUDGMENT_REQUIRED` (fail closed). |
| `authorization` | `default: deny|allow`; `agents.<agent_id>.allow/deny` lists of action types (`*` = all). Failure → `BLOCK` / `AUTHORIZATION_FAILED`. |
| `rules[]` | `{id, description?, when, decision, reason_code?}` |
| `judgment_required[]` | First-class judgment boundary: `- action.type: terminate_employee` or `- when: <condition>`. → `ESCALATE` / `JUDGMENT_REQUIRED`. |
| `evidence_requirements[]` | `{id, when?, require: [paths], missing_decision: ESCALATE|BLOCK, reason_code}` |
| `risk`, `irreversibility` | `defaults.level`, `mappings[{when, level}]`, `escalate_at[]`, `block_at[]` |
| `confidence` | `minimum_to_act`, `below_minimum {decision, reason_code}`, `when_missing: ignore|escalate` |
| `resolver` | `enabled`, `not_resolvable` (reason codes a resolver may never resolve; default human approval, user confirmation, evaluation failure) |
| `records.falsifier_horizon_days` | Default 30 |

**Conditions:** leaf `{field, op, value}` or `{all: [...]}`, `{any: [...]}`, `{not: ...}`.
**Operators:** `eq neq gt gte lt lte in not_in exists not_exists contains`.
**Fields** MUST start with `actor. action. context. evidence. risk. irreversibility. confidence metadata.`

Semantics (identical in every conforming implementation):
- Equality is strict JSON equality (`true ≠ 1`, `"1" ≠ 1`, `1 = 1.0`).
- A missing or null field never matches, except `not_exists`.
- `gt/gte/lt/lte` compare two numbers, or two strings by UTF-16 code units (ISO-8601 UTC timestamps in one format
  compare chronologically). Any other pairing is an evaluation error.
- `contains`: substring for strings, membership for lists; otherwise an evaluation error.

Loading MUST fail (before any evaluation) on: unknown keys, unknown operators, field roots outside the list above,
invalid reason codes, duplicate rule ids, duplicate YAML keys, YAML anchors/aliases, non-JSON YAML tags, NaN/Infinity.

## 5. Evaluation

1. authorization → 2. rules (policy order) → 3. judgment_required → 4. evidence → 5. risk → 6. irreversibility → 7. confidence.

Every matching item is a **finding** `{id, source, decision, reason_code}`. Risk and irreversibility levels are the
**higher** of the caller-supplied level and the policy-mapped level: callers can raise risk, never lower it.

**Precedence:** `BLOCK > ESCALATE > ACT`.
- `BLOCK` if any finding is BLOCK; reason = first BLOCK finding.
- `ESCALATE` if any finding is ESCALATE; reason = `CONFLICTING_RULES` if both an ACT **rule** and an ESCALATE **rule**
  matched, else the first ESCALATE finding in the order above.
- `ACT` if only ACT findings; reason = first ACT rule's reason (default `POLICY_SATISFIED`).
- No findings → `defaults.unmatched`.

All findings appear in the record (`matched_rules`, `rule_results`, `reason_codes`).

**Fail closed.** If the request cannot be parsed safely or any rule cannot be evaluated, the Gate MUST return
`ESCALATE` / `EVALUATION_FAILURE` with a record, and MUST NOT throw to the caller or return `ACT`. If a configured record
store cannot persist the record, the result is `ESCALATE` / `EVALUATION_FAILURE`. An invalid **policy** is rejected at
Gate construction (startup).

## 6. Reason codes

Standard: `POLICY_SATISFIED HARD_POLICY_VIOLATION AUTHORIZATION_FAILED EVIDENCE_MISSING RISK_THRESHOLD_EXCEEDED
FINANCIAL_THRESHOLD_EXCEEDED HIGH_CONSEQUENCE_ACTION HIGH_IRREVERSIBILITY INSUFFICIENT_CONFIDENCE CONFLICTING_RULES
USER_CONFIRMATION_REQUIRED HUMAN_APPROVAL_REQUIRED JUDGMENT_REQUIRED EVALUATION_FAILURE`.
Custom: `namespace.identifier` (e.g. `acme.vendor_credit_risk`, `flow.reach`, `judd.instead`).

## 7. Judgment-Grounded Record (`schemas/jgr.schema.json`)

Every evaluation produces a record. It carries the Gate fields **and** the four FJP-CONF v0.1 components, so every
Gate record is also a valid FJP-CONF JGR at L0–L2.

| Field | |
|---|---|
| `protocol`, `version`, `fjp_conf_version`, `implementation_version`, `producer` | versioning |
| `record_id` (`jgr_<ULID>`), `request_id`, `root_record_id`, `parent_record_id`, `event_type` | identity and linking; `event_type` ∈ `DECISION RESOLUTION OUTCOME` |
| `timestamp`, `expires_at`, `evaluation_time`, `time_source` | time |
| `actor`, `action` (proposed action + FJP-CONF `directive`, `judgment_ref`) | who/what |
| `decision`, `reason_code`, `reason_codes`, `matched_rules`, `rule_results` | the result |
| `risk`, `irreversibility`, `evidence_present`, `evidence_missing`, `confidence` | inputs as evaluated |
| `policy {id, version, hash, format_version}`, `request_hash` | exactly which rules and which request |
| `resolver {type: FJP_GATE, implementation, version}` | who decided |
| `signal`, `judgment`, `action`, `falsifier` | FJP-CONF components |
| `record_hash`, `signature?` | integrity |

**Canonical JSON:** keys sorted by UTF-16 code units, no whitespace, `JSON.stringify` string escaping, ECMAScript number
formatting. Test vectors: `conformance/fixtures/canonical.json`.
**`policy.hash`** = sha256 of the canonical JSON of the parsed policy. **`request_hash`** = sha256 of the canonical
normalized request without `request_id`.
**`record_hash`** = sha256 of the canonical record without `record_hash`, `signature` and `falsifier.status` (the one
field FJP-CONF defines as re-evaluable).
**Signature (optional):** Ed25519 over the ASCII bytes of `record_hash`; `{algorithm: "ed25519", key_id, value(base64)}`.
Keys are local PEM files. Signing MUST NOT require Flow infrastructure.

**Immutability.** A record MUST NOT change after creation. New events are appended as linked records
(`parent_record_id`, `root_record_id`): `RESOLUTION` (a resolver's result) and `OUTCOME`
(`executed failed reverted cancelled approved rejected`). The Gate record is never overwritten.

**Control falsifiers.** Each record states the condition that would prove it wrong, checkable from linked records:

| Record | Triggered when |
|---|---|
| ACT | an OUTCOME reports `failed`/`reverted`, or `executed` with a different `request_hash` |
| BLOCK | an OUTCOME reports `executed` (the action ran despite BLOCK) |
| ESCALATE | an OUTCOME reports `executed` before an ACT RESOLUTION or an `approved` OUTCOME |
| RESOLUTION | the resolver's own falsifier (e.g. Flow's counter-signal); default: failed/reverted outcome |

Status is `open` until triggered, or `expired` once the action completed as asserted or `expires_at` passes.

### 7.1 Shadow mode

A Gate MAY run in **shadow mode** (`mode: "shadow"`; CLI `--shadow` or `ABE_MODE=shadow`) so a team can compare its
decisions with the people who approve actions today, before letting it enforce.

- Evaluation MUST be identical to enforce mode: same `decision`, `reason_code`, `matched_rules`, `request_hash`,
  and the same result, response and CLI exit code. Shadow mode never lets an action run that enforce mode would stop.
- Every record created in shadow mode (DECISION, RESOLUTION, OUTCOME) carries `"mode": "shadow"`. Enforce-mode records
  carry no `mode` field, so they are byte-identical to v0.1. Responses add `"mode": "shadow"`.
- `action.directive` begins `SHADOW: not enforced.` and names the decision the Gate would have made.
- Resolvers are still consulted, so their calls can be compared too (a Flow resolver still uses credits).
- The falsifier asserts agreement with the people handling the action, reported as linked OUTCOME records:

| Shadow record | Triggered (people disagreed) when an OUTCOME reports |
|---|---|
| ACT | `rejected`, `cancelled`, `failed` or `reverted` |
| BLOCK | `approved` or `executed` |
| ESCALATE | `executed` with `details.human_reviewed: false` (review was unnecessary) |

Any other outcome settles the record as `expired` (agreement). Agreement rate = settled records not triggered.

## 8. Storage and telemetry

Default: no storage; the record is returned to the caller. Optional append-only stores: memory, JSON Lines file,
SQLite (update/delete blocked by triggers), Postgres, MongoDB, callback. A Gate MUST work with telemetry off, no
network and no Flow account, and MUST NOT call home. Any future telemetry MUST be explicit opt-in.

## 9. Interfaces

- **Library:** `Gate(policy).check(...)` (Python, sync) / `await new Gate({policy}).check(...)` (TypeScript).
- **CLI:** `abe init | check | validate-policy | validate-record | conformance | serve | mcp | keygen | outcome`.
  `abe check` exits 0 ACT, 10 BLOCK, 20 ESCALATE.
- **Replay:** `abe replay CASES [--policy P] [--baseline B] [--fail-on-change] [--json [--all]]` evaluates saved
  requests (`.jsonl`, `.json`, or a directory) and reports decision counts, changes against a baseline policy, and
  mismatches against an optional `expected` decision per case (`{"id", "request", "expected"}`). No store, signer,
  resolver or network. Exits 1 on any expected mismatch (or any change with `--fail-on-change`), 2 on bad input.
  Python and TypeScript produce identical JSON reports.
- **HTTP (local):** `abe serve` — `POST /v1/check`, `POST /v1/outcome`, `GET /v1/records/{id}`,
  `POST /v1/records/{id}/evaluate`, `GET /healthz` (includes `mode`). Binds `127.0.0.1`; any other interface requires `--allow-remote`
  and a bearer token.
- **MCP:** `abe mcp` — tools `fjp_check_action`, `fjp_report_outcome`, `fjp_get_record`, with agent instructions:
  *call before consequential actions; never execute on BLOCK; follow the escalation path on ESCALATE.*

## 10. Security

No `eval`, no executable policy code, strict validation, bounded inputs, safe YAML, canonical serialization, no
outbound network from the core package, no secrets stored by default, fail closed.

## 11. Resolvers (above the Gate)

`resolve(request, gate_result) -> Resolution | null`. Called **only** for `ESCALATE`, never for `ACT` or `BLOCK` — a
resolver can never loosen a BLOCK. Escalations whose reasons include any `resolver.not_resolvable` code are never
sent. A resolver may return `ACT`, `BLOCK` or `ESCALATE`; anything else, an exception, or a timeout leaves the
result `ESCALATE` with a `RESOLUTION` record marked `unavailable`. The Gate MUST never fail because a resolver is
unavailable.

**Flow resolver** (`abe-flow`): sends the redacted escalation to Flow's judgment service
(`POST https://resolve.flowinfo.co/api/v1/tools/judge`) and maps Flow's verbs:
`REACH → ACT` (high/medium confidence only), `SKIP → BLOCK`, `WAIT | RESEARCH_FIRST | ESCALATE → ESCALATE`.
Degraded output (no Flow record) is never acted on. Flow's own JGR is preserved verbatim in the RESOLUTION record
(`external_record`) with its reason, confidence and falsifier. Only escalations create Flow cost.

## 12. Conformance — FJP-CONF v0.1 Gate profile

| Level | Requires |
|---|---|
| L0 | Valid request/response; canonical JSON vectors; pinned policy hash |
| L1 | Golden ACT/BLOCK/ESCALATE fixtures (`conformance/fixtures/decisions.json`); fail-closed never ACTs |
| L2 | Every record passes FJP-CONF v0.1 L0–L2 and carries the Gate fields |
| L3 | Hash verification and tamper detection, immutability, append-only store, reproducibility, linked outcomes, falsifier re-evaluation (FJP-CONF L3 adapter), policy hash in every record, **no network** |

Third-party implementations are welcome. Claims take the form *"Conforms to FJP-CONF v0.1 Gate profile, Level 3"*
and MUST be reproducible with the published fixtures. "FJP Compatible" requires L3. See `TRADEMARKS.md`.

## 13. Out of scope for v0.1

LLM calls, web browsing, vector databases, UIs, orchestration, workflow builders, billing, hosted policy management,
dashboards, RBAC, approval UIs, analytics, automatic risk or consequence inference, robotics or insurance integrations.
