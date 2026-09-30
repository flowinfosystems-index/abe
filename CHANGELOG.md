# Changelog

## 0.2.0 — 2026-09-30 (abe-ai, PyPI and npm) · abe-flow 0.1.2

- **Shadow mode.** `Gate(policy, mode="shadow")` / `new Gate({ policy, mode: "shadow" })`, `--shadow` or
  `ABE_MODE=shadow` on `check`, `serve` and `mcp`. Same decisions, results and exit codes as enforce mode; every
  record is marked `"mode": "shadow"` and its falsifier measures agreement with the people who handled the action.
  `result.enforced` is false in shadow mode. Enforce-mode records are unchanged.
- **`abe replay`.** Run saved requests through a policy before it goes live: decision counts, changes against
  `--baseline`, and mismatches against expected decisions. `--fail-on-change` for CI. Python and TypeScript
  produce identical JSON reports. Also `abe.replay()` / `replay()` in both libraries.
- Cross-language parity now also covers shadow records and replay reports.
- abe-flow 0.1.2: allows abe-ai 0.2 (`abe-ai>=0.1.0,<0.3`). No code changes.

## abe-flow 0.1.1 — 2026-09-29

- Verify TLS with certifi's CA bundle, so calls to Flow work on python.org builds for macOS without running
  "Install Certificates.command" (previously: CERTIFICATE_VERIFY_FAILED, safely staying ESCALATE).

## 0.1.0 — 2026-09-29

First release of Abe, the reference implementation of Abe.

- Deterministic ACT / BLOCK / ESCALATE with BLOCK > ESCALATE > ACT precedence and fail-closed evaluation.
- Policy: rules (11 operators, all/any/not), per-agent authorization, evidence requirements, risk and
  irreversibility thresholds (callers can raise, never lower), confidence minimums, first-class judgment boundaries.
- Judgment-Grounded Records: canonical JSON, policy hash, request hash, SHA-256 record hash, optional Ed25519
  signatures, append-only linked RESOLUTION and OUTCOME records, deterministic control falsifiers. Every record is a
  valid FJP-CONF v0.1 JGR.
- Python SDK (`abe-ai`), TypeScript SDK (`abe-ai`) with byte-identical hashes, CLI, local HTTP server,
  MCP server, stores (memory, file, SQLite, Postgres, MongoDB, callback).
- `abe-flow`: send ESCALATE results only to Flow's judgment service.
- FJP-CONF v0.1 Gate profile: 160 checks through Level 3, including no-network operation.
