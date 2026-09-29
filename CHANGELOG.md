# Changelog

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
