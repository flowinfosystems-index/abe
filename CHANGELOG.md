# Changelog

## 0.2.5 — 2026-11-26 (abe-ai, PyPI)

- **LangChain / LangGraph middleware** (`abe.integrations.langchain.AbeMiddleware`, `pip install "abe-ai[langchain]"`).
  One line in `create_agent(..., middleware=[...])` gates every tool call. BLOCK and ESCALATE return an error
  `ToolMessage` with Abe's reason and record id; `escalate="interrupt"` pauses the graph for a person to approve.
  Allowed calls get linked `executed` / `failed` outcome records. Sync and async. Tested on LangChain 1.0 and 1.5.
- **OpenAI Agents SDK guardrails** (`abe.integrations.openai_agents.gate_tools`, `pip install "abe-ai[openai-agents]"`).
  Adds an Abe tool input guardrail (decision) and output guardrail (outcome record) to each function tool.
  `escalate="raise"` stops the run instead of rejecting. Tested on openai-agents 0.3.3 and 0.26.
- **`@guard` decorator** (`abe.integrations.guard`) for any Python function, sync or async. Arguments become action
  fields; BLOCK / ESCALATE raise `AbeBlocked` / `AbeEscalated` or, with `on_deny="return"`, return Abe's reason.
  Keeps name, docstring and signature, so LangChain's `@tool` works on top of it.
- `import abe` still imports no agent framework.

## 0.2.4 — 2026-10-29 (abe-ai, PyPI)

- **Claude Agent SDK integration** (`abe.integrations.claude_agent_sdk`, `pip install "abe-ai[claude]"`).
  `ClaudeAgentOptions(hooks=abe_hooks(abe))` gates every tool call with one `PreToolUse` hook: BLOCK becomes
  `deny` with Abe's reason and record id, ESCALATE becomes `deny` / `ask` / `defer` (your choice), ACT leaves the
  SDK's own permissions in charge. Tool inputs become action fields; `action_types` maps a tool onto an existing
  action type. Allowed calls get linked `executed` / `failed` outcome records. Shadow mode and resolvers (Flow)
  work unchanged. Harness tools with no outside effect (`ToolSearch`, `TodoWrite`, `AskUserQuestion`) are not
  gated by default (`ungated=()` to gate them).
- The core package still imports nothing from the SDK: `import abe` stays offline with one dependency.
- `examples/claude_agent_sdk/`: offline replay, or `--live` against a real Claude agent.

## 0.2.3 — 2026-10-13 (abe-ai, PyPI)

- Listed in the official MCP Registry as `io.github.flowinfosystems-index/abe` (`server.json`, ownership line in the
  PyPI page).
- `abe-ai` command, same as `abe`, so `uvx abe-ai mcp` works. No other changes.
- `Dockerfile.mcp`: the MCP server in a container, with a built-in starter policy.

## 0.2.2 — 2026-10-13 (abe-ai, PyPI)

- PyPI page: new opening (what Abe does, free, 40-second demo video), `abe replay` and `--resolver flow` listed,
  `abe-ai[flow]` in the extras table. No code changes.

## abe-flow 0.1.4 — 2026-10-13

- Flow is now told plainly that the policy owner has delegated the decision to it: the rule that routed the action
  is not by itself a reason to involve a human, with each verb defined (REACH approve, SKIP reject, ...). Live runs
  showed Flow escalating well-supported actions "because the threshold requires human sign-off".
- Flow's attribution suffix is stripped from the resolution reason, as it already was from the falsifier.
- Same wording in the copyable JS resolver (`examples/flow/flow-resolver.mjs`).
- `examples/demo/`: the $12,500 demo (terminal or Claude via MCP); reasons are shortened to fit on screen.

## 0.2.1 — 2026-10-13 (abe-ai, PyPI)

- **`--resolver flow` on `abe check`, `abe serve` and `abe mcp`** (or `ABE_RESOLVER=flow`). Sends only ESCALATE
  results to Flow Resolver, using `FLOW_API_KEY`. Previously the Flow resolver was reachable only from Python code.
  Off by default: without the flag nothing leaves the machine. Install with `pip install "abe-ai[flow]"`.
- MCP `fjp_check_action` now includes Flow's reason and falsifier in `what_to_do`, and a `resolver_help` field
  with the refill link (402) or key-reset link (401) when Flow could not answer. The action stays ESCALATE.
- `abe check` prints the resolver's status, reason and falsifier.
- npm package unchanged (stays 0.2.0).

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
