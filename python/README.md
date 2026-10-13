# Abe (Python) — `pip install abe-ai`

<!-- mcp-name: io.github.flowinfosystems-index/abe -->

<p align="left"><img src="https://raw.githubusercontent.com/flowinfosystems-index/abe/main/docs/abe-mascot.png" width="160" alt="Abe, a friendly traffic light giving a thumbs up"></p>

### Act. Block. Escalate.

**Abe is a free, open-source guardrail that checks every AI agent action before it happens.**

Your agent is about to pay an invoice, buy servers, delete a table or email a customer. Abe checks the action
against your rules in under a millisecond, on your machine, and answers **`ACT`**, **`BLOCK`** or **`ESCALATE`**,
with a tamper-evident record of why.

<a href="https://www.youtube.com/watch?v=ctE8Kz9a6W0"><img src="https://img.youtube.com/vi/ctE8Kz9a6W0/hqdefault.jpg" width="480" alt="Watch the demo: an AI agent tries to spend $12,500 twice"></a>

▶ **[Watch the 40-second demo](https://www.youtube.com/watch?v=ctE8Kz9a6W0)**: an AI agent tries to spend $12,500 twice. Rules
decide the easy calls; Flow catches the duplicate and approves the real renewal. ([Run it yourself](https://github.com/flowinfosystems-index/abe/tree/main/examples/demo))

## Free. Really.

Apache-2.0. **No account, no API key, no network, no model, no usage limits.** Every check runs on your machine,
at no cost, forever.

## Why teams put Abe in front of their agents

- **Stops expensive mistakes**: duplicate payments, over-budget purchases, force-pushes to `main`, `DROP TABLE` in production.
- **Same answer every time**: plain YAML rules you can read, test, and replay against past decisions before going live.
- **Proof for auditors**: every decision gets a hash-verified record (optionally Ed25519-signed) showing which rule fired and why.
- **Works with any agent**: Python, TypeScript, a local HTTP sidecar, Docker, or MCP (Claude, Cursor and other MCP clients).
- **No-risk rollout**: shadow mode runs beside your current approval process and shows where Abe would agree.
- **Fails closed**: bad input or a broken rule returns `ESCALATE`, never `ACT`.

## Pay only for the close calls (optional)

When rules can't decide, Abe returns `ESCALATE`. By default that goes to a person. Add `--resolver flow` and only
that action is sent to [Flow](https://fjp.flowinfo.co/abe#escalate) (redacted), which returns a decision, a reason, and what
would prove it wrong, for about $0.03 to $0.05 each. `ACT` and `BLOCK` never leave your machine. See "When rules aren't enough" below.

## Quick start

```bash
pip install abe-ai            # or: npm install abe-ai
abe init                      # writes abe-policy.yaml + request.json
abe check request.json
```
```text
Decision: ESCALATE
Reason: FINANCIAL_THRESHOLD_EXCEEDED
Rules: purchase_review_limit
Risk: MEDIUM
Record: jgr_01M3Q4...
```

## Python

```python
from abe import Abe

abe = Abe("abe-policy.yaml")

result = abe.check(
    action={"type": "wire_transfer", "amount": 50000},
    context={"agent_id": "finance-agent"},
)

if result.decision == "ACT":
    ...                                   # execute exactly as evaluated
elif result.decision == "BLOCK":
    ...                                   # do not execute; tell the user result.reason_code
else:  # ESCALATE
    ...                                   # hold; ask a human, or let a resolver decide

result.record.to_dict()                   # the Judgment-Grounded Record (store it, ship it to your SIEM)
```

## TypeScript

```typescript
import { Abe } from "abe-ai";

const abe = new Abe({ policy: "./abe-policy.yaml" });
const result = await abe.check({
  action: { type: "purchase", amount: 12500, currency: "USD" },
  context: { agent_id: "procurement-agent", principal_id: "user_123" },
});
console.log(result.decision);             // "ESCALATE"
```

## A policy

```yaml
version: "0.1"
defaults: { unmatched: ESCALATE }           # nothing matched -> needs judgment (fail closed)
rules:
  - id: purchase_hard_limit
    when: { all: [ { field: action.type, op: eq, value: purchase }, { field: action.amount, op: gt, value: 100000 } ] }
    decision: BLOCK
    reason_code: HARD_POLICY_VIOLATION
  - id: purchase_review_limit
    when: { all: [ { field: action.type, op: eq, value: purchase }, { field: action.amount, op: gt, value: 10000 } ] }
    decision: ESCALATE
    reason_code: FINANCIAL_THRESHOLD_EXCEEDED
  - id: routine_purchase
    when: { all: [ { field: action.type, op: eq, value: purchase }, { field: action.amount, op: lte, value: 500 } ] }
    decision: ACT
judgment_required:
  - action.type: terminate_employee
```

Also: authorization per agent, required evidence, risk and irreversibility thresholds, confidence minimums.
`BLOCK` beats `ESCALATE` beats `ACT`. Bad input or a broken rule returns `ESCALATE` / `EVALUATION_FAILURE`, never `ACT`.
Full reference: [SPEC.md](https://github.com/flowinfosystems-index/abe/blob/main/SPEC.md).

## Every way to run it

| | |
|---|---|
| Library | `pip install abe-ai` · `npm install abe-ai` |
| CLI | `abe check · replay · validate-policy · validate-record · conformance · keygen` |
| Local HTTP sidecar | `abe serve --policy abe-policy.yaml` → `POST http://127.0.0.1:8787/v1/check` (any language) |
| Docker sidecar | `docker run -e ABE_TOKEN=… -v $PWD:/policy:ro -p 127.0.0.1:8787:8787 ghcr.io/flowinfosystems-index/abe` |
| MCP server | `pip install "abe-ai[mcp]"` → `abe mcp --policy /abs/abe-policy.yaml` (tool: `fjp_check_action`) |
| + Flow on escalations | `pip install "abe-ai[flow]"`, then add `--resolver flow` (or `ABE_RESOLVER=flow`) with `FLOW_API_KEY` to `check`, `serve` or `mcp` |

## Records you can audit

Every call returns a record with the decision, every matched rule, the **exact policy hash**, the **request hash**,
and a SHA-256 `record_hash` (optionally Ed25519-signed with `abe keygen`). Records never change: outcomes and
resolutions are appended as linked records. Each one is a valid FJP-CONF v0.1 Judgment-Grounded Record.

```bash
abe check request.json --record-out jgr.json --sign-key abe-signing-key.pem
abe validate-record jgr.json --public-key abe-signing-key.pub.pem
```

## When rules aren't enough: Flow

Abe is deliberately useful without Flow. When it returns `ESCALATE`, you can hand that one action to
[Flow's judgment service](https://fjp.flowinfo.co) and get a verb, a reason and a falsifiable record back:

```python
from abe import Abe
from abe_flow import FlowResolver                     # pip install abe-flow

abe = Abe("abe-policy.yaml", resolver=FlowResolver(api_key=os.environ["FLOW_API_KEY"]))
```

No code needed for the CLI, sidecar or MCP server (`pip install "abe-ai[mcp,flow]"`):

```json
{"mcpServers": {"abe": {"command": "abe",
  "args": ["mcp", "--policy", "/abs/abe-policy.yaml", "--resolver", "flow"],
  "env": {"FLOW_API_KEY": "fjp_live_..."}}}}
```

`ACT` and `BLOCK` never leave your machine. Only escalations are sent (redacted), and if Flow is unreachable the
answer simply stays `ESCALATE`. Human-approval escalations are never auto-resolved.

## Conformance

```bash
abe conformance --bench        # FJP-CONF v0.1 Gate profile, Level 3 — 160 checks, offline
```

## Repository

```
SPEC.md                  the normative specification
schemas/                 JSON Schemas (request, response, record, policy)
python/                  abe-ai (PyPI): core, CLI, HTTP, MCP, stores, signing, conformance
typescript/              abe-ai (npm): same API, same records, same hashes
flow-resolver/           abe-flow (PyPI): Gate → Flow for ESCALATE only
conformance/fixtures/    golden decisions + canonical-JSON vectors shared by every SDK
examples/                the $12,500 demo, purchasing, software agent, physical agent, travel (+ Judd), Flow
```

Apache-2.0. FJP™, Abe™ (Abe) and FJP-CONF™ are trademarks of Flow Information Systems — see [TRADEMARKS.md](https://github.com/flowinfosystems-index/abe/blob/main/TRADEMARKS.md).

## Extras

| Install | Adds |
|---|---|
| `pip install abe-ai` | core, CLI, HTTP server, stores (memory, file, SQLite), conformance — one dependency (PyYAML) |
| `pip install "abe-ai[signing]"` | Ed25519 record signing (`abe keygen`, `--sign-key`) |
| `pip install "abe-ai[mcp]"` | MCP server (`abe mcp`) |
| `pip install "abe-ai[flow]"` | `--resolver flow`: send escalations to Flow (installs `abe-flow`) |
| `abe.stores.contrib` | `PostgresStore` (psycopg 3), `MongoStore` (pymongo) — bring your own driver |
