# Abe (TypeScript / Node ≥ 18) — `npm install abe-ai`

> **Abe is one control point before an AI agent acts.**

It checks a proposed action against your policy and returns **`ACT`**, **`BLOCK`** or **`ESCALATE`**, plus an immutable,
hash-verified **Judgment-Grounded Record** of why. It runs entirely on your machine: no account, no API key, no
network, no model. Median evaluation time is well under a millisecond.

```bash
npm install abe-ai
npx abe init                      # writes abe-policy.yaml + request.json
npx abe check request.json
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
| CLI | `abe check · validate-policy · validate-record · conformance · keygen` |
| Local HTTP sidecar | `abe serve --policy abe-policy.yaml` → `POST http://127.0.0.1:8787/v1/check` (any language) |
| Docker sidecar | `docker run -e ABE_TOKEN=… -v $PWD:/policy:ro -p 127.0.0.1:8787:8787 ghcr.io/flowinfosystems-index/abe` |
| MCP server | `pip install "abe-ai[mcp]"` → `abe mcp --policy /abs/abe-policy.yaml` (tool: `fjp_check_action`) |

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
examples/                purchasing, software agent, physical agent, travel (+ Judd), Flow
```

Apache-2.0. FJP™, Abe™ (Abe) and FJP-CONF™ are trademarks of Flow Information Systems — see [TRADEMARKS.md](https://github.com/flowinfosystems-index/abe/blob/main/TRADEMARKS.md).

## Notes for Node

- `check()` is async; resolvers may be sync or async and are bounded by `resolverTimeoutMs` (default 15 s).
- Records are deep-frozen objects: any mutation throws `TypeError`.
- Stores: `MemoryStore`, `FileStore` (JSON Lines), `CallbackStore`, or implement `RecordStore` (save/get/linked).
- Flow for Node: copy [`examples/flow/flow-resolver.mjs`](https://github.com/flowinfosystems-index/abe/blob/main/examples/flow/flow-resolver.mjs) (zero dependencies).
- Records and hashes are byte-identical to the Python SDK (verified in CI).
