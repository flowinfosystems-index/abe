# Abe

<p align="left"><img src="https://raw.githubusercontent.com/flowinfosystems-index/abe/main/docs/abe-mascot.png" width="160" alt="Abe, a friendly traffic light giving a thumbs up"></p>

### Act. Block. Escalate.

**Abe is a free, open-source guardrail that checks every AI agent action before it happens.**

Your agent is about to pay an invoice, buy servers, delete a table or email a customer. Abe checks the action
against your rules in under a millisecond, on your machine, and answers **`ACT`**, **`BLOCK`** or **`ESCALATE`**,
with a tamper-evident record of why.

<a href="https://www.youtube.com/watch?v=ctE8Kz9a6W0"><img src="https://img.youtube.com/vi/ctE8Kz9a6W0/hqdefault.jpg" width="480" alt="Watch the demo: an AI agent tries to spend $12,500 twice"></a>

▶ **[Watch the 40-second demo](https://www.youtube.com/watch?v=ctE8Kz9a6W0)**: an AI agent tries to spend $12,500 twice. Rules
decide the easy calls; Flow catches the duplicate and approves the real renewal. ([Run it yourself](examples/demo/))

## Free. Really.

Apache-2.0. **No account, no API key, no network, no model, no usage limits.** Every check runs on your machine,
at no cost, forever.

## Why teams put Abe in front of their agents

- **Stops expensive mistakes**: duplicate payments, over-budget purchases, force-pushes to `main`, `DROP TABLE` in production.
- **Same answer every time**: plain YAML rules you can read, test, and replay against past decisions before going live.
- **Proof for auditors**: every decision gets a hash-verified record (optionally Ed25519-signed) showing which rule fired and why.
- **Works with any agent**: one line for the Claude Agent SDK, LangChain / LangGraph and the OpenAI Agents SDK; a decorator for any Python function; TypeScript, a local HTTP sidecar, Docker, or MCP (Claude, Cursor and other MCP clients).
- **No-risk rollout**: shadow mode runs beside your current approval process and shows where Abe would agree.
- **Fails closed**: bad input or a broken rule returns `ESCALATE`, never `ACT`.

## Pay only for the close calls (optional)

When rules can't decide, Abe returns `ESCALATE`. By default that goes to a person. Add `--resolver flow` and only
that action is sent to [Flow](https://fjp.flowinfo.co/abe#escalate) (redacted), which returns a decision, a reason, and what
would prove it wrong, for about $0.03 to $0.05 each. `ACT` and `BLOCK` never leave your machine. [Details below](#when-rules-arent-enough-flow).

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

**Start from a policy pack** instead of a blank file. Seven packs cover the actions agents most often get wrong:
`refunds`, `payments`, `purchasing`, `subscriptions`, `customer-email`, `deploys`, `data-changes`.

```bash
abe init --list-packs
abe init --pack refunds                                   # one pack, with a sample request that shows it working
abe init --pack payments --pack customer-email --force    # combine packs into one policy
```

Each pack is an ordinary policy: open it, change the amounts to match your business, run `abe validate-policy`.
Anything a pack doesn't recognize still ESCALATEs.

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

## Claude Agent SDK

```python
from claude_agent_sdk import ClaudeAgentOptions
from abe import Abe
from abe.integrations.claude_agent_sdk import abe_hooks

options = ClaudeAgentOptions(hooks=abe_hooks(Abe("abe-policy.yaml"), agent_id="ops-agent"))
```

Every tool call is checked before it runs. BLOCK → `deny` with Abe's reason; ESCALATE → `deny`, `ask` or `defer`
(hand it to a person); ACT → your normal permissions. Tool inputs are action fields (`action.command`,
`action.amount`). See [`examples/claude_agent_sdk`](examples/claude_agent_sdk).

## LangChain and LangGraph

```python
from langchain.agents import create_agent
from abe.integrations.langchain import AbeMiddleware

agent = create_agent(model, tools, middleware=[AbeMiddleware(Abe("abe-policy.yaml"), agent_id="ops-agent")])
```

Every tool call is checked before it runs. BLOCK and ESCALATE return an error `ToolMessage` with Abe's reason, so
the model can pick another approach. `escalate="interrupt"` pauses the graph instead so a person can approve
(`Command(resume="approve")`). Needs LangChain 1.0+: `pip install "abe-ai[langchain]"`.

## OpenAI Agents SDK

```python
from agents import Agent
from abe.integrations.openai_agents import gate_tools

agent = Agent(name="ops", tools=gate_tools(Abe("abe-policy.yaml"), [pay_invoice, delete_rows]))
```

Adds an Abe tool guardrail to each function tool. BLOCK and ESCALATE replace the tool result with Abe's reason;
`escalate="raise"` stops the run so your code can hand the call to a person. `pip install "abe-ai[openai-agents]"`.

## Any Python function

```python
from abe.integrations.guard import guard

@guard(abe, action_type="purchase", agent_id="procurement-agent")
def buy(item: str, amount: float) -> str:
    ...
```

The call's arguments become action fields. BLOCK raises `AbeBlocked`, ESCALATE raises `AbeEscalated`, or pass
`on_deny="return"` to hand Abe's reason back as the result. Keeps the function's name, docstring and signature,
so framework tool decorators that read them (LangChain `@tool`, for one) still work on top of it.

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
Full reference: [`SPEC.md`](SPEC.md).

## Test before you enforce

**Replay** saved requests through a policy before it touches real money. Label each case with what your people
decided and Abe reports where it disagrees; compare against the live policy to see exactly which decisions a change moves.

```bash
# cases.jsonl: one request per line, or {"id": "inv-1042", "request": {...}, "expected": "BLOCK"}
abe replay cases.jsonl --policy new-policy.yaml --baseline abe-policy.yaml
#   Replayed 1204 case(s) against ...      ACT 1088   BLOCK 31   ESCALATE 85
#   Changed vs baseline: 3                 inv-1042: ACT -> ESCALATE  [purchase_review_limit]
#   Agreement with expected: 1198/1204 (99.5%)
abe replay cases.jsonl --policy new-policy.yaml --baseline abe-policy.yaml --fail-on-change   # CI: exit 1 if anything moved
```

**Replay your agent's own logs** to see what Abe would have stopped, before you install anything in the agent.
`abe replay` reads tool calls straight from OpenAI (Chat Completions and Responses), Anthropic, LangChain and Claude
Code hook logs, plus plain `{"tool": ..., "args": ...}` lines. Each call's arguments become action fields.

```bash
abe init --pack refunds --pack payments
abe replay last-month.jsonl --policy abe-policy.yaml --action-type mcp__stripe__create_refund=refund
#   Replayed 1,204 case(s) against pack-refunds-payments ...   ACT 1,131   BLOCK 6   ESCALATE 67
#     Amounts held back: $61,400 blocked, $388,250 escalated (sum of action.amount)
#   Would have stopped: 73
#     call_8f2: ESCALATE wire_transfer $48,000  FINANCIAL_THRESHOLD_EXCEEDED  [payment_review, new_or_changed_payee]
#     toolu_19: BLOCK refund $9,000  HARD_POLICY_VIOLATION  [refund_hard_limit]
```

Nothing is stored or sent anywhere. `--action-type TOOL=TYPE` maps your tool names onto the pack's action types;
calls no rule matches are listed so you know which tools still need a rule.

**Shadow mode** runs Abe beside your current approval process. Decisions, results and exit codes are exactly what
enforce mode would return, and every record is marked `"mode": "shadow"`. Keep approving the way you do today,
report what your people decided, and each record's falsifier shows whether they agreed.

```python
from abe.stores import SQLiteStore

abe = Abe("abe-policy.yaml", mode="shadow", store=SQLiteStore("abe.db"))    # or: abe serve --shadow · ABE_MODE=shadow
r = abe.check(action={"type": "purchase", "amount": 48000}, context={"agent_id": "ap-agent"})
# ... your existing approval happens ...
abe.record_outcome(r.records[0], "approved")    # people approved; if Abe said BLOCK, the falsifier triggers
```

When the agreement rate is where you want it, drop `mode="shadow"` and Abe enforces.

## Every way to run it

| | |
|---|---|
| Library | `pip install abe-ai` · `npm install abe-ai` |
| CLI | `abe check · replay · validate-policy · validate-record · conformance · keygen` |
| Local HTTP sidecar | `abe serve --policy abe-policy.yaml` → `POST http://127.0.0.1:8787/v1/check` (any language) |
| Docker sidecar | `docker run -e ABE_TOKEN=… -v $PWD:/policy:ro -p 127.0.0.1:8787:8787 ghcr.io/flowinfosystems-index/abe` |
| Claude Agent SDK hook | `pip install "abe-ai[claude]"` → `ClaudeAgentOptions(hooks=abe_hooks(abe))` ([example](examples/claude_agent_sdk)) |
| LangChain / LangGraph | `pip install "abe-ai[langchain]"` → `create_agent(..., middleware=[AbeMiddleware(abe)])` |
| OpenAI Agents SDK | `pip install "abe-ai[openai-agents]"` → `Agent(tools=gate_tools(abe, tools))` |
| Any Python function | `@guard(abe, action_type="purchase")` |
| MCP server | `pip install "abe-ai[mcp]"` → `abe mcp --policy /abs/abe-policy.yaml` (tool: `fjp_check_action`) |
| + Flow on escalations | add `--resolver flow` (or `ABE_RESOLVER=flow`) with `FLOW_API_KEY` to `check`, `serve`, `mcp` or the Docker image |

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

No Python? The CLI, sidecar and MCP server take the same resolver (`pip install "abe-ai[mcp,flow]"`):

```json
{"mcpServers": {"abe": {"command": "abe",
  "args": ["mcp", "--policy", "/abs/abe-policy.yaml", "--resolver", "flow"],
  "env": {"FLOW_API_KEY": "fjp_live_..."}}}}
```

`abe serve --resolver flow` and `docker run -e ABE_RESOLVER=flow -e FLOW_API_KEY=… …` work the same way. If Flow
is out of credits, the MCP result says so and links to the refill page; the action stays `ESCALATE`.

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

Apache-2.0. FJP™, Abe™ (Abe) and FJP-CONF™ are trademarks of Flow Information Systems — see [`TRADEMARKS.md`](TRADEMARKS.md).
