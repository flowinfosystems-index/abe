# abe-flow

Send **only the actions Abe escalates** to Flow's judgment service, and get back a decision, a reason and a
falsifiable record.

```bash
pip install abe-ai abe-flow
export FLOW_API_KEY=fjp_live_...        # https://fjp.flowinfo.co
```

```python
import os
from abe import Abe
from abe_flow import FlowResolver

abe = Abe("abe-policy.yaml", resolver=FlowResolver(api_key=os.environ["FLOW_API_KEY"]))
r = abe.check(action={"type": "purchase", "amount": 12500}, context={"agent_id": "procurement-agent"},
               evidence={"vendor_approved": True})

r.gate_decision   # "ESCALATE"  (the Gate's own call, kept in records[0])
r.decision        # "ACT" / "BLOCK" / "ESCALATE" after Flow
r.records         # (gate record, linked Flow RESOLUTION record with Flow's own JGR inside)
```

| Gate | Flow called? | Result |
|---|---|---|
| ACT | no | ACT |
| BLOCK | no (a resolver can never loosen a BLOCK) | BLOCK |
| ESCALATE (human approval / user confirmation / evaluation failure) | no | ESCALATE |
| ESCALATE (anything else) | yes | Flow `REACH` → ACT (high/medium confidence), `SKIP` → BLOCK, `WAIT` / `RESEARCH_FIRST` / `ESCALATE` → ESCALATE |

Flow unreachable, out of credits (402), rate-limited (429), slow (timeout, default 10 s), or degraded output → the
result stays **ESCALATE** and a linked RESOLUTION record says why. Card, account, routing, IBAN, SSN, password,
token and key fields are redacted before anything leaves your process (`redact_keys=` to extend).

Report how a Flow judgment turned out (free; improves Flow's calibration):

```python
FlowResolver().report_outcome(r.resolution["resolver"]["reference"], "CORRECT")   # or WRONG / PARTIAL
```

Options: `base_url` (default `https://resolve.flowinfo.co`, env `FLOW_RESOLVER_URL`), `timeout`,
`accept_act_confidence` (default `("high", "medium")`), `redact_keys`, `include_context`, `include_evidence`.

Apache-2.0. The judgment itself runs on Flow's service; this package is only the client.
