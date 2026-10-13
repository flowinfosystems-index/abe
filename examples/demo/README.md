# The $12,500 demo

Rules catch the obvious. Flow judges the close calls.

A procurement agent makes four purchases. `$120` and `$250,000` are decided by rules on your machine. Two `$12,500`
orders hit the same rule ("over $10,000 needs judgment"). One is a duplicate of yesterday's order with $3,200 of budget
left; the other is a renewal the ML lead asked for. Rules can't tell them apart. Flow can.

## Run it in a terminal

```bash
pip install "abe-ai[flow]"
export FLOW_API_KEY=fjp_live_...     # https://fjp.flowinfo.co/credits
python demo.py                       # paced for screen recording;  --fast to skip pauses
```

Without `FLOW_API_KEY` it runs rules only, and both `$12,500` orders go to a human. Flow's answers are live, not
scripted, so run it once before you record.

## Run it with Claude (MCP)

```bash
pip install "abe-ai[mcp,flow]"
```

Claude Desktop (`claude_desktop_config.json`) or any MCP client:

```json
{"mcpServers": {"abe": {"command": "abe",
  "args": ["mcp", "--policy", "/ABSOLUTE/PATH/examples/demo/abe-policy.yaml", "--resolver", "flow"],
  "env": {"FLOW_API_KEY": "fjp_live_..."}}}}
```

Claude Code: `claude mcp add abe -e FLOW_API_KEY=fjp_live_... -- abe mcp --policy /ABSOLUTE/PATH/examples/demo/abe-policy.yaml --resolver flow`

Then paste this prompt:

> You are our procurement agent. Before every purchase, check it with Abe (fjp_check_action) and follow its decision.
> Place these two orders, each as action type "purchase", amount 12500, currency USD, target "gpu-cloud-co":
>
> 1. Auto-reorder of 8x H100 nodes for 1 month. Evidence: vendor_approved true, budget_remaining_usd 3200,
>    matching_order_last_24h "PO-88412: same vendor, same item, $12,500, placed yesterday, not yet delivered",
>    requested_by "auto-reorder job (no human request)".
> 2. Renewal of 8x H100 nodes for 1 month. Evidence: vendor_approved true, budget_remaining_usd 90000,
>    current_rental_ends "in 2 days", requested_by "ML team lead, ticket ML-2291".
>
> For each, tell me Abe's decision, Flow's reason, and what would prove it wrong.

## 60-second recording

| Time | Screen | Voiceover |
|---|---|---|
| 0–8s | `python demo.py` starts | "AI agents are starting to spend money. Abe checks every action before it happens." |
| 8–18s | $120 ACT, then rules line | "Small stuff is decided by rules, locally. Nothing leaves your machine." |
| 18–38s | Duplicate $12,500 → ESCALATE → Flow BLOCK + "Wrong if" | "Over $10,000, rules can't tell. Abe asks Flow. Flow spots the duplicate order and blocks it, and says exactly what would prove it wrong." |
| 38–50s | Renewal $12,500 → Flow ACT | "Same amount, same rule. This one's a real renewal, so Flow lets it through." |
| 50–60s | $250,000 BLOCK, closing line | "Abe is free and open source. Flow only charges for the close calls. pip install abe-ai." |
