# Abe + Claude Agent SDK

One `PreToolUse` hook puts Abe in front of every tool call a Claude agent makes.

```bash
pip install "abe-ai[claude]"
python run.py            # offline: six tool calls replayed through the hook, no key, no network
python run.py --live     # a real Claude agent (ANTHROPIC_API_KEY, or a logged-in Claude Code)
```

Offline output:

```
Read             {'file_path': '/work/README.md'}               (runs)
Bash             {'command': 'ls -la'}                          (runs)
Bash             {'command': 'rm -rf /work/build'}              deny    Abe BLOCK: HARD_POLICY_VIOLATION | Never delete recursively | record jgr_…
Write            {'file_path': '/work/notes/summary.md', …}     (runs)
mcp__shop__buy   {'sku': 'LAPTOP-14', 'amount': 12500, …}       defer   Abe ESCALATE: FINANCIAL_THRESHOLD_EXCEEDED | Purchases above $10,000 require judgment | record jgr_…
mcp__shop__buy   {'sku': 'SERVER-RACK', 'amount': 250000, …}    deny    Abe BLOCK: HARD_POLICY_VIOLATION | Never permit purchases above $100,000 | record jgr_…
```

In the live run Claude is asked to `rm -rf` a folder, write a note, and order $12,500 of laptops. Abe blocks the
delete (Claude is told why and carries on), lets the note through and records it as executed, and stops the run
with the purchase on `ResultMessage.deferred_tool_use` for a person to approve. Every decision is a
Judgment-Grounded Record in `abe-records.db`.

## The wiring

```python
from claude_agent_sdk import ClaudeAgentOptions
from abe import Abe
from abe.integrations.claude_agent_sdk import abe_hooks

abe = Abe("abe-policy.yaml")
options = ClaudeAgentOptions(hooks=abe_hooks(
    abe,
    agent_id="ops-agent",
    action_types={"mcp__shop__buy": "purchase"},   # reuse your purchasing rules for this tool
    escalate="defer",                               # or "deny" (default) / "ask"
))
```

| Option | Default | |
|---|---|---|
| `escalate` | `"deny"` | `"ask"` routes to your permission prompt / `can_use_tool`; `"defer"` stops the run (SDK 0.1.81+) |
| `act` | `"passthrough"` | `"allow"` also skips the SDK's own permission check for calls Abe allowed |
| `tools` / `matcher` | every tool | gate only some tools, e.g. `tools=["Bash", "mcp__stripe__create_payment"]` |
| `action_types` | none | map a tool name onto an existing `action.type` |
| `map_request` | built in | `(tool_name, tool_input, hook_input) -> FJP request` (return `None` to leave a call ungated) |
| `record_outcomes` | `True` | allowed calls get an `executed` / `failed` outcome record |
| `ungated` | `ToolSearch, TodoWrite, AskUserQuestion` | harness tools with no outside effect; `()` gates them too |

Escalations go to Flow first with `Abe(policy, resolver=FlowResolver(...))` (`python run.py --live --flow`):
only the close calls leave your machine, and Flow's ACT or BLOCK is used instead.
