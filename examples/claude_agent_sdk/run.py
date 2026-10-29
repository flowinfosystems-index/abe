"""Abe gating a Claude Agent SDK agent: one PreToolUse hook, every tool call checked.

    pip install "abe-ai[claude]"
    python run.py                 # offline: replays six tool calls through the hook (no key, no network)
    python run.py --live          # a real Claude agent (needs ANTHROPIC_API_KEY or a logged-in Claude Code)
    python run.py --live --flow   # escalations go to Flow first (needs FLOW_API_KEY and "abe-ai[flow]")
"""
import argparse
import asyncio
import os
import tempfile

from abe import Abe
from abe.integrations.claude_agent_sdk import AbeHooks, abe_hooks
from abe.stores import SQLiteStore

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY = os.path.join(HERE, "abe-policy.yaml")
ACTION_TYPES = {"mcp__shop__buy": "purchase"}   # reuse the purchasing rules for the shop tool


def make_abe(use_flow: bool) -> Abe:
    resolver = None
    if use_flow:
        from abe_flow import FlowResolver
        resolver = FlowResolver(api_key=os.environ["FLOW_API_KEY"])
    return Abe(POLICY, resolver=resolver, store=SQLiteStore(os.path.join(HERE, "abe-records.db")))


async def offline(abe: Abe) -> None:
    """What the SDK sends the hook, and what Abe answers. No model, no network."""
    hooks = AbeHooks(abe, agent_id="ops-agent", action_types=ACTION_TYPES, escalate="defer")
    calls = [
        ("Read", {"file_path": "/work/README.md"}),
        ("Bash", {"command": "ls -la"}),
        ("Bash", {"command": "rm -rf /work/build"}),
        ("Write", {"file_path": "/work/notes/summary.md", "content": "..."}),
        ("mcp__shop__buy", {"sku": "LAPTOP-14", "amount": 12_500, "vendor": "acme"}),
        ("mcp__shop__buy", {"sku": "SERVER-RACK", "amount": 250_000, "vendor": "acme"}),
    ]
    for i, (tool, tool_input) in enumerate(calls):
        tid = f"toolu_{i}"
        out = await hooks.pre_tool_use({"hook_event_name": "PreToolUse", "session_id": "demo", "cwd": "/work",
                                        "transcript_path": "", "tool_name": tool, "tool_input": tool_input,
                                        "tool_use_id": tid}, tid, None)
        spec = out.get("hookSpecificOutput") or {}
        decision = spec.get("permissionDecision", "(runs)")
        print(f"{tool:<16} {str(tool_input)[:44]:<46} {decision:<7} {spec.get('permissionDecisionReason', '')}")
        if decision == "(runs)":
            await hooks.post_tool_use({"tool_use_id": tid}, tid, None)   # the SDK calls this after the tool ran


async def live(abe: Abe) -> None:
    from claude_agent_sdk import (ClaudeAgentOptions, ResultMessage, create_sdk_mcp_server, query, tool)

    @tool("buy", "Buy an item from the company vendor catalog", {"sku": str, "amount": float, "vendor": str})
    async def buy(args):
        return {"content": [{"type": "text", "text": f"Ordered {args['sku']} for ${args['amount']:,.0f}"}]}

    work = tempfile.mkdtemp(prefix="abe-claude-")
    os.makedirs(os.path.join(work, "build"))
    os.makedirs(os.path.join(work, "notes"))
    options = ClaudeAgentOptions(
        cwd=work,
        mcp_servers={"shop": create_sdk_mcp_server("shop", tools=[buy])},
        allowed_tools=["Read", "Glob", "Grep", "Bash", "Write", "mcp__shop__buy"],
        hooks=abe_hooks(abe, agent_id="ops-agent", action_types=ACTION_TYPES, escalate="defer"),
        max_turns=12,
    )
    prompt = ("You are an ops assistant in this folder. Do each step as its own tool call, and if a step is refused, report why and continue. 1) Delete the build directory with rm -rf. "
              "2) Write a one-line status note to notes/status.md with the Write tool. "
              "3) Order 5 laptops (sku LAPTOP-14) from vendor acme for a total of 12500 dollars using the buy tool.")
    async for msg in query(prompt=prompt, options=options):
        if isinstance(msg, ResultMessage):
            print("\nClaude:", (msg.result or "").strip()[:600])
            for d in msg.permission_denials or []:
                print("Denied by Abe:", d)
            if msg.deferred_tool_use:
                d = msg.deferred_tool_use
                print(f"\nHeld for a person (escalate='defer'): {d.name} {d.input}")
                print("Approve it in your own queue, then resume the session to let it run.")
    print(f"\nRecords: {os.path.join(HERE, 'abe-records.db')}   Workspace: {work}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="run a real Claude agent")
    ap.add_argument("--flow", action="store_true", help="send escalations to Flow first (FLOW_API_KEY)")
    a = ap.parse_args()
    gate = make_abe(a.flow)
    asyncio.run(live(gate) if a.live else offline(gate))
