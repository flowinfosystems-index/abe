"""The $12,500 demo: rules catch the obvious, Flow judges the close calls.   python demo.py

    pip install "abe-ai[flow]"
    export FLOW_API_KEY=fjp_live_...      # https://fjp.flowinfo.co/credits  (without it: rules only)
    python demo.py            # paced for screen recording;  --fast to skip the pauses

Four purchases from a procurement agent. $120 and $250,000 are decided by rules on this machine. The two $12,500
orders hit the same rule (over $10,000 needs judgment); only those two go to Flow. Flow's answers are live, not
scripted: whatever it decides is what you see.
"""
import os
import sys
import time

from abe import Abe

HERE = os.path.dirname(os.path.abspath(__file__))
FAST = "--fast" in sys.argv
TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if TTY else s


COLOR = {"ACT": "32;1", "BLOCK": "31;1", "ESCALATE": "33;1"}


def pause(s=1.0):
    if not FAST:
        time.sleep(s)


def say(s="", wait=0.6):
    print(s, flush=True)
    pause(wait)


ORDERS = [
    ("Printer paper", {"type": "purchase", "amount": 120, "currency": "USD", "target": "office-depot"}, {}),
    ("8x GPU servers, 1-month rental (reorder)",
     {"type": "purchase", "amount": 12_500, "currency": "USD", "target": "gpu-cloud-co", "item": "8x H100 node, 1 month"},
     {"vendor_approved": True,
      "budget_remaining_usd": 3_200,
      "matching_order_last_24h": "PO-88412: same vendor, same item, $12,500, placed yesterday, not yet delivered",
      "requested_by": "auto-reorder job (no human request)"}),
    ("8x GPU servers, 1-month rental (renewal)",
     {"type": "purchase", "amount": 12_500, "currency": "USD", "target": "gpu-cloud-co", "item": "8x H100 node, 1 month"},
     {"vendor_approved": True,
      "budget_remaining_usd": 90_000,
      "current_rental_ends": "in 2 days; training run scheduled to continue",
      "requested_by": "ML team lead, ticket ML-2291",
      "vendor_on_time_rate": 0.97}),
    ("Server room buildout", {"type": "purchase", "amount": 250_000, "currency": "USD", "target": "buildout-co"}, {}),
]


def main():
    resolver = None
    if os.environ.get("FLOW_API_KEY"):
        from abe_flow import FlowResolver   # pip install "abe-ai[flow]"
        resolver = FlowResolver()
    abe = Abe(os.path.join(HERE, "abe-policy.yaml"), resolver=resolver)

    say(c("1", "A procurement agent wants to spend money. Abe checks every purchase before it happens."), 1.2)
    say(c("2", "Rules on this machine: under $500 is fine, over $100,000 never, over $10,000 needs judgment.")
        + ("" if resolver else c("33", "\n(No FLOW_API_KEY: rules only. Escalations go to a human.)")), 1.5)

    flow_calls, flow_decisions = 0, []
    for label, action, evidence in ORDERS:
        say()
        say(f"{c('1', label)}   ${action['amount']:,}", 0.8)
        for k, v in evidence.items():
            say(c("2", f"   {k.replace('_', ' ')}: {v}"), 0.25)
        r = abe.check(action=action, context={"agent_id": "procurement-agent"}, evidence=evidence, confidence=0.95)
        if r.resolution:
            flow_calls += 1
            res = r.resolution
            say(f"   Abe:  {c(COLOR['ESCALATE'], 'ESCALATE')}  {r.records[0].reason_code}  -> asking Flow", 1.2)
            flow_decisions.append(r.decision)
            if res["status"] == "resolved":
                say(f"   Flow: {c(COLOR[r.decision], r.decision)}  {res.get('reason', '')}", 0.8)
                if res.get("falsifiers"):
                    say(c("2", f"   Wrong if: {res['falsifiers'][0]}"), 0.6)
            else:
                say(f"   Flow: unavailable ({res.get('error', '?')}); stays {c(COLOR['ESCALATE'], 'ESCALATE')}", 0.8)
        else:
            where = "rules, on this machine" if r.decision != "ESCALATE" else "rules; a human decides"
            say(f"   Abe:  {c(COLOR[r.decision], r.decision)}  {r.reason_code}  ({where})", 0.8)
        say(c("2", f"   record {r.record_id}"), 0.3)

    say()
    if not resolver:
        say(c("1", "Both $12,500 orders landed on a human. Add FLOW_API_KEY and run again."), 0)
        return
    tail = " Same amount, same rule, different answers." if len(set(flow_decisions)) > 1 else ""
    say(c("1", f"{len(ORDERS)} purchases. {len(ORDERS) - flow_calls} decided locally, {flow_calls} sent to Flow.{tail}"), 0)


if __name__ == "__main__":
    main()
