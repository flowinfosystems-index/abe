"""Gate + Flow: only ESCALATE results go to Flow's judgment service (resolve.flowinfo.co).

    pip install abe-ai abe-flow
    export FLOW_API_KEY=fjp_live_...          # from https://fjp.flowinfo.co (Stripe checkout emails the key)
    python with_flow.py
"""
import os

from abe import Abe
from abe.stores import SQLiteStore
from abe_flow import FlowResolver

abe = Abe(os.path.join(os.path.dirname(__file__), "..", "purchasing", "abe-policy.yaml"),
            resolver=FlowResolver(api_key=os.environ["FLOW_API_KEY"]),
            store=SQLiteStore("abe-records.db"))

r = abe.check(action={"type": "purchase", "amount": 12_500, "currency": "USD", "target": "vendor_123"},
               context={"agent_id": "procurement-agent", "principal_id": "user_123"},
               evidence={"vendor_approved": True, "budget_remaining": 90_000, "vendor_on_time_rate": 0.97},
               confidence=0.95)

print("Gate said:", r.gate_decision)                 # ESCALATE (FINANCIAL_THRESHOLD_EXCEEDED)
print("Final:    ", r.decision, r.reason_code)       # e.g. ACT flow.reach
if r.resolution:
    print("Flow:     ", r.resolution.get("reason"))
    print("Wrong if: ", (r.resolution.get("falsifiers") or ["-"])[0])
print("Records:  ", [x.record_id for x in r.records])  # gate record + linked Flow resolution record
