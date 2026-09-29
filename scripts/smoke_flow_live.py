"""Live smoke test against Flow's resolver. Costs one judge credit.

    FLOW_API_KEY=fjp_live_... python scripts/smoke_flow_live.py [--base-url https://resolve.flowinfo.co]
"""
import argparse
import os
import sys

sys.path[:0] = [os.path.join(os.path.dirname(__file__), "..", p) for p in ("python", "flow-resolver")]
from abe import Gate  # noqa: E402
from abe_flow import FlowResolver  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--base-url", default=None)
a = ap.parse_args()
policy = os.path.join(os.path.dirname(__file__), "..", "python", "abe", "templates", "starter.yaml")
gate = Gate(policy, resolver=FlowResolver(base_url=a.base_url))
r = gate.check(action={"type": "purchase", "amount": 12500, "currency": "USD", "target": "vendor_123"},
               context={"agent_id": "smoke-test"}, evidence={"vendor_approved": True, "budget_remaining": 90000},
               confidence=0.95)
print("gate:", r.gate_decision, "| final:", r.decision, r.reason_code)
print("resolution:", r.resolution)
ok = r.resolution and r.resolution["status"] == "resolved" and r.records[1].get("external_record")
print("LIVE FLOW OK" if ok else "FLOW NOT RESOLVED (see resolution above)")
sys.exit(0 if ok else 1)
