"""Purchasing agent: ACT / BLOCK / ESCALATE with no account, no key, no network.   python run.py"""
import os

from abe import Abe
from abe.stores import SQLiteStore

HERE = os.path.dirname(__file__)
abe = Abe(os.path.join(HERE, "abe-policy.yaml"), store=SQLiteStore(os.path.join(HERE, "abe-records.db")))

for amount in (120, 12_500, 250_000):
    r = abe.check(action={"type": "purchase", "amount": amount, "currency": "USD", "target": "vendor_123"},
                   context={"agent_id": "procurement-agent", "principal_id": "user_123"}, confidence=0.95)
    print(f"${amount:>9,}  {r.decision:<8}  {r.reason_code:<30}  {r.record_id}")
    if r.decision == "ACT":
        # ... your agent executes the purchase here ...
        abe.record_outcome(r.record, "executed", {"request_hash": r.record.request_hash})
