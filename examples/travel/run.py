"""Travel: Gate alone, then Gate + Judd.   python run.py   (set JUDD_URL and JUDD_API_KEY to call Judd)"""
import json
import os

from abe import Abe

HERE = os.path.dirname(__file__)
req = json.load(open(os.path.join(HERE, "request.json")))

r = Abe(os.path.join(HERE, "abe-policy.yaml")).check(req)
print("Gate only:", r.decision, r.reason_code, r.matched_rules)   # ESCALATE JUDGMENT_REQUIRED

if os.environ.get("JUDD_URL") and os.environ.get("JUDD_API_KEY"):
    from judd_resolver import JuddResolver
    r = Abe(os.path.join(HERE, "abe-policy.yaml"), resolver=JuddResolver()).check(req)
    print("Gate + Judd:", r.decision, r.resolution["reason"])
