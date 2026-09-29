import json
import os

from abe import Abe

HERE = os.path.dirname(__file__)
r = Abe(os.path.join(HERE, "abe-policy.yaml")).check(json.load(open(os.path.join(HERE, "request.json"))))
print(r.decision, r.reason_code, r.matched_rules)   # ESCALATE HIGH_CONSEQUENCE_ACTION
