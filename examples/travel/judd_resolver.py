"""JuddResolver: Gate -> ESCALATE -> Judd's personalized travel judgment (spec §46).

    Judd -> FJP Gate -> ACT / BLOCK / ESCALATE -> if ESCALATE -> Judd -> personalized decision

The agent puts Judd's TravelCheck payload in evidence.travel_check. Judd verdicts map to Gate decisions:
    YES          -> ACT        (book exactly what was evaluated)
    NO           -> BLOCK
    INSTEAD      -> ESCALATE   (do not book this option; re-check Judd's chosen_option_id through the Gate)
    FIND_BETTER  -> ESCALATE   (search again with Judd's criteria)
    ASK_YOU      -> ESCALATE   (the user decides)
Env: JUDD_URL (e.g. https://judd.flowinfo.co), JUDD_API_KEY (judd_...).
"""
from __future__ import annotations

import json
import os
import urllib.request

from abe import Resolution

MAP = {"YES": "ACT", "NO": "BLOCK", "INSTEAD": "ESCALATE", "FIND_BETTER": "ESCALATE", "ASK_YOU": "ESCALATE"}


class JuddResolver:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, timeout: float = 10.0, transport=None):
        self.base_url = (base_url or os.environ["JUDD_URL"]).rstrip("/")
        self.api_key = api_key or os.environ["JUDD_API_KEY"]
        self.timeout = timeout
        self.transport = transport or self._http

    def _http(self, method: str, path: str, body: dict | None):
        req = urllib.request.Request(f"{self.base_url}{path}", method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            return json.loads(resp.read(1_048_576))

    def resolve(self, request: dict, gate_result) -> Resolution | None:
        check = (request.get("evidence") or {}).get("travel_check")
        if not isinstance(check, dict):
            return None  # nothing for Judd to judge; stays ESCALATE
        agent = request.get("actor", {}).get("agent_id", "abe-ai")
        d = self.transport("POST", f"/v1/travel/check?agent_name={agent}", check)
        jgr = self.transport("GET", f"/v1/decisions/{d['decision_id']}/jgr", None)
        verdict = d["verdict"]
        return Resolution(
            decision=MAP[verdict], reason=f"Judd {verdict}: {d['reason']} {d.get('what_to_do', '')}".strip(),
            reason_code=f"judd.{verdict.lower()}", confidence=d.get("confidence"),
            falsifiers=((jgr.get("falsifier") or {}).get("condition"),) if jgr.get("falsifier") else (),
            resolver_type="JUDD", implementation="judd", implementation_version="0.1", reference=d["decision_id"],
            evidence={"chosen_option_id": d.get("chosen_option_id"), "find_better_criteria": d.get("find_better_criteria", [])},
            external_record=jgr)
