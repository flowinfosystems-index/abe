"""Judgment-Grounded Record (JGR) construction, integrity hashing and falsifier re-evaluation.

Each record carries the Abe fields (decision, reason codes, matched rules, policy hash...) AND the
four FJP-CONF v0.1 components (signal, judgment, action, falsifier), so every Gate record passes the
public FJP-CONF suite at L0-L2, and at L3 through abe.conformance.GateAdapter.

Falsifiers are *control falsifiers*: each record asserts what should happen next (ACT: executes as
evaluated; BLOCK: does not execute; ESCALATE: does not execute before resolution) and names the
linked OUTCOME record that would prove the assertion wrong. They are re-evaluated deterministically
from linked records, never by a model.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from . import __version__
from .canonical import hash_value
from .models import Record

PROTOCOL = "FJP"
PROTOCOL_VERSION = "0.1"
FJP_CONF_VERSION = "0.1.0"
IMPLEMENTATION = "abe-python"

# Fields excluded from record_hash: the hash itself, the signature, and falsifier.status
# (the one field FJP-CONF defines as re-evaluable after creation).
_UNHASHED = ("record_hash", "signature")

OUTCOME_STATUSES = ("executed", "failed", "reverted", "cancelled", "approved", "rejected")


def iso(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2})$")


def parse_iso(s: str) -> datetime:
    """Strict RFC 3339 date-time (the same grammar is accepted by every FJP SDK). Raises ValueError."""
    m = _ISO.match(s.strip()) if isinstance(s, str) else None
    if not m:
        raise ValueError(f"not an RFC 3339 date-time with offset: {s!r}")
    y, mo, d, h, mi, sec, frac, off = m.groups()
    if not 1970 <= int(y) <= 9999:
        raise ValueError("year must be between 1970 and 9999")
    ms = int((frac or "0")[:3].ljust(3, "0"))
    tz = timezone.utc if off == "Z" else timezone(
        (1 if off[0] == "+" else -1) * timedelta(hours=int(off[1:3]), minutes=int(off[4:6])))
    return datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec or 0), ms * 1000, tzinfo=tz).astimezone(timezone.utc)


def hashable_view(record: dict) -> dict:
    d = {k: v for k, v in record.items() if k not in _UNHASHED}
    if isinstance(d.get("falsifier"), dict):
        d["falsifier"] = {k: v for k, v in d["falsifier"].items() if k != "status"}
    return d


def compute_record_hash(record: dict) -> str:
    return hash_value(hashable_view(record))


def finalize(record: dict, signer=None) -> Record:
    record["record_hash"] = compute_record_hash(record)
    if signer is not None:
        record["signature"] = signer.sign(record["record_hash"])
    return Record.from_dict(record)


def verify_hash(record) -> bool:
    d = record.to_dict() if hasattr(record, "to_dict") else dict(record)
    return isinstance(d.get("record_hash"), str) and d["record_hash"] == compute_record_hash(d)


def _base(*, record_id, request_id, root_id, parent_id, event_type, now, horizon_days, policy, actor):
    expires = now + timedelta(days=horizon_days)
    return {
        "protocol": PROTOCOL,
        "version": PROTOCOL_VERSION,
        "fjp_conf_version": FJP_CONF_VERSION,
        "implementation_version": __version__,
        "producer": "abe",
        "record_id": record_id,
        "request_id": request_id,
        "root_record_id": root_id,
        "parent_record_id": parent_id,
        "event_type": event_type,
        "timestamp": iso(now),
        "expires_at": iso(expires),
        "actor": actor,
        "policy": policy,
    }, iso(expires)


def _action_summary(action: dict) -> str:
    parts = [str(action.get("type", "action"))]
    for k in ("amount", "total_price", "currency", "target", "destination"):
        if k in action and isinstance(action[k], (str, int, float)) and not isinstance(action[k], bool):
            parts.append(f"{k}={action[k]}")
    return " ".join(parts)[:300]


def build_decision_record(*, record_id, request_id, now, eval_time, time_source, req, request_hash, policy,
                          decision, reason_code, reason_codes, matched, risk, irr, evidence_present,
                          evidence_missing, confidence, failure_detail=None, signer=None) -> Record:
    actor = req.get("actor") or {}
    rec, expires = _base(record_id=record_id, request_id=request_id, root_id=record_id, parent_id=None,
                         event_type="DECISION", now=now, horizon_days=policy.falsifier_horizon_days if policy else 30,
                         policy=policy.describe() if policy else {"id": None, "version": None, "hash": None,
                                                                  "format_version": PROTOCOL_VERSION},
                         actor=actor)
    action_in = req.get("action") if isinstance(req.get("action"), dict) else {}
    atype = action_in.get("type", "action")
    agent = actor.get("agent_id") or "agent"
    sig_id, jud_id = f"sig-{record_id}", f"jud-{record_id}"

    rule_desc = "; ".join(f"{m['id']} -> {m['decision']} ({m['reason_code']})" for m in matched) or "no rule matched"
    assessment = f"{decision} / {reason_code}. Deterministic policy evaluation: {rule_desc}."
    if evidence_missing:
        assessment += f" Missing evidence: {', '.join(evidence_missing)}."
    if failure_detail:
        assessment += f" Evaluation failure: {failure_detail}."
    assessment += " This is a policy result, not an independent judgment that the action is optimal."

    if decision == "ACT":
        directive = f"ACT: {agent} may execute {atype} as evaluated."
        condition = (f"An OUTCOME record linked to {record_id} reports status failed or reverted, or reports an "
                     f"executed request_hash other than {request_hash}, before {expires}.")
    elif decision == "BLOCK":
        directive = f"BLOCK: {agent} must not execute {atype}."
        condition = (f"An OUTCOME record linked to {record_id} reports status executed (the action ran despite "
                     f"BLOCK) before {expires}.")
    else:
        directive = f"ESCALATE: {agent} must hold {atype} until the configured escalation path resolves it."
        condition = (f"An OUTCOME record linked to {record_id} reports status executed before a RESOLUTION record "
                     f"with decision ACT is linked, before {expires}.")

    rec.update({
        "evaluation_time": iso(eval_time),
        "time_source": time_source,
        "request_hash": request_hash,
        "action": {**action_in, "directive": directive, "judgment_ref": jud_id},
        "decision": decision,
        "reason_code": reason_code,
        "reason_codes": list(reason_codes),
        "matched_rules": [m["id"] for m in matched],
        "rule_results": list(matched),
        "risk": risk,
        "irreversibility": irr,
        "evidence_present": list(evidence_present),
        "evidence_missing": list(evidence_missing),
        "confidence": confidence,
        "resolver": {"type": "FJP_GATE", "implementation": IMPLEMENTATION, "version": __version__},
        "signal": {
            "id": sig_id,
            "description": f"{agent} proposed {_action_summary(action_in)} (request {request_id}).",
            "sources": [f"fjp:agent:{agent}", f"fjp:request:{request_id}", f"fjp:policy:{rec['policy']['hash']}"],
            "observed_at": iso(eval_time),
        },
        "judgment": {
            "id": jud_id,
            "assessment": assessment,
            # Certainty that the policy yields this decision; 0 when evaluation itself failed.
            "confidence": 0.0 if reason_code == "EVALUATION_FAILURE" else 1.0,
            "basis": "deterministic_policy",
            "signal_ref": sig_id,
        },
        "falsifier": {"condition": condition, "checkable": True, "status": "open"},
    })
    if failure_detail:
        rec["evaluation_error"] = str(failure_detail)[:500]
    return finalize(rec, signer)


def build_resolution_record(*, record_id, parent: Record, now, resolution, final_decision, horizon_days,
                            status="resolved", error=None, signer=None) -> Record:
    rec, expires = _base(record_id=record_id, request_id=parent.request_id, root_id=parent.root_record_id,
                         parent_id=parent.record_id, event_type="RESOLUTION", now=now, horizon_days=horizon_days,
                         policy=parent.policy.to_dict(), actor=parent.actor.to_dict())
    sig_id, jud_id = f"sig-{record_id}", f"jud-{record_id}"
    pa = parent.action.to_dict()
    atype = pa.get("type", "action")
    if resolution is not None:
        reason = resolution.reason
        conf = resolution.confidence
        res_meta = {"type": resolution.resolver_type, "implementation": resolution.implementation,
                    "version": resolution.implementation_version, "reference": resolution.reference}
        falsifiers = list(resolution.falsifiers)
    else:
        reason = f"Resolver unavailable: {error}" if error else "Resolver unavailable."
        conf = None
        res_meta = {"type": "EXTERNAL", "implementation": "unknown", "version": "0", "reference": None}
        falsifiers = []
    condition = falsifiers[0] if falsifiers else None
    if not condition or not isinstance(condition, str):
        condition = (f"An OUTCOME record linked to {parent.record_id} reports status failed or reverted "
                     f"before {expires}.")
    directive = {"ACT": f"ACT: execute {atype} as evaluated in {parent.record_id}.",
                 "BLOCK": f"BLOCK: do not execute {atype}.",
                 "ESCALATE": f"ESCALATE: {atype} still requires a human or another resolver."}[final_decision]
    rec.update({
        "decision": final_decision,
        "original_gate_decision": parent.decision,
        "reason_code": (resolution.reason_code if resolution and resolution.reason_code else parent.reason_code),
        "resolution_status": status,
        "request_hash": parent.request_hash,
        "action": {**pa, "directive": directive, "judgment_ref": jud_id},
        "resolver": res_meta,
        "judgment_detail": {"reason": reason, "confidence": conf, "falsifiers": falsifiers,
                            "evidence": dict(resolution.evidence) if resolution else {}},
        "external_record": dict(resolution.external_record) if resolution and resolution.external_record else None,
        "signal": {
            "id": sig_id,
            "description": f"Gate record {parent.record_id} escalated ({parent.reason_code}); resolver consulted.",
            "sources": [f"fjp:record:{parent.record_id}", f"fjp:resolver:{res_meta['type'].lower()}"]
                       + ([f"fjp:resolver-ref:{res_meta['reference']}"] if res_meta.get("reference") else []),
            "observed_at": iso(now),
        },
        "judgment": {
            "id": jud_id,
            "assessment": reason or "No reason supplied.",
            "confidence": float(conf) if isinstance(conf, (int, float)) and not isinstance(conf, bool)
                          and 0 <= conf <= 1 else 0.0,
            "basis": "external_resolver" if resolution else "resolver_unavailable",
            "signal_ref": sig_id,
        },
        "falsifier": {"condition": condition, "checkable": True, "status": "open"},
    })
    if error:
        rec["resolution_error"] = str(error)[:500]
    return finalize(rec, signer)


def build_outcome_record(*, record_id, parent: Record, now, status, details, horizon_days, signer=None) -> Record:
    rec, expires = _base(record_id=record_id, request_id=parent.request_id, root_id=parent.root_record_id,
                         parent_id=parent.record_id, event_type="OUTCOME", now=now, horizon_days=horizon_days,
                         policy=parent.policy.to_dict(), actor=parent.actor.to_dict())
    sig_id, jud_id = f"sig-{record_id}", f"jud-{record_id}"
    rec.update({
        "status": status,
        "details": details,
        "decision": parent.decision,
        "request_hash": parent.request_hash,
        "action": {"directive": f"RECORD: outcome {status} for {parent.record_id}.", "judgment_ref": jud_id},
        "signal": {"id": sig_id, "description": f"Outcome reported for {parent.record_id}: {status}.",
                   "sources": [f"fjp:record:{parent.record_id}"], "observed_at": iso(now)},
        "judgment": {"id": jud_id, "assessment": f"Reported outcome: {status}.", "confidence": 1.0,
                     "basis": "reported_outcome", "signal_ref": sig_id},
        "falsifier": {"condition": (f"A later OUTCOME record linked to {parent.record_id} reports a status other "
                                    f"than {status} before {expires}."),
                      "checkable": True, "status": "open"},
    })
    return finalize(rec, signer)


def evaluate_falsifier(record, linked: list, now: datetime | None = None) -> str:
    """open | triggered | expired, from the record and every record sharing its root (any order)."""
    now = now or datetime.now(timezone.utc)
    r = record.to_dict() if hasattr(record, "to_dict") else dict(record)
    others = [x.to_dict() if hasattr(x, "to_dict") else dict(x) for x in linked]
    others = [x for x in others if x.get("record_id") != r.get("record_id")]
    others.sort(key=lambda x: (x.get("timestamp", ""), x.get("record_id", "")))
    root = r.get("root_record_id") or r.get("record_id")
    outcomes = [x for x in others if x.get("event_type") == "OUTCOME" and x.get("root_record_id") == root]
    resolutions = [x for x in others if x.get("event_type") == "RESOLUTION" and x.get("root_record_id") == root]
    expired = now > parse_iso(r["expires_at"]) if r.get("expires_at") else False
    et, dec = r.get("event_type"), r.get("decision")

    if et == "OUTCOME":
        later = [o for o in outcomes if o.get("timestamp", "") > r.get("timestamp", "")]
        if any(o.get("status") != r.get("status") for o in later):
            return "triggered"
        return "expired" if expired else "open"

    if et == "RESOLUTION" or dec == "ACT":
        for o in outcomes:
            if o.get("status") in ("failed", "reverted"):
                return "triggered"
            rh = (o.get("details") or {}).get("request_hash")
            if o.get("status") == "executed" and rh and rh != r.get("request_hash"):
                return "triggered"
        if any(o.get("status") in ("executed", "cancelled") for o in outcomes):
            return "expired"
        return "expired" if expired else "open"

    if dec == "BLOCK":
        if any(o.get("status") == "executed" for o in outcomes):
            return "triggered"
        return "expired" if expired else "open"

    # ESCALATE
    executed = [o for o in outcomes if o.get("status") == "executed"]
    if executed:
        first = executed[0]
        prior = [x for x in resolutions if x.get("timestamp", "") <= first.get("timestamp", "")]
        approvals = [o for o in outcomes if o.get("status") == "approved"
                     and o.get("timestamp", "") <= first.get("timestamp", "")]
        if (prior and prior[-1].get("decision") == "ACT") or approvals:
            return "expired"
        return "triggered"
    return "expired" if expired else "open"
