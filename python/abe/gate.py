"""Abe: one control point before an AI agent acts.

    gate = Gate("abe-policy.yaml")
    result = gate.check(action={"type": "purchase", "amount": 12500}, context={"agent_id": "procurement-agent"})
    result.decision  # "ACT" | "BLOCK" | "ESCALATE"

Guarantees:
  - no network calls, no model calls (the core package imports nothing that can make one)
  - check() never raises for bad input or a broken rule: it fails closed to ESCALATE / EVALUATION_FAILURE
  - every call returns an immutable Judgment-Grounded Record; resolvers and outcomes append linked records
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Protocol, runtime_checkable

from . import reason_codes as rc
from .canonical import canonical_json, hash_value, to_plain
from .evaluator import matches, present, resolve
from .exceptions import EvaluationError, PolicyError, RequestError
from .ids import new_id
from .models import GateResult, Record, Resolution
from .policy import DECISIONS, LEVEL_RANK, LEVELS, Policy, load_policy
from .records import (OUTCOME_STATUSES, build_decision_record, build_outcome_record, build_resolution_record,
                      evaluate_falsifier as _eval_falsifier, parse_iso)

log = logging.getLogger("abe")

MAX_REQUEST_BYTES = 262_144
MODES = ("enforce", "shadow")
SEVERITY = {"ACT": 0, "ESCALATE": 1, "BLOCK": 2}
RESERVED_ACTION_KEYS = ("directive", "judgment_ref")
_REQUEST_KEYS = ("protocol", "version", "request_id", "actor", "action", "context", "evidence", "confidence",
                 "risk", "irreversibility", "metadata")


@runtime_checkable
class Resolver(Protocol):
    """Optional resolver for ESCALATE results (human queue, Flow, your own service).

    Return a Resolution, or None if it cannot resolve. Exceptions are caught: the result stays ESCALATE.
    """

    def resolve(self, request: dict, gate_result: GateResult) -> Resolution | None: ...


def _level(v, where: str):
    if v is None:
        return None
    if isinstance(v, dict):
        v = v.get("level")
    if v is None:
        return None
    if v not in LEVELS:
        raise RequestError(f"{where} must be one of {list(LEVELS)}")
    return v


def normalize_request(request: dict | None = None, **kw) -> dict:
    if request is not None:
        if not isinstance(request, dict):
            raise RequestError("request must be an object")
        if any(v is not None for v in kw.values()):
            raise RequestError("pass either a request object or keyword fields, not both")
        src = request
    else:
        src = {k: v for k, v in kw.items() if v is not None}
    if src.get("protocol", "FJP") != "FJP":
        raise RequestError('protocol must be "FJP"')
    if str(src.get("version", "0.1")) != "0.1":
        raise RequestError('version must be "0.1"')

    action = src.get("action")
    if not isinstance(action, dict):
        raise RequestError("action must be an object")
    if not isinstance(action.get("type"), str) or not action["type"].strip():
        raise RequestError("action.type must be a non-empty string")
    for k in RESERVED_ACTION_KEYS:
        if k in action:
            raise RequestError(f"action.{k} is reserved by FJP records")
    for k in ("context", "evidence", "metadata", "actor"):
        if k in src and src[k] is not None and not isinstance(src[k], dict):
            raise RequestError(f"{k} must be an object")
    context = dict(src.get("context") or {})
    actor = dict(src.get("actor") or {})
    for k in ("agent_id", "principal_id", "organization_id"):
        if k not in actor and isinstance(context.get(k), str):
            actor[k] = context[k]
    for k, v in actor.items():
        if k in ("agent_id", "principal_id", "organization_id") and v is not None and not isinstance(v, str):
            raise RequestError(f"actor.{k} must be a string")
    conf = src.get("confidence")
    if conf is not None and (isinstance(conf, bool) or not isinstance(conf, (int, float)) or not 0 <= conf <= 1):
        raise RequestError("confidence must be a number in [0, 1]")
    rid = src.get("request_id")
    if rid is not None and (not isinstance(rid, str) or not rid.strip() or len(rid) > 128):
        raise RequestError("request_id must be a non-empty string of at most 128 characters")

    req: dict[str, Any] = {"actor": actor, "action": dict(action), "context": context,
                           "evidence": dict(src.get("evidence") or {})}
    if conf is not None:
        req["confidence"] = conf
    rl = _level(src.get("risk"), "risk.level")
    if rl:
        req["risk"] = {"level": rl}
    il = _level(src.get("irreversibility"), "irreversibility.level")
    if il:
        req["irreversibility"] = {"level": il}
    if src.get("metadata"):
        req["metadata"] = dict(src["metadata"])
    req["request_id"] = rid or new_id("req")
    req["_ignored"] = sorted(k for k in src if k not in _REQUEST_KEYS)
    return req


def _scale_level(req: dict, cfg: dict | None, key: str) -> dict:
    supplied = (req.get(key) or {}).get("level")
    mapped, source = None, None
    if cfg:
        for cond, lvl in cfg["mappings"]:
            if matches(req, cond):
                mapped, source = lvl, "policy_mapping"
                break
        if mapped is None and cfg["default"]:
            mapped, source = cfg["default"], "policy_default"
    candidates = [x for x in (supplied, mapped) if x]
    if not candidates:
        return {"level": "UNSPECIFIED", "source": "none"}
    level = max(candidates, key=lambda x: LEVEL_RANK[x])
    # The higher of the caller-supplied and policy-mapped level wins: a caller can raise risk, never lower it.
    if supplied and mapped:
        src = "request+policy" if supplied == mapped else ("request" if LEVEL_RANK[supplied] > LEVEL_RANK[mapped] else source)
    else:
        src = "request" if supplied else source
    return {"level": level, "source": src, "supplied": supplied, "mapped": mapped}


class Gate:
    def __init__(self, policy, *, resolver: Resolver | None = None, store=None, signer=None,
                 clock: Callable[[], datetime] | None = None, max_request_bytes: int = MAX_REQUEST_BYTES,
                 mode: str = "enforce"):
        """mode="shadow": every decision is computed and recorded exactly as in enforce mode, but records and
        results are marked shadow (not enforced). Keep your existing approval process, record what people
        decided with record_outcome(), and compare. A disagreement triggers the record's falsifier."""
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.mode = mode
        self.policy: Policy = load_policy(policy)   # raises PolicyError at startup: loud, before any action
        if resolver is not None and not callable(getattr(resolver, "resolve", None)):
            raise TypeError("resolver must have a resolve(request, gate_result) method")
        self.resolver = resolver
        self.store = store
        self.signer = signer
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.max_request_bytes = max_request_bytes

    # ------------------------------------------------------------------ evaluation

    def _evaluate(self, req: dict) -> dict:
        p = self.policy
        findings: list[dict] = []   # {id, source, decision, reason_code, description}

        def add(fid, source, decision, reason, desc=""):
            findings.append({"id": fid, "source": source, "decision": decision, "reason_code": reason,
                             **({"description": desc} if desc else {})})

        # 1. authorization
        if p.authorization:
            agent = req["actor"].get("agent_id")
            spec = p.authorization["agents"].get(agent) if isinstance(agent, str) else None
            atype = req["action"]["type"]
            if spec is None:
                if p.authorization["default"] == "deny":
                    add("authorization", "authorization", "BLOCK", rc.AUTHORIZATION_FAILED,
                        f"agent {agent!r} is not authorized by this policy")
            else:
                allow, deny = spec.get("allow", ["*"]), spec.get("deny", [])
                if atype in deny or "*" in deny or not (atype in allow or "*" in allow):
                    add("authorization", "authorization", "BLOCK", rc.AUTHORIZATION_FAILED,
                        f"agent {agent!r} is not authorized for {atype!r}")
        # 2. rules
        for r in p.rules:
            if matches(req, r.when):
                add(r.id, "rule", r.decision, r.reason_code, r.description)
        # 3. declared judgment boundary
        for j in p.judgment_required:
            if matches(req, j["when"]):
                add(j["id"], "judgment_required", "ESCALATE", j["reason_code"])
        # 4. evidence
        present_keys = sorted(k for k, v in req["evidence"].items() if v is not None)
        missing: list[str] = []
        for e in p.evidence_requirements:
            if e["when"] is None or matches(req, e["when"]):
                miss = [path for path in e["require"] if not present(resolve(req, path))]
                if miss:
                    missing.extend(m for m in miss if m not in missing)
                    add(e["id"], "evidence", e["decision"], e["reason_code"], "missing " + ", ".join(miss))
        # 5-6. risk and irreversibility
        risk = _scale_level(req, p.risk, "risk")
        irr = _scale_level(req, p.irreversibility, "irreversibility")
        for key, lv, cfg, reason in (("risk", risk, p.risk, rc.RISK_THRESHOLD_EXCEEDED),
                                     ("irreversibility", irr, p.irreversibility, rc.HIGH_IRREVERSIBILITY)):
            if cfg and lv["level"] in cfg["block_at"]:
                add(f"{key}.block_at", key, "BLOCK", reason, f"{key} {lv['level']}")
            elif cfg and lv["level"] in cfg["escalate_at"]:
                add(f"{key}.escalate_at", key, "ESCALATE", reason, f"{key} {lv['level']}")
        # 7. confidence (caller-supplied, stored as evidence, never treated as calibrated)
        conf_info = {"supplied": req.get("confidence"), "calibrated": False}
        if p.confidence:
            conf_info["minimum_to_act"] = p.confidence["minimum"]
            c = req.get("confidence")
            if c is None:
                if p.confidence["when_missing"] == "escalate":
                    add("confidence.missing", "confidence", p.confidence["decision"], p.confidence["reason_code"],
                        "no confidence supplied")
            elif c < p.confidence["minimum"]:
                add("confidence.minimum_to_act", "confidence", p.confidence["decision"], p.confidence["reason_code"],
                    f"{c} < {p.confidence['minimum']}")

        # precedence: BLOCK > ESCALATE > ACT
        top = max((SEVERITY[f["decision"]] for f in findings), default=None)
        rule_decisions = {f["decision"] for f in findings if f["source"] == "rule"}
        if top == SEVERITY["BLOCK"]:
            decision = "BLOCK"
            reason = next(f["reason_code"] for f in findings if f["decision"] == "BLOCK")
        elif top == SEVERITY["ESCALATE"]:
            decision = "ESCALATE"
            if {"ACT", "ESCALATE"} <= rule_decisions:
                reason = rc.CONFLICTING_RULES
            else:
                reason = next(f["reason_code"] for f in findings if f["decision"] == "ESCALATE")
        elif top == SEVERITY["ACT"]:
            decision = "ACT"
            reason = next(f["reason_code"] for f in findings if f["decision"] == "ACT")
        else:
            decision, reason = p.unmatched_decision, p.unmatched_reason
            findings.append({"id": "defaults.unmatched", "source": "default", "decision": decision,
                             "reason_code": reason, "description": "no rule matched"})
        codes = [reason] + [f["reason_code"] for f in findings if f["reason_code"] != reason]
        return {"decision": decision, "reason_code": reason, "reason_codes": list(dict.fromkeys(codes)),
                "findings": findings, "risk": risk, "irreversibility": irr, "evidence_present": present_keys,
                "evidence_missing": missing, "confidence": conf_info}

    def _eval_time(self, req: dict, now: datetime) -> tuple[datetime, str]:
        ctx = req["context"]
        for key in ("current_time", "time"):
            if key in ctx:
                v = ctx[key]
                if not isinstance(v, str):
                    raise RequestError(f"context.{key} must be an ISO 8601 string")
                try:
                    return parse_iso(v), "request"
                except ValueError as e:
                    raise RequestError(f"context.{key} is not valid ISO 8601") from e
        return now, "system"

    # ------------------------------------------------------------------ public API

    def check(self, request: dict | None = None, /, *, action=None, context=None, evidence=None, actor=None,
              confidence=None, risk=None, irreversibility=None, request_id=None, metadata=None) -> GateResult:
        """Evaluate a proposed action. Never raises for bad input: fails closed to ESCALATE."""
        now = self._clock()
        raw = request
        try:
            req = normalize_request(request, action=action, context=context, evidence=evidence, actor=actor,
                                    confidence=confidence, risk=risk, irreversibility=irreversibility,
                                    request_id=request_id, metadata=metadata)
            ignored = req.pop("_ignored")
            hashed = {k: v for k, v in req.items() if k != "request_id"}
            body = canonical_json(hashed)
            if len(body.encode("utf-8")) > self.max_request_bytes:
                raise RequestError(f"request exceeds {self.max_request_bytes} bytes")
            request_hash = hash_value(hashed)
            eval_time, time_source = self._eval_time(req, now)
            ev = self._evaluate(req)
        except (RequestError, EvaluationError, PolicyError, RecursionError, ValueError, TypeError, KeyError) as e:
            return self._failure(raw, action, context, actor, request_id, now, e)
        except Exception as e:  # noqa: BLE001 - fail closed on anything unexpected
            log.exception("fjp: unexpected evaluation error")
            return self._failure(raw, action, context, actor, request_id, now, e)

        rec = build_decision_record(
            record_id=new_id("jgr"), request_id=req["request_id"], now=now, eval_time=eval_time,
            time_source=time_source, req=req, request_hash=request_hash, policy=self.policy,
            decision=ev["decision"], reason_code=ev["reason_code"], reason_codes=ev["reason_codes"],
            matched=[f for f in ev["findings"] if f["source"] != "default"], risk=ev["risk"],
            irr=ev["irreversibility"], evidence_present=ev["evidence_present"],
            evidence_missing=ev["evidence_missing"], confidence=ev["confidence"], signer=self.signer,
            mode=self.mode)
        warnings = tuple(f"ignored unknown request field {k!r}" for k in ignored)
        err = self._persist(rec)
        if err:
            return self._failure(raw, action, context, actor, request_id, now, err, parent=rec)
        result = GateResult(
            decision=ev["decision"], reason_code=ev["reason_code"], record=rec, risk_level=ev["risk"]["level"],
            irreversibility_level=ev["irreversibility"]["level"], matched_rules=tuple(rec.matched_rules),
            reason_codes=tuple(ev["reason_codes"]), missing_evidence=tuple(ev["evidence_missing"]),
            gate_decision=ev["decision"], records=(rec,), warnings=warnings, mode=self.mode)
        if result.decision == "ESCALATE" and self.resolver is not None and self.policy.resolver["enabled"]:
            esc_codes = {f["reason_code"] for f in ev["findings"] if f["decision"] == "ESCALATE"} | {ev["reason_code"]}
            if esc_codes & set(self.policy.resolver["not_resolvable"]):
                return result
            return self._resolve(req, result, now)
        return result

    def _resolve(self, req: dict, result: GateResult, now: datetime) -> GateResult:
        parent = result.record
        resolution, status, error = None, "resolved", None
        try:
            resolution = self.resolver.resolve(to_plain(req), result)
            if resolution is None:
                status = "unresolved"
            elif not isinstance(resolution, Resolution):
                raise TypeError("resolver must return abe.Resolution or None")
            elif resolution.decision not in DECISIONS:
                raise ValueError(f"resolver returned invalid decision {resolution.decision!r}")
            elif resolution.reason_code is not None and not rc.is_valid(resolution.reason_code):
                raise ValueError(f"resolver returned invalid reason_code {resolution.reason_code!r}")
        except Exception as e:  # noqa: BLE001 - the Gate never fails because a resolver is unavailable
            log.warning("fjp: resolver failed; staying ESCALATE: %s", e)
            resolution, status, error = None, "unavailable", f"{type(e).__name__}: {e}"
        final = resolution.decision if resolution is not None else "ESCALATE"
        rrec = build_resolution_record(record_id=new_id("jgr"), parent=parent, now=self._clock(),
                                       resolution=resolution, final_decision=final,
                                       horizon_days=self.policy.falsifier_horizon_days, status=status,
                                       error=error, signer=self.signer)
        err = self._persist(rrec)
        if err:
            return self._failure(req, None, None, None, None, now, err, parent=rrec)
        summary = {"status": status, "decision": final, "record_id": rrec.record_id,
                   "resolver": rrec.resolver.to_dict()}
        if resolution is not None:
            summary.update({"reason": resolution.reason, "confidence": resolution.confidence,
                            "falsifiers": list(resolution.falsifiers)})
        if error:
            summary["error"] = error
        return GateResult(
            decision=final, reason_code=rrec.reason_code, record=rrec, risk_level=result.risk_level,
            irreversibility_level=result.irreversibility_level, matched_rules=result.matched_rules,
            reason_codes=result.reason_codes, missing_evidence=result.missing_evidence,
            gate_decision=result.decision, records=(parent, rrec), resolution=summary, warnings=result.warnings,
            mode=self.mode)

    def _persist(self, rec: Record):
        if self.store is None:
            return None
        try:
            self.store.save(rec)
            return None
        except Exception as e:  # noqa: BLE001
            log.error("fjp: record store failed: %s", e)
            return RuntimeError(f"record store failed: {e}")

    def _failure(self, raw, action, context, actor, request_id, now, error, parent: Record | None = None) -> GateResult:
        """ESCALATE / EVALUATION_FAILURE with a best-effort record. Never raises."""
        src = raw if isinstance(raw, dict) else {"action": action, "context": context, "actor": actor,
                                                 "request_id": request_id}
        a = src.get("action") if isinstance(src.get("action"), dict) else {}
        atype = a.get("type") if isinstance(a.get("type"), str) else "unknown"
        actor_in = src.get("actor") if isinstance(src.get("actor"), dict) else {}
        ctx = src.get("context") if isinstance(src.get("context"), dict) else {}
        safe_actor = {k: str(v)[:128] for k, v in {**{k: ctx.get(k) for k in ("agent_id", "principal_id")},
                                                    **actor_in}.items()
                      if k in ("agent_id", "principal_id", "organization_id") and v is not None}
        rid = src.get("request_id") if isinstance(src.get("request_id"), str) and len(src["request_id"]) <= 128 \
            else new_id("req")
        req = {"actor": safe_actor, "action": {"type": atype[:128]}}
        try:
            request_hash = hash_value(src)
        except Exception:  # noqa: BLE001
            request_hash = "unavailable"
        detail = f"{type(error).__name__}: {error}"
        finding = {"id": "evaluation", "source": "gate", "decision": "ESCALATE",
                   "reason_code": rc.EVALUATION_FAILURE, "description": str(error)[:300]}
        if parent is not None:
            finding["description"] = f"{error} (unpersisted record {parent.record_id})"
        rec = build_decision_record(
            record_id=new_id("jgr"), request_id=rid, now=now, eval_time=now, time_source="system", req=req,
            request_hash=request_hash, policy=self.policy, decision="ESCALATE", reason_code=rc.EVALUATION_FAILURE,
            reason_codes=[rc.EVALUATION_FAILURE], matched=[finding], risk={"level": "UNSPECIFIED", "source": "none"},
            irr={"level": "UNSPECIFIED", "source": "none"}, evidence_present=[], evidence_missing=[],
            confidence={"supplied": None, "calibrated": False}, failure_detail=detail, signer=self.signer,
            mode=self.mode)
        if parent is None:
            self._persist(rec)  # best effort; the failure is already the fail-closed outcome
        return GateResult(decision="ESCALATE", reason_code=rc.EVALUATION_FAILURE, record=rec,
                          risk_level="UNSPECIFIED", irreversibility_level="UNSPECIFIED",
                          matched_rules=("evaluation",), reason_codes=(rc.EVALUATION_FAILURE,),
                          gate_decision="ESCALATE", records=(rec,), warnings=(detail,), mode=self.mode)

    # ------------------------------------------------------------------ linked records

    def _get(self, record_or_id) -> Record:
        if isinstance(record_or_id, Record):
            return record_or_id
        if isinstance(record_or_id, GateResult):
            return record_or_id.records[0]
        if self.store is None:
            raise LookupError("pass the Record itself, or configure a store to look records up by id")
        rec = self.store.get(record_or_id)
        if rec is None:
            raise LookupError(f"record {record_or_id!r} not found")
        return rec

    def record_outcome(self, record_or_id, status: str, details: dict | None = None) -> Record:
        """Append a linked OUTCOME record (never mutates the original).

        status: executed | failed | reverted | cancelled | approved | rejected.
        details may include request_hash (what was actually executed), final amounts, external ids.
        """
        if status not in OUTCOME_STATUSES:
            raise ValueError(f"status must be one of {OUTCOME_STATUSES}")
        details = to_plain(details or {})
        canonical_json(details)  # validates JSON-compatibility
        target = self._get(record_or_id)
        root = target if target.event_type == "DECISION" else self._root_of(target)
        rec = build_outcome_record(record_id=new_id("jgr"), parent=root, now=self._clock(), status=status,
                                   details=details, horizon_days=self.policy.falsifier_horizon_days,
                                   signer=self.signer)
        err = self._persist(rec)
        if err:
            raise err
        return rec

    def _root_of(self, rec: Record) -> Record:
        if self.store is not None:
            root = self.store.get(rec.root_record_id)
            if root is not None:
                return root
        raise LookupError("outcomes attach to the Gate's DECISION record; pass result.records[0] or configure a store")

    def get_record(self, record_id: str) -> Record:
        return self._get(record_id)

    def evaluate_falsifier(self, record_or_id, now: datetime | None = None) -> str:
        rec = self._get(record_or_id)
        linked = self.store.linked(rec.root_record_id) if self.store is not None else []
        return _eval_falsifier(rec, linked, now or self._clock())

