"""Policy loading and strict validation.

Strictness is a safety feature: an unknown key or a misspelled field root ("acton.type") is an
error at load time, not a rule that silently never matches.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from . import reason_codes as rc
from .canonical import canonical_json, hash_value
from .evaluator import OPS, ROOTS
from .exceptions import PolicyError, RequestError
from .yaml_safe import load_yaml

POLICY_FORMAT_VERSION = "0.1"
DECISIONS = ("ACT", "BLOCK", "ESCALATE")
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
LEVEL_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}
MAX_POLICY_BYTES = 1_048_576
MAX_RULES = 1000
MAX_COND_DEPTH = 16
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_PATH = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+){0,15}$")

TOP_KEYS = {"version", "policy_id", "policy_version", "description", "defaults", "authorization", "rules",
            "risk", "irreversibility", "evidence_requirements", "confidence", "judgment_required",
            "resolver", "records"}


def _err(where: str, msg: str):
    raise PolicyError(f"{where}: {msg}")


def _keys(obj, allowed: set, where: str, required: tuple = ()):
    if not isinstance(obj, dict):
        _err(where, "must be a mapping")
    extra = set(obj) - allowed
    if extra:
        _err(where, f"unknown key(s) {sorted(extra)}; allowed: {sorted(allowed)}")
    for r in required:
        if r not in obj:
            _err(where, f"missing required key {r!r}")


def _path(p, where: str):
    if not isinstance(p, str) or not _PATH.match(p):
        _err(where, f"invalid field path {p!r}")
    if p.split(".")[0] not in ROOTS:
        _err(where, f"field {p!r} must start with one of {list(ROOTS)}")


def _scalar(v) -> bool:
    return v is None or isinstance(v, (str, int, float, bool))


def validate_condition(c, where: str, depth: int = 0):
    if depth > MAX_COND_DEPTH:
        _err(where, f"condition nested deeper than {MAX_COND_DEPTH}")
    if not isinstance(c, dict):
        _err(where, "condition must be a mapping")
    forms = [k for k in ("all", "any", "not") if k in c]
    if forms:
        if len(c) != 1:
            _err(where, f"a '{forms[0]}' condition cannot have other keys")
        k = forms[0]
        if k == "not":
            validate_condition(c["not"], f"{where}.not", depth + 1)
        else:
            if not isinstance(c[k], list) or not c[k]:
                _err(where, f"'{k}' must be a non-empty list")
            for i, sub in enumerate(c[k]):
                validate_condition(sub, f"{where}.{k}[{i}]", depth + 1)
        return
    _keys(c, {"field", "op", "value"}, where, required=("field", "op"))
    _path(c["field"], where)
    op = c["op"]
    if op not in OPS:
        _err(where, f"unknown op {op!r}; allowed: {list(OPS)}")
    if op in ("exists", "not_exists"):
        if "value" in c:
            _err(where, f"'{op}' takes no value")
        return
    if "value" not in c:
        _err(where, f"'{op}' requires a value")
    v = c["value"]
    if op in ("in", "not_in"):
        if not isinstance(v, list) or not v:
            _err(where, f"'{op}' value must be a non-empty list")
    elif op in ("gt", "gte", "lt", "lte"):
        if isinstance(v, bool) or not isinstance(v, (int, float, str)):
            _err(where, f"'{op}' value must be a number or string")
    elif op == "contains":
        if not _scalar(v) or v is None:
            _err(where, "'contains' value must be a string, number or boolean")


def _decision(v, where: str, allowed=DECISIONS):
    if v not in allowed:
        _err(where, f"decision must be one of {list(allowed)}, got {v!r}")
    return v


def _reason(v, where: str):
    if not rc.is_valid(v):
        _err(where, f"reason_code {v!r} is not a standard code or a namespaced custom code (namespace.identifier)")
    return v


def _levels(v, where: str) -> list:
    if not isinstance(v, list) or any(x not in LEVELS for x in v):
        _err(where, f"must be a list of {list(LEVELS)}")
    return list(v)


@dataclass(frozen=True)
class Rule:
    id: str
    when: dict
    decision: str
    reason_code: str
    description: str = ""


@dataclass(frozen=True)
class Policy:
    raw: dict
    hash: str
    policy_id: str | None
    policy_version: str | None
    unmatched_decision: str
    unmatched_reason: str
    rules: tuple
    authorization: dict | None
    risk: dict | None
    irreversibility: dict | None
    evidence_requirements: tuple
    confidence: dict | None
    judgment_required: tuple
    resolver: dict = field(default_factory=dict)
    falsifier_horizon_days: int = 30
    source: str | None = None

    def describe(self) -> dict:
        return {"id": self.policy_id, "version": self.policy_version, "hash": self.hash,
                "format_version": POLICY_FORMAT_VERSION}


def _scale(obj, where: str) -> dict | None:
    if obj is None:
        return None
    _keys(obj, {"defaults", "mappings", "escalate_at", "block_at"}, where)
    default = None
    if "defaults" in obj:
        _keys(obj["defaults"], {"level"}, f"{where}.defaults", required=("level",))
        default = obj["defaults"]["level"]
        if default not in LEVELS:
            _err(f"{where}.defaults.level", f"must be one of {list(LEVELS)}")
    mappings = []
    for i, m in enumerate(obj.get("mappings") or []):
        w = f"{where}.mappings[{i}]"
        _keys(m, {"when", "level"}, w, required=("when", "level"))
        validate_condition(m["when"], f"{w}.when")
        if m["level"] not in LEVELS:
            _err(f"{w}.level", f"must be one of {list(LEVELS)}")
        mappings.append((m["when"], m["level"]))
    return {"default": default, "mappings": tuple(mappings),
            "escalate_at": _levels(obj.get("escalate_at", []), f"{where}.escalate_at"),
            "block_at": _levels(obj.get("block_at", []), f"{where}.block_at")}


def parse_policy(data, source: str | None = None) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping at the top level")
    _keys(data, TOP_KEYS, "policy", required=("version",))
    if str(data["version"]) != POLICY_FORMAT_VERSION or not isinstance(data["version"], str):
        raise PolicyError(f'policy.version must be the string "{POLICY_FORMAT_VERSION}" (quote it in YAML)')
    try:
        phash = hash_value(data)
    except RequestError as e:
        raise PolicyError(f"policy is not canonical JSON-compatible: {e}") from e

    for k in ("policy_id", "policy_version", "description"):
        if k in data and not isinstance(data[k], str):
            _err(f"policy.{k}", "must be a string")

    # defaults
    d = data.get("defaults") or {}
    _keys(d, {"unmatched", "unmatched_reason_code"}, "policy.defaults")
    unmatched = _decision(d.get("unmatched", "ESCALATE"), "policy.defaults.unmatched")
    unmatched_reason = _reason(d.get("unmatched_reason_code", rc.DEFAULT_FOR_DECISION[unmatched]
                                     if unmatched != "ESCALATE" else rc.JUDGMENT_REQUIRED),
                               "policy.defaults.unmatched_reason_code")

    # rules
    rules_in = data.get("rules") or []
    if not isinstance(rules_in, list):
        _err("policy.rules", "must be a list")
    if len(rules_in) > MAX_RULES:
        _err("policy.rules", f"at most {MAX_RULES} rules")
    rules, seen = [], set()
    for i, r in enumerate(rules_in):
        w = f"policy.rules[{i}]"
        _keys(r, {"id", "description", "when", "decision", "reason_code"}, w, required=("id", "when", "decision"))
        if not isinstance(r["id"], str) or not _ID.match(r["id"]):
            _err(f"{w}.id", "must match [A-Za-z0-9][A-Za-z0-9_.:-]*")
        if r["id"] in seen:
            _err(f"{w}.id", f"duplicate rule id {r['id']!r}")
        seen.add(r["id"])
        w = f"policy.rules[{r['id']}]"
        validate_condition(r["when"], f"{w}.when")
        dec = _decision(r["decision"], f"{w}.decision")
        reason = _reason(r.get("reason_code", rc.DEFAULT_FOR_DECISION[dec]), f"{w}.reason_code")
        if "description" in r and not isinstance(r["description"], str):
            _err(f"{w}.description", "must be a string")
        rules.append(Rule(r["id"], r["when"], dec, reason, r.get("description", "")))

    # authorization
    auth = data.get("authorization")
    if auth is not None:
        _keys(auth, {"default", "agents"}, "policy.authorization")
        if auth.get("default", "deny") not in ("allow", "deny"):
            _err("policy.authorization.default", "must be 'allow' or 'deny'")
        agents = auth.get("agents") or {}
        if not isinstance(agents, dict):
            _err("policy.authorization.agents", "must be a mapping of agent_id -> {allow, deny}")
        for aid, spec in agents.items():
            w = f"policy.authorization.agents[{aid}]"
            _keys(spec, {"allow", "deny"}, w)
            for k in ("allow", "deny"):
                if k in spec and (not isinstance(spec[k], list) or not all(isinstance(x, str) for x in spec[k])):
                    _err(f"{w}.{k}", "must be a list of action types ('*' for all)")
        auth = {"default": auth.get("default", "deny"), "agents": agents}

    risk = _scale(data.get("risk"), "policy.risk")
    irr = _scale(data.get("irreversibility"), "policy.irreversibility")

    # evidence
    evs = []
    ev_in = data.get("evidence_requirements") or []
    if not isinstance(ev_in, list):
        _err("policy.evidence_requirements", "must be a list")
    for i, e in enumerate(ev_in):
        w = f"policy.evidence_requirements[{i}]"
        _keys(e, {"id", "when", "require", "missing_decision", "reason_code"}, w, required=("id", "require"))
        if "when" in e:
            validate_condition(e["when"], f"{w}.when")
        if not isinstance(e["require"], list) or not e["require"]:
            _err(f"{w}.require", "must be a non-empty list of field paths")
        for p in e["require"]:
            _path(p, f"{w}.require")
        dec = _decision(e.get("missing_decision", "ESCALATE"), f"{w}.missing_decision", ("BLOCK", "ESCALATE"))
        evs.append({"id": str(e["id"]), "when": e.get("when"), "require": list(e["require"]),
                    "decision": dec, "reason_code": _reason(e.get("reason_code", rc.EVIDENCE_MISSING), f"{w}.reason_code")})

    # confidence
    conf = data.get("confidence")
    if conf is not None:
        _keys(conf, {"minimum_to_act", "below_minimum", "when_missing"}, "policy.confidence", required=("minimum_to_act",))
        m = conf["minimum_to_act"]
        if isinstance(m, bool) or not isinstance(m, (int, float)) or not 0 <= m <= 1:
            _err("policy.confidence.minimum_to_act", "must be a number in [0, 1]")
        below = conf.get("below_minimum") or {}
        _keys(below, {"decision", "reason_code"}, "policy.confidence.below_minimum")
        wm = conf.get("when_missing", "ignore")
        if wm not in ("ignore", "escalate"):
            _err("policy.confidence.when_missing", "must be 'ignore' or 'escalate'")
        conf = {"minimum": m,
                "decision": _decision(below.get("decision", "ESCALATE"), "policy.confidence.below_minimum.decision", ("BLOCK", "ESCALATE")),
                "reason_code": _reason(below.get("reason_code", rc.INSUFFICIENT_CONFIDENCE), "policy.confidence.below_minimum.reason_code"),
                "when_missing": wm}

    # judgment_required: [{ "action.type": "x" }] or [{ when: cond, reason_code? , id? }]
    jr = []
    jr_in = data.get("judgment_required") or []
    if not isinstance(jr_in, list):
        _err("policy.judgment_required", "must be a list")
    for i, j in enumerate(jr_in):
        w = f"policy.judgment_required[{i}]"
        if not isinstance(j, dict) or not j:
            _err(w, "must be a mapping")
        if "when" in j:
            _keys(j, {"id", "when", "reason_code"}, w, required=("when",))
            validate_condition(j["when"], f"{w}.when")
            cond = j["when"]
            reason = _reason(j.get("reason_code", rc.JUDGMENT_REQUIRED), f"{w}.reason_code")
            jid = str(j.get("id", f"judgment_required[{i}]"))
        else:
            leaves = []
            for p, v in j.items():
                _path(p, w)
                if not _scalar(v):
                    _err(w, f"{p}: shorthand value must be a scalar (use 'when' for complex conditions)")
                leaves.append({"field": p, "op": "eq", "value": v})
            cond = leaves[0] if len(leaves) == 1 else {"all": leaves}
            reason = rc.JUDGMENT_REQUIRED
            jid = f"judgment_required[{i}]"
        jr.append({"id": jid, "when": cond, "reason_code": reason})

    # resolver
    res = data.get("resolver") or {}
    _keys(res, {"enabled", "mode", "not_resolvable"}, "policy.resolver")
    if "enabled" in res and not isinstance(res["enabled"], bool):
        _err("policy.resolver.enabled", "must be true or false")
    nr = res.get("not_resolvable", sorted(rc.NOT_AUTO_RESOLVABLE))
    if not isinstance(nr, list) or any(not rc.is_valid(x) for x in nr):
        _err("policy.resolver.not_resolvable", "must be a list of reason codes")
    resolver = {"enabled": res.get("enabled", True), "mode": res.get("mode", "external"),
                "not_resolvable": tuple(nr)}

    recs = data.get("records") or {}
    _keys(recs, {"falsifier_horizon_days"}, "policy.records")
    horizon = recs.get("falsifier_horizon_days", 30)
    if isinstance(horizon, bool) or not isinstance(horizon, int) or not 1 <= horizon <= 3650:
        _err("policy.records.falsifier_horizon_days", "must be an integer 1..3650")

    return Policy(raw=data, hash=phash, policy_id=data.get("policy_id"), policy_version=data.get("policy_version"),
                  unmatched_decision=unmatched, unmatched_reason=unmatched_reason, rules=tuple(rules),
                  authorization=auth, risk=risk, irreversibility=irr, evidence_requirements=tuple(evs),
                  confidence=conf, judgment_required=tuple(jr), resolver=resolver,
                  falsifier_horizon_days=horizon, source=source)


def load_policy(policy) -> Policy:
    """Accepts a Policy, a dict, a path to a .yaml/.yml/.json file, or YAML text."""
    if isinstance(policy, Policy):
        return policy
    if isinstance(policy, dict):
        return parse_policy(policy)
    if isinstance(policy, os.PathLike) or (isinstance(policy, str) and "\n" not in policy):
        path = os.fspath(policy)
        if not os.path.isfile(path):
            raise PolicyError(f"policy file not found: {path}")
        if os.path.getsize(path) > MAX_POLICY_BYTES:
            raise PolicyError(f"policy file exceeds {MAX_POLICY_BYTES} bytes")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if path.endswith(".json"):
            def _no_dups(pairs):
                out = {}
                for k, v in pairs:
                    if k in out:
                        raise PolicyError(f"duplicate key {k!r}")
                    out[k] = v
                return out
            try:
                data = json.loads(text, object_pairs_hook=_no_dups)
            except json.JSONDecodeError as e:
                raise PolicyError(f"invalid JSON: {e}") from e
        else:
            data = load_yaml(text)
        return parse_policy(data, source=path)
    if isinstance(policy, str):
        if len(policy.encode("utf-8")) > MAX_POLICY_BYTES:
            raise PolicyError(f"policy text exceeds {MAX_POLICY_BYTES} bytes")
        return parse_policy(load_yaml(policy))
    raise PolicyError(f"unsupported policy type {type(policy).__name__}")


__all__ = ["Policy", "Rule", "load_policy", "parse_policy", "LEVELS", "LEVEL_RANK", "DECISIONS", "canonical_json"]
