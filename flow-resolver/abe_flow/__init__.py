"""abe-flow — send FJP Gate escalations to Flow's judgment service.

    import os
    from abe import Gate
    from abe_flow import FlowResolver

    gate = Gate("abe-policy.yaml", resolver=FlowResolver(api_key=os.environ["FLOW_API_KEY"]))

Behavior:
    Gate -> ACT       return ACT        (Flow is never called)
    Gate -> BLOCK     return BLOCK      (Flow is never called; a resolver can never loosen a BLOCK)
    Gate -> ESCALATE  call Flow's judge, map its verb, append a linked RESOLUTION record

Only escalations create Flow cost. If Flow is unreachable, out of credits, rate-limited, slow, or returns degraded
output, the result simply stays ESCALATE. Escalations marked HUMAN_APPROVAL_REQUIRED, USER_CONFIRMATION_REQUIRED or
EVALUATION_FAILURE are never sent (policy: resolver.not_resolvable).

Flow verb -> Gate decision:
    REACH          -> ACT       (only when Flow's confidence is in accept_act_confidence; default high, medium)
    SKIP           -> BLOCK
    WAIT           -> ESCALATE  (not now; Flow's counter-signal says what would change it)
    RESEARCH_FIRST -> ESCALATE  (gather the evidence Flow names, then check again)
    ESCALATE       -> ESCALATE  (a human should decide)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from typing import Callable, Iterable

from abe import Resolution

__version__ = "0.1.3"

DEFAULT_BASE_URL = "https://resolve.flowinfo.co"
VERB_TO_DECISION = {"REACH": "ACT", "SKIP": "BLOCK", "WAIT": "ESCALATE", "RESEARCH_FIRST": "ESCALATE",
                    "ESCALATE": "ESCALATE"}
CONFIDENCE_VALUE = {"high": 0.80, "medium": 0.55, "low": 0.30}  # same constants as the Flow resolver's JGRs
DEFAULT_REDACT = ("card_number", "cvv", "cvc", "account_number", "routing_number", "iban", "ssn", "password",
                  "secret", "api_key", "token", "authorization", "private_key")
MAX_CONTEXT = 19_000
MAX_RESPONSE = 1_048_576
# Flow Resolver attribution, current ("Flow") and legacy ("FJP").
_ATTRIBUTION = re.compile(r"\s*(\(\s*per (?:Flow|FJP)[^)]*\)|—\s*Judged by (?:Flow|FJP)\.?)\s*$", re.IGNORECASE)


class FlowError(Exception):
    """Flow could not be reached or refused the call. The Gate turns this into ESCALATE (unavailable)."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _strip_attribution(text: str) -> str:
    prev, text = None, (text or "").strip()
    while prev != text:
        prev, text = text, _ATTRIBUTION.sub("", text).strip()
    return text


def redact(value, keys: Iterable[str]):
    """Remove fields whose name contains any redaction key (case-insensitive), recursively."""
    ks = tuple(k.lower() for k in keys)
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if any(x in k.lower() for x in ks) else redact(v, ks)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, ks) for v in value]
    return value


Transport = Callable[[str, dict, bytes, float], tuple[int, bytes]]


def _ssl_context() -> ssl.SSLContext:
    """Verify TLS with certifi's CA bundle when available.

    python.org builds on macOS ship without system CA certificates, so the default context fails with
    CERTIFICATE_VERIFY_FAILED until "Install Certificates.command" is run. certifi (a dependency) avoids that.
    SSL_CERT_FILE / SSL_CERT_DIR, if set, still take precedence.
    """
    if os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR"):
        return ssl.create_default_context()
    try:
        import certifi  # noqa: PLC0415
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:  # pragma: no cover
        return ssl.create_default_context()


def _urllib_transport(url: str, headers: dict, body: bytes, timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:  # noqa: S310
            return resp.status, resp.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as e:
        return e.code, e.read(MAX_RESPONSE + 1)


class FlowResolver:
    """Resolver that asks Flow's judgment service about actions the Gate escalated."""

    implementation = "abe-flow"

    def __init__(self, api_key: str | None = None, *, base_url: str | None = None, timeout: float = 10.0,
                 redact_keys: Iterable[str] = DEFAULT_REDACT, accept_act_confidence: Iterable[str] = ("high", "medium"),
                 transport: Transport | None = None, include_context: bool = True, include_evidence: bool = True):
        self.api_key = api_key or os.environ.get("FLOW_API_KEY") or os.environ.get("FJP_API_KEY")
        if not self.api_key:
            raise ValueError("FlowResolver needs an API key (api_key=... or FLOW_API_KEY)")
        self.base_url = (base_url or os.environ.get("FLOW_RESOLVER_URL") or DEFAULT_BASE_URL).rstrip("/")
        if not (self.base_url.startswith("https://") or self.base_url.startswith("http://127.0.0.1")
                or self.base_url.startswith("http://localhost")):
            raise ValueError("base_url must be https:// (http only for localhost testing)")
        self.timeout = timeout
        self.redact_keys = tuple(redact_keys)
        self.accept_act_confidence = set(accept_act_confidence)
        self.transport = transport or _urllib_transport
        self.include_context, self.include_evidence = include_context, include_evidence

    # ------------------------------------------------------------ request building

    def build_judge_request(self, request: dict, gate_result) -> dict:
        rec = gate_result.record
        safe = redact(request, self.redact_keys)
        parts = [
            "PRE-EXECUTION JUDGMENT (FJP Gate escalation).",
            f"The agent's proposed action passed hard policy limits but the Gate escalated it: {rec.reason_code}"
            f" (all reasons: {', '.join(rec.reason_codes)}). Matched: {', '.join(rec.matched_rules) or 'none'}.",
            "Question: is this permitted action justified by the evidence, intent and context? "
            "REACH = proceed, SKIP = do not proceed, WAIT = not now, RESEARCH_FIRST = establish more first, "
            "ESCALATE = a human must decide.",
            f"Actor: {json.dumps(safe.get('actor', {}), ensure_ascii=False)}",
            f"Proposed action: {json.dumps({k: v for k, v in safe.get('action', {}).items()}, ensure_ascii=False)}",
            f"Risk: {gate_result.risk_level}. Irreversibility: {gate_result.irreversibility_level}. "
            f"Agent-supplied confidence (uncalibrated): {safe.get('confidence', 'not supplied')}.",
        ]
        if gate_result.missing_evidence:
            parts.append(f"Missing evidence: {', '.join(gate_result.missing_evidence)}.")
        if self.include_evidence and safe.get("evidence"):
            parts.append(f"Evidence: {json.dumps(safe['evidence'], ensure_ascii=False)}")
        if self.include_context and safe.get("context"):
            parts.append(f"Context: {json.dumps(safe['context'], ensure_ascii=False)}")
        context = "\n".join(parts)
        if len(context) > MAX_CONTEXT:
            context = context[: MAX_CONTEXT - 1] + "…"
        pol = rec.policy
        return {
            "context": context,
            "background": f"Policy {pol.id or 'unnamed'} version {pol.version or 'unversioned'} ({pol.hash}).",
            "sources": [f"fjp:gate-record:{rec.record_id}", f"fjp:policy:{pol.hash}", f"fjp:request:{rec.request_id}"],
            "observed_at": rec.evaluation_time,
        }

    def idempotency_key(self, gate_result) -> str:
        rec = gate_result.record
        return hashlib.sha256(f"{rec.request_id}|{rec.request_hash}|{rec.policy.hash}".encode()).hexdigest()

    # ------------------------------------------------------------ Resolver interface

    def resolve(self, request: dict, gate_result) -> Resolution:
        body = json.dumps(self.build_judge_request(request, gate_result), ensure_ascii=False).encode("utf-8")
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json",
                   "Accept": "application/json", "X-Idempotency-Key": self.idempotency_key(gate_result),
                   "User-Agent": f"{self.implementation}/{__version__}"}
        try:
            status, raw = self.transport(f"{self.base_url}/api/v1/tools/judge", headers, body, self.timeout)
        except Exception as e:  # noqa: BLE001 - network failures, timeouts
            raise FlowError(f"Flow unreachable: {type(e).__name__}: {e}") from e
        if len(raw) > MAX_RESPONSE:
            raise FlowError("Flow response too large")
        if status == 401:
            raise FlowError("Flow rejected the API key (401)", status)
        if status == 402:
            raise FlowError("Flow account is out of credits (402)", status)
        if status == 429:
            raise FlowError("Flow rate limit reached (429)", status)
        if status != 200:
            raise FlowError(f"Flow returned HTTP {status}", status)
        try:
            out = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise FlowError("Flow returned invalid JSON") from e
        return self.to_resolution(out)

    def to_resolution(self, out: dict) -> Resolution:
        verb = out.get("verb")
        if verb not in VERB_TO_DECISION:
            raise FlowError(f"Flow returned an unknown verb {verb!r}")
        bucket = out.get("confidence") if out.get("confidence") in CONFIDENCE_VALUE else "low"
        jgr = out.get("jgr") if isinstance(out.get("jgr"), dict) else None
        framing = str(out.get("framing") or "").strip()
        counter = _strip_attribution(str(out.get("counter_signal") or ""))
        evidence = {"flow_verb": verb, "flow_timing": out.get("timing"), "flow_confidence": bucket,
                    "flow_request_id": out.get("request_id")}
        ref = out.get("request_id")

        if jgr is None:
            # Degraded output: never act on it (fjp-resolve R3).
            return Resolution(decision="ESCALATE", reason="Flow returned degraded output without a record; not acted on.",
                              reason_code="flow.degraded", confidence=None, resolver_type="FLOW",
                              implementation=self.implementation, implementation_version=__version__,
                              reference=ref, evidence=evidence)

        decision = VERB_TO_DECISION[verb]
        reason = framing or f"Flow verb {verb}."
        if decision == "ACT" and bucket not in self.accept_act_confidence:
            decision = "ESCALATE"
            reason = f"Flow leaned REACH with {bucket} confidence, below this resolver's bar; escalating. " + reason
        conf = jgr.get("judgment", {}).get("confidence")
        if not isinstance(conf, (int, float)) or isinstance(conf, bool):
            conf = CONFIDENCE_VALUE[bucket]
        falsifier = (jgr.get("falsifier") or {}).get("condition") or counter
        return Resolution(decision=decision, reason=reason, reason_code=f"flow.{verb.lower()}",
                          confidence=float(conf), falsifiers=tuple(x for x in (falsifier,) if x),
                          resolver_type="FLOW", implementation=self.implementation,
                          implementation_version=__version__, reference=ref, evidence=evidence, external_record=jgr)

    # ------------------------------------------------------------ outcomes (free on Flow)

    def report_outcome(self, flow_request_id: str, outcome: str, notes: str | None = None) -> dict:
        """Tell Flow how its judgment turned out: CORRECT | WRONG | PARTIAL. Free; feeds Flow's calibration."""
        if outcome not in ("CORRECT", "WRONG", "PARTIAL"):
            raise ValueError("outcome must be CORRECT, WRONG or PARTIAL")
        body = json.dumps({"request_id": flow_request_id, "outcome": outcome, "notes": notes}).encode()
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json",
                   "X-Idempotency-Key": hashlib.sha256(f"{flow_request_id}|{outcome}".encode()).hexdigest()}
        status, raw = self.transport(f"{self.base_url}/api/v1/outcome", headers, body, self.timeout)
        if status != 200:
            raise FlowError(f"Flow outcome report failed: HTTP {status}", status)
        return json.loads(raw)


__all__ = ["FlowResolver", "FlowError", "VERB_TO_DECISION", "redact", "__version__"]
