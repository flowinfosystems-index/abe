"""Result and record types. Records are deeply immutable once created."""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .canonical import to_plain
from .exceptions import RecordImmutableError


def _freeze(v):
    if isinstance(v, dict):
        return MappingProxyType({k: _freeze(x) for k, x in v.items()})
    if isinstance(v, list):
        return tuple(_freeze(x) for x in v)
    return v


class _FrozenView:
    """Attribute + item access over a frozen mapping. Mutation raises RecordImmutableError."""
    __slots__ = ("_data",)

    def __init__(self, data):
        object.__setattr__(self, "_data", data)

    def __getattr__(self, name):
        try:
            v = self._data[name]
        except KeyError:
            raise AttributeError(name) from None
        return _FrozenView(v) if isinstance(v, MappingProxyType) else v

    def __getitem__(self, key):
        v = self._data[key]
        return _FrozenView(v) if isinstance(v, MappingProxyType) else v

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        return key in self._data

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def keys(self):
        return self._data.keys()

    def items(self):
        return ((k, self[k]) for k in self._data)

    def __setattr__(self, name, value):
        raise RecordImmutableError("Judgment-Grounded Records are immutable; append a linked record instead")

    __delattr__ = __setattr__

    def __setitem__(self, key, value):
        raise RecordImmutableError("Judgment-Grounded Records are immutable; append a linked record instead")

    __delitem__ = __setitem__

    def to_dict(self) -> dict:
        """A mutable deep copy (plain JSON types). Changing it does not change the record."""
        return to_plain(self._data)

    def __eq__(self, other):
        if isinstance(other, _FrozenView):
            return self.to_dict() == other.to_dict()
        if isinstance(other, dict):
            return self.to_dict() == other
        return NotImplemented

    def __hash__(self):
        return hash(self._data.get("record_hash") or id(self))

    def __repr__(self):
        return f"{type(self).__name__}({self.to_dict()!r})"


class Record(_FrozenView):
    """An FJP Judgment-Grounded Record (JGR). Immutable: `record.decision = "ACT"` raises."""
    __slots__ = ()

    @classmethod
    def from_dict(cls, d: dict) -> "Record":
        return cls(_freeze(to_plain(d)))

    def evaluation_content(self) -> dict:
        """The deterministic part of the record: excludes ids, timestamps and integrity fields."""
        d = self.to_dict()
        keep = ("protocol", "version", "event_type", "decision", "reason_code", "reason_codes", "matched_rules",
                "risk", "irreversibility", "evidence_present", "evidence_missing", "confidence", "policy",
                "request_hash", "actor", "evaluation_time", "time_source", "resolver", "mode")
        return {k: d[k] for k in keep if k in d}


@dataclass(frozen=True)
class GateResult:
    decision: str
    reason_code: str
    record: Record
    risk_level: str
    irreversibility_level: str
    matched_rules: tuple = ()
    reason_codes: tuple = ()
    missing_evidence: tuple = ()
    gate_decision: str | None = None           # the Gate's own decision when a resolver changed it
    records: tuple = ()                        # [gate record, resolution record?]
    resolution: dict | None = None
    warnings: tuple = ()
    mode: str = "enforce"                      # "shadow": recorded for comparison, not enforced

    @property
    def enforced(self) -> bool:
        """False in shadow mode: keep your existing approval process and don't act on `decision`."""
        return self.mode != "shadow"

    @property
    def record_id(self) -> str:
        return self.record.record_id

    @property
    def allowed(self) -> bool:
        """True only for ACT. BLOCK and ESCALATE both mean: do not execute now."""
        return self.decision == "ACT"

    @property
    def timestamp(self) -> str:
        return self.record.timestamp

    def to_dict(self) -> dict:
        """The FJP v0.1 response format."""
        out: dict[str, Any] = {
            "protocol": "FJP",
            "version": "0.1",
            "decision": self.decision,
            "reason_code": self.reason_code,
            "risk_level": self.risk_level,
            "record_id": self.record_id,
            "timestamp": self.timestamp,
        }
        if self.matched_rules:
            out["matched_rules"] = list(self.matched_rules)
        if self.missing_evidence:
            out["missing_evidence"] = list(self.missing_evidence)
        if self.gate_decision and self.gate_decision != self.decision or self.resolution:
            out["original_gate_decision"] = self.gate_decision
            out["gate_record_id"] = self.records[0].record_id
        if self.resolution:
            out["resolution"] = dict(self.resolution)
        if self.mode == "shadow":
            out["mode"] = "shadow"
        return out


@dataclass(frozen=True)
class Resolution:
    """What a resolver returns for an ESCALATE. decision must be ACT, BLOCK or ESCALATE."""
    decision: str
    reason: str
    reason_code: str | None = None
    confidence: float | None = None
    falsifiers: tuple = ()
    resolver_type: str = "EXTERNAL"
    implementation: str = "custom"
    implementation_version: str = "0"
    reference: str | None = None               # e.g. the resolver's own request/record id
    evidence: dict = field(default_factory=dict)
    external_record: dict | None = None        # e.g. Flow's own JGR, preserved verbatim
