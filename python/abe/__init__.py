"""Abe — Act. Block. Escalate. One control point before an AI agent acts.

Deterministic ACT / BLOCK / ESCALATE plus an immutable Judgment-Grounded Record for every call.
Runs entirely locally: no network, no model, no Flow account.
"""
__version__ = "0.1.0"

from .exceptions import (EvaluationError, FJPError, PolicyError, RecordImmutableError,  # noqa: E402
                         RequestError, SigningError)
from .models import GateResult, Record, Resolution  # noqa: E402
from .policy import Policy, load_policy  # noqa: E402
from .gate import Gate, Resolver  # noqa: E402

Abe = Gate  # the product name; Gate is the protocol role (FJP Gate)
from .records import evaluate_falsifier, verify_hash  # noqa: E402

ACT, BLOCK, ESCALATE = "ACT", "BLOCK", "ESCALATE"

__all__ = ["Abe", "Gate", "GateResult", "Record", "Resolution", "Resolver", "Policy", "load_policy",
           "verify_hash", "evaluate_falsifier", "FJPError", "PolicyError", "RequestError", "EvaluationError",
           "RecordImmutableError", "SigningError", "ACT", "BLOCK", "ESCALATE", "__version__"]
