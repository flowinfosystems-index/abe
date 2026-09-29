"""Abe exceptions. Gate.check() never raises these to the caller: it fails closed."""


class FJPError(Exception):
    """Base class."""


class PolicyError(FJPError):
    """The policy file is missing, unsafe, or invalid."""


class RequestError(FJPError):
    """The request cannot be parsed safely (bad types, too large, too deep, non-JSON values)."""


class EvaluationError(FJPError):
    """A rule could not be evaluated deterministically (e.g. comparing a number to a string)."""


class RecordImmutableError(FJPError, TypeError):
    """Raised on any attempt to modify a Judgment-Grounded Record after creation."""


class SigningError(FJPError):
    """Signing or signature verification failed or is unavailable."""
