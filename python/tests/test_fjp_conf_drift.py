"""Drift check: Abe's built-in FJP-CONF checks must agree with the published reference suite.

Abe ships its own port of the FJP-CONF v0.1 record checks so it can run offline with no
dependencies. This test fails the build if that port drifts from the reference package
(`fjp-conformance` on PyPI), which is the single source of truth for the standard.
"""
import json
import pathlib

import pytest

ref = pytest.importorskip("conformance", reason="install the dev extra: pip install -e 'python[dev]'")
from conformance import checks as ref_checks, schema as ref_schema  # noqa: E402

from abe.conformance import fjp_conf as abe_conf  # noqa: E402

FALSIFIERS = [
    "Manager approval recorded before execution",
    "Vendor misses the Oct 15 delivery date",
    "Price rises above $798 before 2026-10-13",
    "Conditions may change.",
    "Conditions may change. (per Reuters)",
    "If circumstances change",
    "Vendor confirms duplicate. (per Flow)",
    "TBD",
    "",
]


def test_same_spec_version():
    assert abe_conf.SPEC_VERSION == ref_schema.SPEC_VERSION


def test_same_vacuity_and_concreteness_vocabulary():
    assert tuple(abe_conf.VACUITY_BLOCKLIST) == tuple(ref_schema.VACUITY_BLOCKLIST)
    assert tuple(abe_conf.CONCRETENESS_MARKERS) == tuple(ref_schema.CONCRETENESS_MARKERS)


@pytest.mark.parametrize("condition", FALSIFIERS)
def test_same_falsifier_verdicts(condition):
    assert abe_conf._is_vacuous(condition) == ref_checks._is_vacuous(condition)


def _record(condition: str) -> dict:
    return {
        "record_id": "drift-1",
        "timestamp": "2026-10-04T12:00:00Z",
        "fjp_conf_version": ref_schema.SPEC_VERSION,
        "signal": {"id": "sig-1", "description": "Agent proposes a $12,000 refund; authority is $5,000.",
                   "sources": ["policy:refunds"], "observed_at": "2026-10-04T12:00:00Z"},
        "judgment": {"id": "jud-1", "assessment": "Refund exceeds autonomous authority.",
                     "confidence": 0.9, "signal_ref": "sig-1"},
        "action": {"directive": "ESCALATE: route to a manager.", "judgment_ref": "jud-1"},
        "falsifier": {"condition": condition, "checkable": True, "status": "open"},
    }


@pytest.mark.parametrize("condition", FALSIFIERS)
@pytest.mark.parametrize("level", [0, 1, 2])
def test_same_record_verdicts(condition, level):
    rec = _record(condition)
    assert abe_conf.conforms(abe_conf.evaluate(rec, level)) == ref_checks.conforms(ref_checks.evaluate(rec, level))
