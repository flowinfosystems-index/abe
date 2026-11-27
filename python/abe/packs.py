"""Starter policy packs: ready-made rules for the actions agents most often get wrong.

    abe init --list-packs
    abe init --pack refunds
    abe init --pack payments --pack customer-email     # combine packs into one policy

Each pack is an ordinary Abe policy under abe/templates/packs/. Edit the amounts, then validate it. A single
pack is copied as written (comments included); several packs are merged into one policy: rules are
concatenated, risk mappings are combined, and anything no rule matches still ESCALATEs.
"""
from __future__ import annotations

import json
from importlib import resources

import yaml

from .policy import load_policy
from .yaml_safe import load_yaml

# One example request per pack, used by `abe init --pack` so the first `abe check` shows the pack working.
SAMPLES = {
    "refunds": {"action": {"type": "refund", "amount": 1200, "order_id": "A-1042"},
                "context": {"agent_id": "support-agent"}},
    "payments": {"action": {"type": "wire_transfer", "amount": 48000, "payee": "Acme Supply", "new_payee": True},
                 "context": {"agent_id": "finance-agent"}},
    "purchasing": {"action": {"type": "purchase", "amount": 12500, "item": "servers", "vendor": "Dell"},
                   "context": {"agent_id": "procurement-agent"}},
    "subscriptions": {"action": {"type": "subscribe", "amount": 1188, "interval": "year", "product": "Analytics Pro"},
                      "context": {"agent_id": "ops-agent"}},
    "customer-email": {"action": {"type": "send_email", "to": "customer@example.com", "recipient_count": 1,
                                  "body": "We'll issue a full refund today."},
                       "context": {"agent_id": "support-agent"}},
    "deploys": {"action": {"type": "deploy", "service": "api", "environment": "production"},
                "context": {"agent_id": "coding-agent"}},
    "data-changes": {"action": {"type": "execute_sql", "query": "DELETE FROM users WHERE last_login < '2025-01-01'"},
                     "context": {"agent_id": "data-agent"}},
}


class PackError(ValueError):
    pass


def _dir():
    return resources.files("abe").joinpath("templates").joinpath("packs")


def list_packs() -> list[tuple[str, str]]:
    """(name, one-line summary) for every pack, sorted by name."""
    out = []
    for entry in _dir().iterdir():
        if not entry.name.endswith(".yaml"):
            continue
        name = entry.name[: -len(".yaml")]
        first = entry.read_text(encoding="utf-8").splitlines()[0]
        summary = first.split(".", 1)[1].strip() if first.startswith("# Abe pack:") and "." in first else ""
        out.append((name, summary))
    return sorted(out)


def pack_text(name: str) -> str:
    names = [n for n, _ in list_packs()]
    if name not in names:
        raise PackError(f"unknown pack {name!r}; available: {', '.join(names)}")
    return _dir().joinpath(f"{name}.yaml").read_text(encoding="utf-8")


def build(names: list[str]) -> str:
    """Policy YAML for one pack (verbatim) or several (merged). Always a valid policy."""
    names = list(dict.fromkeys(names))  # drop repeats, keep order
    if not names:
        raise PackError("no pack named")
    if len(names) == 1:
        text = pack_text(names[0])
        load_policy(load_yaml(text))  # never hand out a pack that does not load
        return text
    docs = [load_yaml(pack_text(n)) for n in names]
    merged: dict = {
        "version": "0.1",
        "policy_id": "pack-" + "-".join(names),
        "policy_version": max(str(d.get("policy_version", "")) for d in docs),
        "defaults": {"unmatched": "ESCALATE"},
        "rules": [r for d in docs for r in d.get("rules", [])],
    }
    evidence = [e for d in docs for e in d.get("evidence_requirements", [])]
    if evidence:
        merged["evidence_requirements"] = evidence
    risks = [d["risk"] for d in docs if d.get("risk")]
    if risks:
        levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        merged["risk"] = {
            "defaults": {"level": max((r.get("defaults", {}).get("level", "LOW") for r in risks), key=levels.index)},
            "mappings": [m for r in risks for m in r.get("mappings", [])],
            "escalate_at": sorted({x for r in risks for x in r.get("escalate_at", [])}, key=levels.index),
        }
    ids = [r.get("id") for r in merged["rules"]]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise PackError(f"packs share rule ids: {', '.join(dupes)}")
    load_policy(merged)
    header = (f"# Abe policy built from packs: {', '.join(names)}\n"
              "# Docs: https://fjp.flowinfo.co/abe    Edit the amounts, then: abe validate-policy <file>\n"
              "# Anything no rule matches needs judgment (fail closed).\n")
    return header + yaml.safe_dump(merged, sort_keys=False, allow_unicode=True, width=120)


def sample_request(names: list[str]) -> str:
    sample = SAMPLES.get(names[0]) if names else None
    return json.dumps(sample, indent=2) + "\n" if sample else ""


__all__ = ["list_packs", "pack_text", "build", "sample_request", "PackError", "SAMPLES"]
