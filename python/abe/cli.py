"""abe — Abe command line.

  abe init                               write abe-policy.yaml + request.json to start from
  abe check request.json                 Decision / Reason / Record   (exit 0 ACT, 10 BLOCK, 20 ESCALATE)
  abe validate-policy abe-policy.yaml
  abe validate-record jgr.json [--public-key pub.pem]
  abe conformance [--level 3] [--bench]
  abe serve [--host 127.0.0.1] [--port 8787]
  abe mcp                                MCP server over stdio (pip install "abe-ai[mcp]")
  abe keygen [--out-dir .]               Ed25519 key pair for local record signing
  abe outcome RECORD_ID executed --store sqlite:abe.db

--policy defaults to $ABE_POLICY, then ./abe-policy.yaml
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from importlib import resources

from . import __version__

EXIT = {"ACT": 0, "BLOCK": 10, "ESCALATE": 20}


def _policy_arg(args) -> str:
    if args.policy or os.environ.get("ABE_POLICY") or os.environ.get("FJP_POLICY"):
        return args.policy or os.environ.get("ABE_POLICY") or os.environ["FJP_POLICY"]
    # abe-policy.yaml, or a pre-rename fjp-policy.yaml if that's what exists
    return "fjp-policy.yaml" if not os.path.exists("abe-policy.yaml") and os.path.exists("fjp-policy.yaml") else "abe-policy.yaml"


def _load_json(path: str):
    raw = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
    if len(raw.encode("utf-8")) > 1_048_576:
        raise SystemExit("input exceeds 1 MiB")
    return json.loads(raw)


def _gate(args, default_store: str | None = None):
    from .exceptions import PolicyError
    from .gate import Gate
    from .stores import store_from_uri
    signer = None
    key = getattr(args, "sign_key", None) or (os.environ.get("ABE_SIGNING_KEY") or os.environ.get("FJP_SIGNING_KEY"))
    if key:
        from .signing import Signer
        signer = Signer.from_file(key, key_id=getattr(args, "key_id", None) or "local:key:1")
    try:
        return Gate(_policy_arg(args), store=store_from_uri(getattr(args, "store", None) or default_store),
                    signer=signer)
    except PolicyError as e:
        print(f"policy error: {e}", file=sys.stderr)
        raise SystemExit(2) from e


def cmd_init(args):
    tpl = resources.files("abe").joinpath("templates")
    for name, dest in (("starter.yaml", args.policy_out), ("request.json", args.request_out)):
        if os.path.exists(dest) and not args.force:
            print(f"exists, skipped: {dest} (use --force to overwrite)")
            continue
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(tpl.joinpath(name).read_text(encoding="utf-8"))
        print(f"wrote {dest}")
    print(f"\nnext:  abe check {args.request_out} --policy {args.policy_out}")
    return 0


def cmd_check(args):
    gate = _gate(args)
    try:
        req = _load_json(args.request)
    except (OSError, json.JSONDecodeError) as e:
        print(f"cannot read request: {e}", file=sys.stderr)
        req = None  # still answered, fail closed
    r = gate.check(req if isinstance(req, dict) else None)
    if args.json:
        out = r.to_dict()
        if args.record:
            out["record"] = r.record.to_dict()
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"Decision: {r.decision}")
        print(f"Reason: {r.reason_code}")
        if r.matched_rules:
            print(f"Rules: {', '.join(r.matched_rules)}")
        if r.missing_evidence:
            print(f"Missing evidence: {', '.join(r.missing_evidence)}")
        print(f"Risk: {r.risk_level}")
        print(f"Record: {r.record_id}")
        for w in r.warnings:
            print(f"Warning: {w}", file=sys.stderr)
        if args.record:
            print(json.dumps(r.record.to_dict(), indent=2, ensure_ascii=False))
    if args.record_out:
        with open(args.record_out, "w", encoding="utf-8") as fh:
            json.dump(r.record.to_dict(), fh, indent=2, ensure_ascii=False)
    return EXIT[r.decision]


def cmd_validate_policy(args):
    from .exceptions import PolicyError
    from .policy import load_policy
    try:
        p = load_policy(args.path)
    except PolicyError as e:
        print(f"INVALID: {e}")
        return 1
    print(f"VALID  {args.path}")
    print(f"  policy_id:      {p.policy_id}")
    print(f"  policy_version: {p.policy_version}")
    print(f"  hash:           {p.hash}")
    print(f"  rules: {len(p.rules)}  evidence requirements: {len(p.evidence_requirements)}  "
          f"judgment boundaries: {len(p.judgment_required)}  unmatched -> {p.unmatched_decision}")
    return 0


def validate_record_dict(rec) -> list[str]:
    from . import reason_codes as rc
    from .conformance import RECORD_REQUIRED, fjp_conf
    from .records import verify_hash
    problems = []
    if not isinstance(rec, dict):
        return ["record must be a JSON object"]
    problems += [f"missing field {k}" for k in RECORD_REQUIRED if k not in rec]
    if rec.get("protocol") != "FJP":
        problems.append('protocol must be "FJP"')
    if rec.get("version") != "0.1":
        problems.append('version must be "0.1"')
    if rec.get("event_type") not in ("DECISION", "RESOLUTION", "OUTCOME"):
        problems.append("event_type must be DECISION, RESOLUTION or OUTCOME")
    if rec.get("decision") not in ("ACT", "BLOCK", "ESCALATE"):
        problems.append("decision must be ACT, BLOCK or ESCALATE")
    if "reason_code" in rec and rec.get("event_type") != "OUTCOME" and not rc.is_valid(rec["reason_code"]):
        problems.append(f"reason_code {rec['reason_code']!r} is not standard or namespaced")
    if "record_hash" in rec and not verify_hash(rec):
        problems.append("record_hash does not match the record contents (modified after creation?)")
    problems += [f"FJP-CONF {c.check_id}: {c.detail}" for c in fjp_conf.evaluate(rec, 2) if not c.passed]
    return problems


def cmd_validate_record(args):
    try:
        rec = _load_json(args.path)
    except (OSError, json.JSONDecodeError) as e:
        print(f"INVALID: cannot read record: {e}")
        return 2
    problems = validate_record_dict(rec)
    if args.public_key and isinstance(rec, dict):
        from .signing import verify_signature
        with open(args.public_key, "rb") as fh:
            if not verify_signature(rec, fh.read()):
                problems.append("signature missing or does not verify with the given public key")
    if problems:
        print(f"INVALID  {args.path}")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"VALID  {args.path}  ({rec.get('record_id')}, {rec.get('event_type')} {rec.get('decision')}, "
          f"hash verified{', signature verified' if args.public_key else ''}; FJP-CONF v0.1 L0-L2)")
    return 0


def cmd_conformance(args):
    from . import conformance
    checks = conformance.run(args.fixtures, level=args.level)
    ok, text = conformance.report(checks, args.level)
    print(text)
    if args.bench:
        b = conformance.benchmark()
        print(f"\nperformance: p50 {b['p50_ms']} ms  p95 {b['p95_ms']} ms  (n={b['n']}; targets p50 < 2 ms, p95 < 10 ms)")
    return 0 if ok else 1


def cmd_serve(args):
    from .server import serve
    gate = _gate(args, default_store="memory:")
    serve(gate, host=args.host, port=args.port, token=args.token or (os.environ.get("ABE_TOKEN") or os.environ.get("FJP_TOKEN")),
          allow_remote=args.allow_remote)
    return 0


def cmd_mcp(args):
    from .mcp_server import run_stdio
    run_stdio(_gate(args, default_store="memory:"))
    return 0


def cmd_keygen(args):
    from .signing import generate_keypair
    priv, pub = generate_keypair()
    os.makedirs(args.out_dir, exist_ok=True)
    pp, bp = os.path.join(args.out_dir, "abe-signing-key.pem"), os.path.join(args.out_dir, "abe-signing-key.pub.pem")
    if os.path.exists(pp) and not args.force:
        print(f"exists: {pp} (use --force)")
        return 1
    fd = os.open(pp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv)
    with open(bp, "wb") as fh:
        fh.write(pub)
    print(f"wrote {pp} (private, keep secret; mode 600)\nwrote {bp} (public, share with auditors)")
    print(f"\nsign records:  abe check request.json --sign-key {pp}\nverify:        abe validate-record jgr.json --public-key {bp}")
    return 0


def cmd_outcome(args):
    gate = _gate(args)
    if gate.store is None:
        print("outcome needs --store (the store that holds the original record)", file=sys.stderr)
        return 2
    details = json.loads(args.details) if args.details else {}
    rec = gate.record_outcome(args.record_id, args.status, details)
    print(json.dumps(rec.to_dict(), indent=2, ensure_ascii=False))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="abe", description="Abe — one control point before an AI agent acts.")
    p.add_argument("--version", action="version", version=f"abe-ai {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def with_policy(sp, store=True, sign=False):
        sp.add_argument("--policy", help="policy file (default $ABE_POLICY or ./abe-policy.yaml)")
        if store:
            sp.add_argument("--store", help="record store: memory: | file:records.jsonl | sqlite:abe.db")
        if sign:
            sp.add_argument("--sign-key", help="Ed25519 private key PEM (or $ABE_SIGNING_KEY)")
            sp.add_argument("--key-id", help="key id written into signatures (default local:key:1)")
        return sp

    s = sub.add_parser("init", help="write a starter policy and request")
    s.add_argument("--policy-out", default="abe-policy.yaml")
    s.add_argument("--request-out", default="request.json")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)

    s = with_policy(sub.add_parser("check", help="evaluate a request (file or - for stdin)"), sign=True)
    s.add_argument("request")
    s.add_argument("--json", action="store_true", help="print the FJP response as JSON")
    s.add_argument("--record", action="store_true", help="also print the full record")
    s.add_argument("--record-out", help="write the record to this file")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("validate-policy", help="validate a policy file")
    s.add_argument("path")
    s.set_defaults(fn=cmd_validate_policy)

    s = sub.add_parser("validate-record", help="validate a Judgment-Grounded Record")
    s.add_argument("path")
    s.add_argument("--public-key", help="verify the Ed25519 signature with this public key PEM")
    s.set_defaults(fn=cmd_validate_record)

    s = sub.add_parser("conformance", help="run the FJP-CONF Gate profile suite")
    s.add_argument("--level", type=int, default=3, choices=(0, 1, 2, 3))
    s.add_argument("--fixtures", help="alternate fixtures directory")
    s.add_argument("--bench", action="store_true", help="also measure evaluation latency")
    s.set_defaults(fn=cmd_conformance)

    s = with_policy(sub.add_parser("serve", help="local HTTP server (127.0.0.1 by default)"), sign=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--token", help="require Authorization: Bearer <token> (or $ABE_TOKEN)")
    s.add_argument("--allow-remote", action="store_true", help="permit binding a non-loopback interface")
    s.set_defaults(fn=cmd_serve)

    s = with_policy(sub.add_parser("mcp", help="MCP server over stdio"), sign=True)
    s.set_defaults(fn=cmd_mcp)

    s = sub.add_parser("keygen", help="generate an Ed25519 signing key pair")
    s.add_argument("--out-dir", default=".")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_keygen)

    s = with_policy(sub.add_parser("outcome", help="append an OUTCOME record"))
    s.add_argument("record_id")
    s.add_argument("status", choices=("executed", "failed", "reverted", "cancelled", "approved", "rejected"))
    s.add_argument("--details", help="JSON object, e.g. '{\"request_hash\": \"sha256:...\"}'")
    s.set_defaults(fn=cmd_outcome)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
