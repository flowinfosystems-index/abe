"""Cross-language parity: Python and TypeScript SDKs must agree byte-for-byte.

For every golden fixture: same decision, reason codes, matched rules, request_hash and policy hash.
Records produced by each SDK (signed) must verify — hash, Ed25519 signature, FJP-CONF L0-L2 — in the other.
Run from the repo root after `npm run build` in typescript/:  python scripts/cross_language_check.py
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "python"))
from abe import Gate, verify_hash  # noqa: E402
from abe.conformance import fjp_conf  # noqa: E402
from abe.signing import Signer, generate_keypair, verify_signature  # noqa: E402

FIX = os.path.join(ROOT, "conformance", "fixtures")
cases = json.load(open(os.path.join(FIX, "decisions.json")))["cases"]
priv, pub = generate_keypair()
tmp = tempfile.mkdtemp()
open(os.path.join(tmp, "k.pem"), "wb").write(priv)
open(os.path.join(tmp, "k.pub.pem"), "wb").write(pub)

# Pin request_id and time so request_hash is comparable.
reqs = []
for c in cases:
    r = json.loads(json.dumps(c["request"]))
    if isinstance(r, dict):
        r["request_id"] = f"req_{c['id']}"
    reqs.append(r)
json.dump(reqs, open(os.path.join(tmp, "reqs.json"), "w"))

g = Gate(os.path.join(FIX, "policies", "standard.yaml"), signer=Signer(priv, "x:1"))
py = [g.check(r) for r in reqs]
json.dump([r.record.to_dict() for r in py], open(os.path.join(tmp, "py_records.json"), "w"))

node = f"""
import {{ readFileSync, writeFileSync }} from 'node:fs';
import {{ Gate, Ed25519Signer, verifyHash, verifySignature, fjpConf }} from '{ROOT}/typescript/dist/index.js';
const t = '{tmp}';
const reqs = JSON.parse(readFileSync(t + '/reqs.json', 'utf8'));
const g = new Gate({{ policy: '{FIX}/policies/standard.yaml', signer: Ed25519Signer.fromFile(t + '/k.pem', 'x:1') }});
const out = [];
for (const r of reqs) out.push((await g.check(r)).record);
writeFileSync(t + '/ts_records.json', JSON.stringify(out));
const pub = readFileSync(t + '/k.pub.pem', 'utf8');
const bad = JSON.parse(readFileSync(t + '/py_records.json', 'utf8')).filter(r => !(verifyHash(r) && verifySignature(r, pub) && fjpConf.conforms(fjpConf.evaluate(r, 2))));
console.log(JSON.stringify({{ policy_hash: g.policy.hash, py_records_failing_in_ts: bad.map(r => r.record_id) }}));
"""
res = subprocess.run(["node", "--input-type=module", "-e", node], capture_output=True, text=True)
if res.returncode:
    print(res.stderr)
    sys.exit(1)
ts_report = json.loads(res.stdout.strip().splitlines()[-1])
ts = json.load(open(os.path.join(tmp, "ts_records.json")))

problems = []
if ts_report["policy_hash"] != g.policy.hash:
    problems.append("policy hash differs")
problems += [f"python record {x} fails in TypeScript" for x in ts_report["py_records_failing_in_ts"]]
for c, p, t in zip(cases, py, ts):
    for k in ("decision", "reason_code", "reason_codes", "matched_rules", "evidence_missing", "evidence_present", "risk",
              "irreversibility", "confidence", "time_source"):
        if p.record.get(k) is not None and p.record.to_dict().get(k) != t.get(k):
            problems.append(f"{c['id']}: {k} py={p.record.to_dict().get(k)} ts={t.get(k)}")
    if c["expect"]["reason_code"] != "EVALUATION_FAILURE" and p.record.request_hash != t["request_hash"]:
        problems.append(f"{c['id']}: request_hash differs")
    if not (verify_hash(t) and verify_signature(t, pub) and fjp_conf.conforms(fjp_conf.evaluate(t, 2))):
        problems.append(f"{c['id']}: TypeScript record fails in Python")

# Shadow mode: same decisions as enforce, records marked, and each SDK's shadow records verify in the other.
from abe.replay import replay  # noqa: E402

gs = Gate(os.path.join(FIX, "policies", "standard.yaml"), signer=Signer(priv, "x:1"), mode="shadow")
py_shadow = [gs.check(r).record.to_dict() for r in reqs]
json.dump(py_shadow, open(os.path.join(tmp, "py_shadow.json"), "w"))
cases_path = os.path.join(tmp, "cases.jsonl")
with open(cases_path, "w") as fh:
    for c, r in zip(cases, reqs):
        fh.write(json.dumps({"id": c["id"], "request": r, "expected": c["expect"]["decision"]}) + "\n")
node2 = f"""
import {{ readFileSync, writeFileSync }} from 'node:fs';
import {{ Gate, Ed25519Signer, verifyHash, verifySignature, fjpConf, replay, loadCases }} from '{ROOT}/typescript/dist/index.js';
const t = '{tmp}';
const reqs = JSON.parse(readFileSync(t + '/reqs.json', 'utf8'));
const g = new Gate({{ policy: '{FIX}/policies/standard.yaml', signer: Ed25519Signer.fromFile(t + '/k.pem', 'x:1'), mode: 'shadow' }});
const out = [];
for (const r of reqs) out.push((await g.check(r)).record);
writeFileSync(t + '/ts_shadow.json', JSON.stringify(out));
const pub = readFileSync(t + '/k.pub.pem', 'utf8');
const bad = JSON.parse(readFileSync(t + '/py_shadow.json', 'utf8')).filter(r => !(r.mode === 'shadow' && verifyHash(r) && verifySignature(r, pub) && fjpConf.conforms(fjpConf.evaluate(r, 2))));
const rep = await replay(loadCases(t + '/cases.jsonl'), '{FIX}/policies/standard.yaml', '{FIX}/policies/standard.yaml');
console.log(JSON.stringify({{ bad: bad.map(r => r.record_id), replay: rep }}));
"""
res2 = subprocess.run(["node", "--input-type=module", "-e", node2], capture_output=True, text=True)
if res2.returncode:
    print(res2.stderr)
    sys.exit(1)
ts2 = json.loads(res2.stdout.strip().splitlines()[-1])
ts_shadow = json.load(open(os.path.join(tmp, "ts_shadow.json")))
problems += [f"python shadow record {x} fails in TypeScript" for x in ts2["bad"]]
for c, p, s, t in zip(cases, py, py_shadow, ts_shadow):
    if s["decision"] != p.decision or t["decision"] != p.decision:
        problems.append(f"{c['id']}: shadow decision differs from enforce")
    if not (t.get("mode") == "shadow" and verify_hash(t) and verify_signature(t, pub)
            and fjp_conf.conforms(fjp_conf.evaluate(t, 2))):
        problems.append(f"{c['id']}: TypeScript shadow record fails in Python")
    if s["action"]["directive"].split(";")[0] != t["action"]["directive"].split(";")[0]:
        problems.append(f"{c['id']}: shadow directive differs")
py_rep = replay([json.loads(line) for line in open(cases_path)], os.path.join(FIX, "policies", "standard.yaml"),
                os.path.join(FIX, "policies", "standard.yaml"))
if py_rep != ts2["replay"]:
    problems.append("replay report differs between Python and TypeScript")

print(f"cross-language parity: {len(cases)} fixtures (+ shadow, replay), {len(problems)} problem(s)")
for x in problems:
    print("  -", x)
sys.exit(1 if problems else 0)
