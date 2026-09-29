# Deploying Abe

Nothing here touches the live Flow services (`backend-main`, `fjp-resolve`, `judd`). The Flow resolver adapter
calls the **existing** `POST https://resolve.flowinfo.co/api/v1/tools/judge` and `POST /api/v1/outcome` exactly
as they are today.

## 1. Create the repo (5 min)

1. Create public repo **`flowinfosystems-index/abe`** and push this folder as-is.
2. Settings → Actions: allow GitHub Actions. The `ci` workflow runs Python 3.10–3.13, Node 18/20/22,
   cross-language parity, fixture drift and a Docker smoke test.

## 2. Claim the package names (10 min, once)

| Registry | Name | How |
|---|---|---|
| PyPI | `abe-ai`, `abe-flow` | pypi.org → Publishing → *Add a pending publisher*: owner `flowinfosystems-index`, repo `abe`, workflow `release.yml`, environments `pypi` (abe-ai) and `pypi-flow` (abe-flow). Do it for both names. |
| npm | `abe-ai` | npmjs.com → create organization **`abe`** (free for public packages). Create an automation token → repo secret `NPM_TOKEN`. |
| GHCR | `ghcr.io/flowinfosystems-index/abe` | nothing to do; the workflow uses `GITHUB_TOKEN`. |

In GitHub → Settings → Environments, create an environment named `pypi`.

## 3. Release (2 min)

```bash
git tag v0.1.0 && git push origin v0.1.0
```

`release.yml` builds and publishes both PyPI packages, `abe-ai` (with npm provenance) and the Docker image.

Verify from any machine:

```bash
pip install abe-ai && abe init && abe check request.json && abe conformance
npm install abe-ai && npx abe conformance
```

## 4. Publish the developer page (fjp.flowinfo.co/abe)

In the **`fjp-conformance`** repo (Railway service for fjp.flowinfo.co), commit:

| Repo path | Change |
|---|---|
| `web/abe.html` | new — the Abe developer page |
| `Caddyfile` | adds `/abe` → `abe.html`, `/gate` → 301 to `/abe`, and `/abe/spec` → SPEC.md redirect |
| `Dockerfile` | adds `COPY web/abe.html /srv/abe.html` |
| `web/landing.html`, `web/quickstart.html`, `web/index.html` | adds an "Abe" nav link |
| `web/quickstart.html` | **bug fix**: step 05 used `POST /api/v1/outcomes` with `"outcome":"confirmed"`; the resolver's route is `/api/v1/outcome` and it accepts only `CORRECT`, `WRONG`, `PARTIAL` |

Deploy **after** step 3, so the `pip install` / `npm install` commands on the page work.
Check: `https://fjp.flowinfo.co/abe` (200), `/gate` (301 → /abe), `/abe/spec` (302), `/`, `/quickstart`, `/conformance/v0.1/` unchanged.

## 5. Verify Flow is ready behind the Gate

```bash
FLOW_API_KEY=fjp_live_... python scripts/smoke_flow_live.py      # one judge credit
```

Expect `gate: ESCALATE | final: ACT/BLOCK/ESCALATE flow.<verb>` and `LIVE FLOW OK`.
Developers get keys the way they do today (Stripe checkout → emailed `fjp_live_` key).

## 6. Optional: Judd behind the Gate

`examples/travel/judd_resolver.py` routes travel escalations to Judd (`JUDD_URL`, `JUDD_API_KEY`). Judd itself is
unchanged.

## Operational notes

- The Gate has no server to run. The only hosted cost is Flow calls, and those happen only on ESCALATE.
- The Docker sidecar requires `ABE_TOKEN` and should be published on `127.0.0.1` only.
- Rotate nothing: the Gate stores no secrets. Signing keys (`abe keygen`) stay with the customer.
- Open resolver items from `fjp-resolve/docs/openshell-gate.md` that now matter more: **R4** (`mode: pre_execution`
  prompt) and **R7** (model routing) — the adapter already sends a pre-execution framing in `context`, so R4 is an
  improvement, not a blocker.
