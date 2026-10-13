# Abe examples

| Folder | Shows | Run |
|---|---|---|
| `demo/` | The $12,500 demo: rules decide the easy calls, Flow tells a duplicate order from a real renewal (terminal or Claude via MCP) | `python demo.py` |
| `purchasing/` | ACT / BLOCK / ESCALATE with a SQLite audit trail, outcome reporting | `python run.py` · `node run.mjs` |
| `software_agent/` | Coding/DevOps agent: protected branches, force-push, destructive SQL | `python run.py` |
| `physical_agent/` | Spec §27: critical physical action near humans → `HIGH_CONSEQUENCE_ACTION` | `python run.py` |
| `travel/` | Spec §28/§46: Gate stops at "judgment required"; `JuddResolver` hands it to Judd | `python run.py` |
| `flow/` | Gate + Flow: only escalations go to `resolve.flowinfo.co` (Python package + copyable JS resolver) | `FLOW_API_KEY=… python with_flow.py` |

None of these need an account or network access except `demo/` (rules only without a key), `flow/` and the optional Judd step in `travel/`.
