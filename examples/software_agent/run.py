import os

from abe import Abe

abe = Abe(os.path.join(os.path.dirname(__file__), "abe-policy.yaml"))
for action, ctx in [({"type": "run_tests"}, {"environment": "staging"}),
                    ({"type": "git_push", "branch": "feature/login"}, {"environment": "staging"}),
                    ({"type": "git_push", "branch": "main"}, {"environment": "staging"}),
                    ({"type": "git_push", "branch": "main", "force": True}, {"environment": "staging"}),
                    ({"type": "run_sql", "statement": "DROP TABLE users;"}, {"environment": "production"}),
                    ({"type": "delete_resource", "id": "bucket-7"}, {"environment": "staging"})]:
    r = abe.check(action=action, context={**ctx, "agent_id": "coding-agent"})
    print(f"{str(action):<60} {r.decision:<8} {r.reason_code}")
