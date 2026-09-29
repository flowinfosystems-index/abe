"""Local HTTP mode (stdlib only):  abe serve --policy ./abe-policy.yaml

    POST /v1/check                      {action, context, evidence, ...} -> FJP response + record
    POST /v1/outcome                    {record_id, status, details}     -> linked OUTCOME record
    GET  /v1/records/{record_id}        stored record, falsifier status re-evaluated now
    POST /v1/records/{record_id}/evaluate                                -> {record_id, status}
    GET  /healthz

Binds 127.0.0.1 by default. Binding any other interface requires --allow-remote AND a bearer token.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .gate import Gate

log = logging.getLogger("abe.server")
MAX_BODY = 1_048_576


def is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_handler(gate: Gate, token: str | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"abe/{__version__}"
        sys_version = ""

        def log_message(self, fmt, *args):  # quiet by default; no request bodies in logs
            log.info("%s %s", self.address_string(), fmt % args)

        def _send(self, code: int, body: dict):
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            if not token:
                return True
            got = self.headers.get("Authorization", "")
            return hmac.compare_digest(got.removeprefix("Bearer ").strip().encode(), token.encode())

        def _body(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                return None, (413, {"error": "payload_too_large", "max_bytes": MAX_BODY})
            raw = self.rfile.read(n) if n else b""
            try:
                return json.loads(raw or b"{}"), None
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                return None, (400, {"error": "invalid_json"})

        def do_GET(self):  # noqa: N802
            if self.path == "/healthz":
                return self._send(200, {"status": "ok", "version": __version__, "policy_hash": gate.policy.hash})
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            if self.path.startswith("/v1/records/"):
                rid = self.path[len("/v1/records/"):]
                try:
                    rec = gate.get_record(rid).to_dict()
                except LookupError:
                    return self._send(404, {"error": "not_found"})
                rec["falsifier"]["status"] = gate.evaluate_falsifier(rid)
                return self._send(200, rec)
            return self._send(404, {"error": "not_found"})

        def do_POST(self):  # noqa: N802
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            body, err = self._body()
            if err:
                # A malformed body on /v1/check is still answered with a fail-closed decision.
                if self.path == "/v1/check" and err[0] == 400:
                    r = gate.check(None)
                    return self._send(200, {**r.to_dict(), "record": r.record.to_dict()})
                return self._send(*err)
            if self.path == "/v1/check":
                r = gate.check(body if isinstance(body, dict) else {"action": None})
                out = {**r.to_dict(), "record": r.record.to_dict()}
                if len(r.records) > 1:
                    out["records"] = [x.to_dict() for x in r.records]
                return self._send(200, out)
            if self.path == "/v1/outcome":
                if not isinstance(body, dict) or not isinstance(body.get("record_id"), str):
                    return self._send(400, {"error": "record_id required"})
                try:
                    rec = gate.record_outcome(body["record_id"], body.get("status", ""), body.get("details") or {})
                except LookupError:
                    return self._send(404, {"error": "not_found"})
                except (ValueError, TypeError) as e:
                    return self._send(400, {"error": "invalid_outcome", "message": str(e)[:200]})
                return self._send(200, rec.to_dict())
            if self.path.startswith("/v1/records/") and self.path.endswith("/evaluate"):
                rid = self.path[len("/v1/records/"):-len("/evaluate")]
                try:
                    return self._send(200, {"record_id": rid, "status": gate.evaluate_falsifier(rid)})
                except LookupError:
                    return self._send(404, {"error": "not_found"})
            return self._send(404, {"error": "not_found"})

    return Handler


def serve(gate: Gate, host: str = "127.0.0.1", port: int = 8787, token: str | None = None,
          allow_remote: bool = False):
    if not is_loopback(host):
        if not allow_remote:
            raise SystemExit(f"refusing to bind {host}: Abe binds 127.0.0.1 by default. "
                             "Pass --allow-remote (and --token) to expose it beyond this machine.")
        if not token:
            raise SystemExit("--allow-remote requires --token (or ABE_TOKEN) so the endpoint is not open")
    httpd = ThreadingHTTPServer((host, port), make_handler(gate, token))
    print(f"Abe {__version__} listening on http://{host}:{port}  policy {gate.policy.hash[:19]}…"
          f"  store={'none' if gate.store is None else type(gate.store).__name__}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return httpd
