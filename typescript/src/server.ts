/** Local HTTP mode — same endpoints as the Python SDK. Binds 127.0.0.1 unless explicitly allowed otherwise. */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { timingSafeEqual } from "node:crypto";
import type { Gate } from "./gate.js";
import { VERSION } from "./version.js";

const MAX_BODY = 1_048_576;

export function isLoopback(host: string): boolean {
  if (host === "localhost") return true;
  if (isIP(host) === 4) return host.startsWith("127.");
  if (isIP(host) === 6) return host === "::1";
  return false;
}

function send(res: ServerResponse, code: number, body: unknown) {
  const data = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Content-Length": data.length,
    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  res.end(data);
}

function readBody(req: IncomingMessage): Promise<Buffer | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) { resolve(null); req.destroy(); } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export function createGateServer(gate: Gate, token?: string | null): Server {
  const authorized = (req: IncomingMessage) => {
    if (!token) return true;
    const got = Buffer.from(String(req.headers.authorization ?? "").replace(/^Bearer\s+/, "").trim());
    const want = Buffer.from(token);
    return got.length === want.length && timingSafeEqual(got, want);
  };
  return createServer(async (req, res) => {
    try {
      const url = (req.url ?? "/").split("?")[0];
      if (req.method === "GET" && url === "/healthz") return send(res, 200, { status: "ok", version: VERSION, policy_hash: gate.policy.hash, mode: gate.mode });
      if (!authorized(req)) return send(res, 401, { error: "unauthorized" });
      if (req.method === "GET" && url.startsWith("/v1/records/")) {
        const id = decodeURIComponent(url.slice("/v1/records/".length));
        try {
          const rec = JSON.parse(JSON.stringify(await gate.getRecord(id)));
          rec.falsifier.status = await gate.evaluateFalsifier(id);
          return send(res, 200, rec);
        } catch {
          return send(res, 404, { error: "not_found" });
        }
      }
      if (req.method !== "POST") return send(res, 404, { error: "not_found" });
      const raw = await readBody(req);
      if (raw === null) return send(res, 413, { error: "payload_too_large", max_bytes: MAX_BODY });
      let body: unknown;
      try {
        body = raw.length ? JSON.parse(raw.toString("utf8")) : {};
      } catch {
        if (url === "/v1/check") {
          const r = await gate.check(null as never);
          return send(res, 200, { ...r.toResponse(), record: r.record });
        }
        return send(res, 400, { error: "invalid_json" });
      }
      if (url === "/v1/check") {
        const r = await gate.check(body as never);
        const out: Record<string, unknown> = { ...r.toResponse(), record: r.record };
        if (r.records.length > 1) out.records = r.records;
        return send(res, 200, out);
      }
      if (url === "/v1/outcome") {
        const b = body as { record_id?: unknown; status?: unknown; details?: unknown };
        if (!b || typeof b.record_id !== "string") return send(res, 400, { error: "record_id required" });
        try {
          return send(res, 200, await gate.recordOutcome(b.record_id, b.status as never, (b.details as Record<string, unknown>) ?? {}));
        } catch (e) {
          if (e instanceof RangeError) return send(res, 404, { error: "not_found" });
          return send(res, 400, { error: "invalid_outcome", message: String((e as Error).message).slice(0, 200) });
        }
      }
      const m = /^\/v1\/records\/(.+)\/evaluate$/.exec(url);
      if (m) {
        const id = decodeURIComponent(m[1]);
        try {
          return send(res, 200, { record_id: id, status: await gate.evaluateFalsifier(id) });
        } catch {
          return send(res, 404, { error: "not_found" });
        }
      }
      return send(res, 404, { error: "not_found" });
    } catch {
      return send(res, 500, { error: "internal_error" });
    }
  });
}

export function serve(gate: Gate, opts: { host?: string; port?: number; token?: string | null; allowRemote?: boolean } = {}): Server {
  const host = opts.host ?? "127.0.0.1", port = opts.port ?? 8787;
  if (!isLoopback(host)) {
    if (!opts.allowRemote) throw new Error(`refusing to bind ${host}: Abe binds 127.0.0.1 by default. Pass --allow-remote (and --token) to expose it.`);
    if (!opts.token) throw new Error("--allow-remote requires --token (or ABE_TOKEN) so the endpoint is not open");
  }
  const srv = createGateServer(gate, opts.token);
  srv.listen(port, host, () => {
    console.log(`Abe ${VERSION} (TypeScript) listening on http://${host}:${port}  policy ${gate.policy.hash.slice(0, 19)}…${gate.mode === "shadow" ? "  mode=shadow (recorded, not enforced)" : ""}`);
  });
  return srv;
}
