// Purchasing agent (TypeScript/Node):  node run.mjs
import { Abe, FileStore } from "abe-ai";

const abe = new Abe({ policy: new URL("./abe-policy.yaml", import.meta.url).pathname, store: new FileStore("abe-records.jsonl") });
for (const amount of [120, 12_500, 250_000]) {
  const r = await abe.check({ action: { type: "purchase", amount, currency: "USD", target: "vendor_123" },
    context: { agent_id: "procurement-agent", principal_id: "user_123" }, confidence: 0.95 });
  console.log(`$${amount.toLocaleString().padStart(9)}  ${r.decision.padEnd(8)}  ${r.reasonCode.padEnd(30)}  ${r.recordId}`);
  if (r.decision === "ACT") await abe.recordOutcome(r.record, "executed", { request_hash: r.record.request_hash });
}
