/**
 * Optional append-only record stores. Default: none (the record is returned to the caller).
 * Built in: MemoryStore, FileStore (JSON Lines), CallbackStore. For SQL/Mongo, implement RecordStore
 * (three methods) against your driver; see the Python SDK's abe.stores.contrib for reference schemas.
 */
import { appendFileSync, existsSync, fsyncSync, mkdirSync, openSync, closeSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { canonicalJson, deepFreeze } from "./canonical.js";
import { RecordImmutableError } from "./errors.js";
import type { JGR } from "./records.js";

export interface RecordStore {
  save(record: JGR): void | Promise<void>;
  get(recordId: string): JGR | null | Promise<JGR | null>;
  /** Every record whose root_record_id equals rootRecordId (including the root). */
  linked(rootRecordId: string): JGR[] | Promise<JGR[]>;
}

export class MemoryStore implements RecordStore {
  private byId = new Map<string, JGR>();
  save(record: JGR) {
    if (this.byId.has(record.record_id)) throw new RecordImmutableError(`record ${record.record_id} already exists`);
    this.byId.set(record.record_id, record);
  }
  get(id: string) {
    return this.byId.get(id) ?? null;
  }
  linked(root: string) {
    return [...this.byId.values()].filter((r) => r.root_record_id === root);
  }
  all() {
    return [...this.byId.values()];
  }
}

/** Append-only JSON Lines file (single process). */
export class FileStore implements RecordStore {
  readonly path: string;
  constructor(path: string) {
    this.path = resolve(path);
    mkdirSync(dirname(this.path), { recursive: true });
  }
  private *iter(): Generator<JGR> {
    if (!existsSync(this.path)) return;
    for (const line of readFileSync(this.path, "utf8").split("\n")) if (line.trim()) yield deepFreeze(JSON.parse(line));
  }
  save(record: JGR) {
    if (this.get(record.record_id)) throw new RecordImmutableError(`record ${record.record_id} already exists`);
    appendFileSync(this.path, canonicalJson(record) + "\n", "utf8");
    const fd = openSync(this.path, "r");
    try { fsyncSync(fd); } finally { closeSync(fd); }
  }
  get(id: string) {
    for (const r of this.iter()) if (r.record_id === id) return r;
    return null;
  }
  linked(root: string) {
    return [...this.iter()].filter((r) => r.root_record_id === root);
  }
}

/** Hands every record to your function (SIEM, data lake, queue). Write-only. */
export class CallbackStore implements RecordStore {
  constructor(private fn: (record: Record<string, unknown>) => void | Promise<void>) {}
  async save(record: JGR) {
    await this.fn(JSON.parse(canonicalJson(record)));
  }
  get() {
    return null;
  }
  linked() {
    return [];
  }
}

export function storeFromUri(uri?: string | null): RecordStore | null {
  if (!uri || uri === "none") return null;
  if (uri === "memory:" || uri === "memory") return new MemoryStore();
  if (uri.startsWith("file:")) return new FileStore(uri.slice(5));
  throw new Error(`unknown store '${uri}'; use memory: or file:<path.jsonl> (SQLite is available in the Python SDK)`);
}
