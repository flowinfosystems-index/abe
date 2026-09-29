/** Optional local Ed25519 signing of record hashes (node:crypto; PEM keys interoperable with the Python SDK). */
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { SigningError } from "./errors.js";
import type { Signer } from "./records.js";

export function generateKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export class Ed25519Signer implements Signer {
  private key;
  constructor(privateKeyPem: string, readonly keyId = "local:key:1") {
    this.key = createPrivateKey(privateKeyPem);
    if (this.key.asymmetricKeyType !== "ed25519") throw new SigningError("private key must be Ed25519");
  }
  static fromFile(path: string, keyId = "local:key:1") {
    return new Ed25519Signer(readFileSync(path, "utf8"), keyId);
  }
  sign(recordHash: string) {
    return { algorithm: "ed25519" as const, key_id: this.keyId,
      value: sign(null, Buffer.from(recordHash, "ascii"), this.key).toString("base64") };
  }
}

export function verifySignature(record: Record<string, unknown>, publicKeyPem: string): boolean {
  const sig = record.signature as { algorithm?: string; value?: string } | undefined;
  if (!sig || sig.algorithm !== "ed25519" || typeof sig.value !== "string") return false;
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new SigningError("public key must be Ed25519");
  try {
    return verify(null, Buffer.from(String(record.record_hash ?? ""), "ascii"), key, Buffer.from(sig.value, "base64"));
  } catch {
    return false;
  }
}
