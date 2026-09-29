"""Optional local Ed25519 signing of record hashes. Never requires Flow infrastructure.

Install with:  pip install "abe-ai[signing]"
The signature is over the ASCII bytes of record["record_hash"] ("sha256:<hex>").
Keys are standard PEM (PKCS#8 private, SubjectPublicKeyInfo public), interoperable with Node's crypto.
"""
from __future__ import annotations

import base64

from .exceptions import SigningError


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as e:  # pragma: no cover - depends on environment
        raise SigningError('signing needs the "cryptography" package: pip install "abe-ai[signing]"') from e
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def generate_keypair() -> tuple[bytes, bytes]:
    """(private_pem, public_pem)"""
    ser, Priv, _ = _crypto()
    key = Priv.generate()
    priv = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    pub = key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


class Signer:
    def __init__(self, private_key_pem: bytes | str, key_id: str = "local:key:1"):
        ser, Priv, _ = _crypto()
        data = private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem
        key = ser.load_pem_private_key(data, password=None)
        if not isinstance(key, Priv):
            raise SigningError("private key must be Ed25519")
        self._key = key
        self.key_id = key_id

    @classmethod
    def from_file(cls, path: str, key_id: str = "local:key:1") -> "Signer":
        with open(path, "rb") as fh:
            return cls(fh.read(), key_id)

    def sign(self, record_hash: str) -> dict:
        sig = self._key.sign(record_hash.encode("ascii"))
        return {"algorithm": "ed25519", "key_id": self.key_id, "value": base64.b64encode(sig).decode("ascii")}


def verify_signature(record, public_key_pem: bytes | str) -> bool:
    ser, _, Pub = _crypto()
    d = record.to_dict() if hasattr(record, "to_dict") else dict(record)
    sig = d.get("signature")
    if not isinstance(sig, dict) or sig.get("algorithm") != "ed25519":
        return False
    data = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    key = ser.load_pem_public_key(data)
    if not isinstance(key, Pub):
        raise SigningError("public key must be Ed25519")
    try:
        key.verify(base64.b64decode(sig["value"]), str(d.get("record_hash", "")).encode("ascii"))
        return True
    except Exception:  # noqa: BLE001 - any failure is "not verified"
        return False
