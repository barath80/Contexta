"""
Contexta Backend - Ledger signing (Ed25519)

A server-held Ed25519 key signs every ledger block hash. The private key is
persisted to LEDGER_KEY_PATH on first start (mode 0600 where supported).
"""

import base64
import hashlib
import os
from pathlib import Path
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_cache: dict = {}


def _public_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(pub: Ed25519PublicKey) -> str:
    return hashlib.sha256(_public_bytes(pub)).hexdigest()


def load_or_create_key(path: str) -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Load the signing key from disk, creating it if missing."""
    if path in _cache:
        return _cache[path]
    p = Path(path)
    if p.exists():
        private = serialization.load_pem_private_key(p.read_bytes(), password=None)
    else:
        private = Ed25519PrivateKey.generate()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    _cache[path] = (private, private.public_key())
    return _cache[path]


def sign_hash(private: Ed25519PrivateKey, block_hash: str) -> str:
    return base64.b64encode(private.sign(block_hash.encode())).decode()


def verify_hash(public: Ed25519PublicKey, block_hash: str, signature_b64: str) -> bool:
    try:
        public.verify(base64.b64decode(signature_b64), block_hash.encode())
        return True
    except (InvalidSignature, ValueError):
        return False


def public_key_pem(public: Ed25519PublicKey) -> str:
    return public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
