"""Cryptographic primitives of the protocol (SPEC.md sections 5-7).

Pure computation over bytes: no network, no filesystem, no clock.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from hmtp.core.entities.message import canonical


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(data: str) -> bytes:
    return base64.b64decode(data)


def url_token(size: int) -> str:
    return base64.urlsafe_b64encode(os.urandom(size)).decode().rstrip("=")


def new_signing_keypair() -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    return b64(key.private_bytes_raw()), b64(key.public_key().public_bytes_raw())


def new_encryption_keypair() -> tuple[str, str]:
    key = x25519.X25519PrivateKey.generate()
    return b64(key.private_bytes_raw()), b64(key.public_key().public_bytes_raw())


def sign(payload: dict, private_key_b64: str) -> str:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(unb64(private_key_b64))
    return b64(key.sign(canonical(payload)))


def sign_bytes(data: bytes, private_key_b64: str) -> str:
    key = ed25519.Ed25519PrivateKey.from_private_bytes(unb64(private_key_b64))
    return b64(key.sign(data))


def verify_signature(msg: dict, signing_key_b64: str) -> None:
    """Raise InvalidSignature unless the message's signature covers the
    canonical form of everything but the signature itself."""
    payload = {k: v for k, v in msg.items() if k != "signature"}
    key = ed25519.Ed25519PublicKey.from_public_bytes(unb64(signing_key_b64))
    key.verify(unb64(msg["signature"]), canonical(payload))


def verify_bytes(data: bytes, signature_b64: str, signing_key_b64: str) -> None:
    key = ed25519.Ed25519PublicKey.from_public_bytes(unb64(signing_key_b64))
    key.verify(unb64(signature_b64), data)


def _sealing_key(shared: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=ephemeral_pub + recipient_pub,
    ).derive(shared)


def seal(text: str, recipient_key_b64: str) -> dict:
    """Encrypt the content (subject, body, attachment keys) to an X25519 key
    (sealed box): only the holder of the private key can read it, servers
    included."""
    recipient_pub = unb64(recipient_key_b64)
    recipient_key = x25519.X25519PublicKey.from_public_bytes(recipient_pub)
    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key().public_bytes_raw()
    key = _sealing_key(ephemeral.exchange(recipient_key), ephemeral_pub, recipient_pub)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, text.encode(), None)
    return {
        "cipher": "x25519-chacha20poly1305",
        "ephemeral_key": b64(ephemeral_pub),
        "nonce": b64(nonce),
        "data": b64(ciphertext),
    }


def unseal(sealed: dict, cfg: dict) -> str:
    """Decrypt with the current encryption key, falling back to rotated-out
    ones so old mail stays readable after a key rotation."""
    from cryptography.exceptions import InvalidTag

    keypairs = [
        (cfg["encryption_private_key"], cfg["encryption_public_key"]),
        *cfg.get("previous_encryption_keys", []),
    ]
    ephemeral_pub = unb64(sealed["ephemeral_key"])
    for private_b64, public_b64 in keypairs:
        private = x25519.X25519PrivateKey.from_private_bytes(unb64(private_b64))
        shared = private.exchange(
            x25519.X25519PublicKey.from_public_bytes(ephemeral_pub)
        )
        key = _sealing_key(shared, ephemeral_pub, unb64(public_b64))
        try:
            return (
                ChaCha20Poly1305(key)
                .decrypt(unb64(sealed["nonce"]), unb64(sealed["data"]), None)
                .decode()
            )
        except InvalidTag:
            continue
    raise ValueError("no encryption key can decrypt this message")


def encrypt_blob(data: bytes) -> tuple[bytes, str, str]:
    """Encrypt a file with a fresh single-use key. Returns the opaque blob
    (nonce || ciphertext), its hex digest and the base64 key."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    blob = nonce + ChaCha20Poly1305(key).encrypt(nonce, data, None)
    return blob, hashlib.sha256(blob).hexdigest(), b64(key)


def decrypt_blob(blob: bytes, key_b64: str) -> bytes:
    return ChaCha20Poly1305(unb64(key_b64)).decrypt(blob[:12], blob[12:], None)


def blob_matches(blob: bytes, ref: dict, digest: str) -> bool:
    return len(blob) == ref["size"] and hashlib.sha256(blob).hexdigest() == digest
