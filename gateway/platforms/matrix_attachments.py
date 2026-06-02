"""Matrix attachment encryption helpers.

Implements the Matrix encrypted attachment payload format (``v2``) without
importing ``mautrix.crypto.attachments``.
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64u_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def encrypt_attachment(data: bytes) -> tuple[bytes, dict]:
    """Encrypt attachment bytes and return ciphertext + Matrix ``file`` payload."""
    key = os.urandom(32)
    iv = os.urandom(16)

    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    file_payload = {
        "v": "v2",
        "iv": _b64u_encode(iv),
        "hashes": {"sha256": _b64u_encode(hashlib.sha256(ciphertext).digest())},
        "key": {
            "kty": "oct",
            "alg": "A256CTR",
            "ext": True,
            "k": _b64u_encode(key),
            "key_ops": ["encrypt", "decrypt"],
        },
    }
    return ciphertext, file_payload


def decrypt_attachment(ciphertext: bytes, key_b64: str, hash_b64: str, iv_b64: str) -> bytes:
    """Decrypt attachment bytes and verify the ciphertext hash."""
    expected = _b64u_decode(hash_b64)
    actual = hashlib.sha256(ciphertext).digest()
    if expected != actual:
        raise ValueError("Encrypted attachment SHA-256 hash mismatch")

    key = _b64u_decode(key_b64)
    iv = _b64u_decode(iv_b64)
    decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()