"""Tests for native Matrix attachment crypto helpers."""

import pytest

from gateway.platforms.matrix_attachments import decrypt_attachment, encrypt_attachment


class TestMatrixAttachments:
    def test_roundtrip_encrypt_decrypt(self):
        plaintext = b"hello encrypted attachment"

        ciphertext, payload = encrypt_attachment(plaintext)

        assert ciphertext != plaintext
        assert payload["v"] == "v2"

        key = payload["key"]["k"]
        iv = payload["iv"]
        sha256 = payload["hashes"]["sha256"]
        decrypted = decrypt_attachment(ciphertext, key, sha256, iv)

        assert decrypted == plaintext

    def test_decrypt_rejects_hash_mismatch(self):
        plaintext = b"integrity check"
        ciphertext, payload = encrypt_attachment(plaintext)

        bad_hash = payload["hashes"]["sha256"][:-1] + "A"

        with pytest.raises(ValueError, match="hash mismatch"):
            decrypt_attachment(
                ciphertext,
                payload["key"]["k"],
                bad_hash,
                payload["iv"],
            )
