"""Unit tests for Matrix vodozemac helper wrappers."""

from __future__ import annotations

import pytest

from gateway.platforms import matrix_vodozemac as mz


pytest.importorskip("vodozemac")


_PICKLE_KEY = b"DEFAULT_PICKLE_KEY_1234567890___"


class TestVodozemacBindings:
    def test_required_bindings_present(self):
        assert mz.has_required_bindings() is True


class TestAccountHelpers:
    def test_account_identity_and_signing(self):
        account = mz.create_account()
        keys = mz.account_identity_keys(account)

        assert keys["ed25519"]
        assert keys["curve25519"]

        signature = mz.sign(account, "hello matrix")
        assert isinstance(signature, str)
        assert signature

    def test_one_time_and_fallback_keys(self):
        account = mz.create_account()

        one_time = mz.generate_one_time_keys(account, 5)
        assert len(one_time) == 5

        fallback = mz.generate_fallback_key(account)
        assert len(fallback) == 1

        mz.mark_keys_as_published(account)
        assert not account.one_time_keys

    def test_account_pickle_roundtrip(self):
        account = mz.create_account()
        pickled = mz.pickle_account(account, _PICKLE_KEY)
        unpickled = mz.unpickle_account(pickled, _PICKLE_KEY)

        assert account.ed25519_key == unpickled.ed25519_key
        assert account.curve25519_key == unpickled.curve25519_key


class TestOlmSessions:
    def test_outbound_inbound_roundtrip(self):
        alice = mz.create_account()
        bob = mz.create_account()

        mz.generate_one_time_keys(bob, 1)
        one_time_key = next(iter(bob.one_time_keys.values()))

        outbound = mz.create_outbound_olm_session(alice, bob.curve25519_key, one_time_key)
        prekey_message = mz.encrypt_olm(outbound, "hello from alice")

        inbound, plaintext = mz.create_inbound_olm_session(
            bob,
            alice.curve25519_key,
            prekey_message,
        )

        assert plaintext == "hello from alice"
        assert inbound.session_id == outbound.session_id

        followup = mz.encrypt_olm(outbound, "followup")
        assert mz.decrypt_olm(inbound, followup) == "followup"

    def test_olm_session_pickle_roundtrip(self):
        alice = mz.create_account()
        bob = mz.create_account()

        mz.generate_one_time_keys(bob, 1)
        one_time_key = next(iter(bob.one_time_keys.values()))

        session = mz.create_outbound_olm_session(alice, bob.curve25519_key, one_time_key)
        pickled = mz.pickle_olm_session(session, _PICKLE_KEY)
        restored = mz.unpickle_olm_session(pickled, _PICKLE_KEY)

        assert session.session_id == restored.session_id


class TestMegolmSessions:
    def test_group_encrypt_decrypt(self):
        outbound = mz.create_outbound_megolm_session()
        inbound = mz.create_inbound_megolm_session(outbound.session_key)

        ciphertext = mz.encrypt_megolm(outbound, "group hello")
        plaintext, index = mz.decrypt_megolm(inbound, ciphertext)

        assert plaintext == "group hello"
        assert index == 0

    def test_group_pickle_roundtrip(self):
        outbound = mz.create_outbound_megolm_session()
        inbound = mz.create_inbound_megolm_session(outbound.session_key)

        out_pickle = mz.pickle_outbound_megolm_session(outbound, _PICKLE_KEY)
        in_pickle = mz.pickle_inbound_megolm_session(inbound, _PICKLE_KEY)

        restored_out = mz.unpickle_outbound_megolm_session(out_pickle, _PICKLE_KEY)
        restored_in = mz.unpickle_inbound_megolm_session(in_pickle, _PICKLE_KEY)

        assert restored_out.session_id == outbound.session_id
        assert restored_in.session_id == inbound.session_id

    def test_inbound_import_roundtrip(self):
        outbound = mz.create_outbound_megolm_session()
        inbound = mz.create_inbound_megolm_session(outbound.session_key)

        exported = inbound.export_at(inbound.first_known_index)
        imported = mz.import_inbound_megolm_session(exported)

        ciphertext = mz.encrypt_megolm(outbound, "imported session")
        plaintext, index = mz.decrypt_megolm(imported, ciphertext)

        assert plaintext == "imported session"
        assert index == 0
