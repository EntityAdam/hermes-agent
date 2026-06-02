"""Tests for native Matrix vodozemac E2EE engine helpers."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.platforms import matrix_vodozemac as mv
from gateway.platforms.matrix_native_e2ee import NativeVodozemacE2EE, _OutboundMegolmState


class _FakeSessionKey:
    def to_base64(self):
        return "BASE64_SESSION_KEY"


class _FakeClient:
    def __init__(self):
        self.send_to_device = AsyncMock(return_value=None)


class TestNativeVodozemacE2EE:
    def test_session_key_to_base64_prefers_method(self):
        key = _FakeSessionKey()
        assert NativeVodozemacE2EE._session_key_to_base64(key) == "BASE64_SESSION_KEY"

    @pytest.mark.asyncio
    async def test_share_room_key_payload_uses_base64_and_device_metadata(self, monkeypatch):
        client = _FakeClient()
        engine = NativeVodozemacE2EE(
            client=client,
            user_id="@bot:example.org",
            device_id="BOTDEVICE",
            state_path=SimpleNamespace(parent=SimpleNamespace(mkdir=lambda **kwargs: None)),
            pickle_key="pickle",
        )
        engine._account = object()
        engine._curve25519 = "BOT_CURVE"
        engine._ed25519 = "BOT_ED"

        engine._fetch_room_device_identities = AsyncMock(
            return_value={
                ("@alice:example.org", "ALICEDEVICE"): {
                    "curve25519": "ALICE_CURVE",
                    "ed25519": "ALICE_ED",
                }
            }
        )
        engine._ensure_olm_session_locked = AsyncMock(return_value=object())

        captured = {}

        def _fake_encrypt_olm(session, plaintext):
            captured["plaintext"] = plaintext
            return "olm-message"

        monkeypatch.setattr(mv, "encrypt_olm", _fake_encrypt_olm)
        monkeypatch.setattr(mv, "olm_message_to_matrix_parts", lambda _msg: (0, "BODY"))

        outbound = _OutboundMegolmState(
            session=SimpleNamespace(session_id="SESSION_ID", session_key=_FakeSessionKey())
        )

        await engine._share_room_key_with_members_locked("!room:example.org", outbound)

        assert client.send_to_device.await_count == 1
        assert "@alice:example.org|ALICEDEVICE" in outbound.shared_with

        payload = json.loads(captured["plaintext"])
        assert payload["type"] == "m.room_key"
        assert payload["sender"] == "@bot:example.org"
        assert payload["sender_device"] == "BOTDEVICE"
        assert payload["keys"]["ed25519"] == "BOT_ED"
        assert payload["recipient"] == "@alice:example.org"
        assert payload["recipient_keys"]["ed25519"] == "ALICE_ED"
        assert payload["content"]["session_key"] == "BASE64_SESSION_KEY"
