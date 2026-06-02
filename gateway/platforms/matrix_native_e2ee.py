"""Native Matrix E2EE engine backed by vodozemac.

This module implements the minimum Matrix E2EE primitives Hermes needs
without importing ``mautrix.crypto`` (which currently depends on
python-olm/libolm).
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gateway.platforms import matrix_vodozemac as mv

logger = logging.getLogger(__name__)

_OLM_ALGORITHM = "m.olm.v1.curve25519-aes-sha2"
_MEGOLM_ALGORITHM = "m.megolm.v1.aes-sha2"
_STATE_VERSION = 1
_KEY_SEP = "\x1f"


@dataclass
class _OutboundMegolmState:
    session: Any
    shared_with: set[str] = field(default_factory=set)


class NativeVodozemacE2EE:
    """Native vodozemac E2EE state + protocol helpers for Matrix."""

    def __init__(
        self,
        client: Any,
        user_id: str,
        device_id: str,
        state_path: Path,
        pickle_key: str,
    ):
        self._client = client
        self._user_id = user_id
        self._device_id = device_id
        self.state_path = state_path
        self._pickle_key = pickle_key

        self._account: Any = None
        self._curve25519: str = ""
        self._ed25519: str = ""

        self._olm_sessions: dict[str, Any] = {}
        self._inbound_group_sessions: dict[tuple[str, str, str], Any] = {}
        self._outbound_group_sessions: dict[str, _OutboundMegolmState] = {}
        self._device_curve_cache: dict[tuple[str, str], str] = {}
        self._device_ed25519_cache: dict[tuple[str, str], str] = {}
        self._room_encryption_cache: dict[str, bool] = {}

        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Load crypto state and publish device/one-time keys."""
        async with self._lock:
            self._load_state_locked()
            if self._account is None:
                self._account = mv.create_account()
                self._refresh_identity_keys_locked()

            # Re-share outbound room keys after restart so devices can recover
            # from stale/missed to-device delivery and prior payload bugs.
            for state in self._outbound_group_sessions.values():
                state.shared_with.clear()

            await self._upload_keys_locked(include_device_keys=True)
            self._save_state_locked()

    async def close(self) -> None:
        """Persist current crypto state to disk."""
        async with self._lock:
            self._save_state_locked()

    async def is_room_encrypted(self, room_id: str) -> bool:
        if room_id in self._room_encryption_cache:
            return self._room_encryption_cache[room_id]

        encrypted = False
        event_type = self._room_encryption_event_type()
        try:
            state = await self._maybe_await(self._client.get_state_event(room_id, event_type))
            encrypted = bool(state)
        except Exception:
            encrypted = False

        self._room_encryption_cache[room_id] = encrypted
        return encrypted

    async def handle_olm_to_device_event(self, event: Any, content: dict[str, Any]) -> None:
        """Handle incoming ``m.room.encrypted`` to-device Olm payloads."""
        if content.get("algorithm") != _OLM_ALGORITHM:
            return

        async with self._lock:
            sender_key = str(content.get("sender_key") or "")
            if not sender_key:
                return

            ciphertext_map = content.get("ciphertext")
            if not isinstance(ciphertext_map, dict):
                return

            own_cipher = ciphertext_map.get(self._curve25519)
            if own_cipher is None and ciphertext_map:
                own_cipher = next(iter(ciphertext_map.values()))
            if not isinstance(own_cipher, dict):
                return

            try:
                message = mv.olm_message_from_matrix_parts(
                    int(own_cipher.get("type", 0)),
                    str(own_cipher.get("body", "")),
                )
            except Exception as exc:
                logger.debug("Matrix E2EE: invalid to-device Olm payload: %s", exc)
                return

            plaintext: str | None = None
            session = self._olm_sessions.get(sender_key)

            if session is not None:
                try:
                    plaintext = mv.decrypt_olm(session, message)
                except Exception:
                    plaintext = None

            if plaintext is None:
                try:
                    session, plaintext = mv.create_inbound_olm_session(
                        self._account,
                        sender_key,
                        message,
                    )
                except Exception as exc:
                    logger.debug("Matrix E2EE: cannot establish inbound Olm session: %s", exc)
                    return

                self._olm_sessions[sender_key] = session

            try:
                payload = json.loads(plaintext)
            except Exception:
                return

            if payload.get("type") != "m.room_key":
                self._save_state_locked()
                return

            key_content = payload.get("content")
            if not isinstance(key_content, dict):
                self._save_state_locked()
                return

            if key_content.get("algorithm") != _MEGOLM_ALGORITHM:
                self._save_state_locked()
                return

            room_id = str(key_content.get("room_id") or "")
            session_id = str(key_content.get("session_id") or "")
            session_key = str(key_content.get("session_key") or "")
            if not room_id or not session_id or not session_key:
                self._save_state_locked()
                return

            try:
                inbound = mv.create_inbound_megolm_session(session_key)
            except Exception as exc:
                logger.debug("Matrix E2EE: invalid room key payload: %s", exc)
                self._save_state_locked()
                return

            self._inbound_group_sessions[(room_id, sender_key, session_id)] = inbound
            self._save_state_locked()

    async def decrypt_room_event(self, event: Any, content: dict[str, Any]) -> dict[str, Any] | None:
        """Decrypt an encrypted room timeline event payload."""
        if content.get("algorithm") != _MEGOLM_ALGORITHM:
            return None

        room_id = str(getattr(event, "room_id", "") or "")
        sender_key = str(content.get("sender_key") or "")
        session_id = str(content.get("session_id") or "")
        ciphertext = str(content.get("ciphertext") or "")
        if not room_id or not sender_key or not session_id or not ciphertext:
            return None

        async with self._lock:
            session = self._inbound_group_sessions.get((room_id, sender_key, session_id))
            if session is None:
                return None

            try:
                plaintext, _ = mv.decrypt_megolm(session, ciphertext)
                payload = json.loads(plaintext)
            except Exception:
                return None

            self._save_state_locked()
            return payload if isinstance(payload, dict) else None

    async def encrypt_room_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Encrypt a room event, returning ``m.room.encrypted`` content or None."""
        if not await self.is_room_encrypted(room_id):
            return None

        async with self._lock:
            outbound = self._outbound_group_sessions.get(room_id)
            if outbound is None:
                outbound = _OutboundMegolmState(session=mv.create_outbound_megolm_session())
                self._outbound_group_sessions[room_id] = outbound

            await self._share_room_key_with_members_locked(room_id, outbound)

            payload = {
                "type": event_type,
                "sender": self._user_id,
                "room_id": room_id,
                "content": content,
            }

            ciphertext = mv.encrypt_megolm(outbound.session, self._canonical_json(payload))
            encrypted_content = {
                "algorithm": _MEGOLM_ALGORITHM,
                "sender_key": self._curve25519,
                "ciphertext": ciphertext,
                "session_id": str(outbound.session.session_id),
                "device_id": self._device_id,
            }

            self._save_state_locked()
            return encrypted_content

    async def _upload_keys_locked(self, include_device_keys: bool) -> None:
        one_time_keys = mv.generate_one_time_keys(self._account, 25)
        signed_keys = {
            f"signed_curve25519:{key_id}": self._sign_one_time_key(value)
            for key_id, value in one_time_keys.items()
        }

        device_keys = self._build_device_keys_payload() if include_device_keys else None
        await self._maybe_await(
            self._client.upload_keys(
                one_time_keys=signed_keys,
                device_keys=device_keys,
            )
        )
        mv.mark_keys_as_published(self._account)

    async def _share_room_key_with_members_locked(
        self,
        room_id: str,
        outbound: _OutboundMegolmState,
    ) -> None:
        device_map = await self._fetch_room_device_identities(room_id)
        if not device_map:
            return

        room_key_payload = {
            "algorithm": _MEGOLM_ALGORITHM,
            "room_id": room_id,
            "session_id": str(outbound.session.session_id),
            "session_key": self._session_key_to_base64(outbound.session.session_key),
        }

        to_device_messages: dict[str, dict[str, dict[str, Any]]] = {}
        newly_shared: list[str] = []

        for (user_id, device_id), identities in device_map.items():
            curve25519 = identities.get("curve25519", "")
            recipient_ed25519 = identities.get("ed25519", "")
            if not user_id or not device_id or not curve25519:
                continue
            if user_id == self._user_id and device_id == self._device_id:
                continue
            if not recipient_ed25519:
                logger.debug(
                    "Matrix E2EE: skipping device without ed25519 key: %s / %s",
                    user_id,
                    device_id,
                )
                continue

            share_id = f"{user_id}|{device_id}"
            if share_id in outbound.shared_with:
                continue

            session = await self._ensure_olm_session_locked(user_id, device_id, curve25519)
            if session is None:
                continue

            plaintext = self._canonical_json(
                {
                    "type": "m.room_key",
                    "sender": self._user_id,
                    "sender_device": self._device_id,
                    "keys": {
                        "ed25519": self._ed25519,
                    },
                    "recipient": user_id,
                    "recipient_keys": {
                        "ed25519": recipient_ed25519,
                    },
                    "content": room_key_payload,
                }
            )
            olm_message = mv.encrypt_olm(session, plaintext)
            msg_type, msg_body = mv.olm_message_to_matrix_parts(olm_message)

            content = {
                "algorithm": _OLM_ALGORITHM,
                "sender_key": self._curve25519,
                "sender_device": self._device_id,
                "ciphertext": {
                    curve25519: {
                        "type": msg_type,
                        "body": msg_body,
                    }
                },
            }

            to_device_messages.setdefault(user_id, {})[device_id] = content
            newly_shared.append(share_id)

        if not to_device_messages:
            return

        await self._maybe_await(
            self._client.send_to_device(self._to_device_event_type(), to_device_messages)
        )
        outbound.shared_with.update(newly_shared)

    async def _ensure_olm_session_locked(
        self,
        user_id: str,
        device_id: str,
        curve25519: str,
    ) -> Any | None:
        existing = self._olm_sessions.get(curve25519)
        if existing is not None:
            return existing

        claim_resp = await self._maybe_await(
            self._client.claim_keys(
                {user_id: {device_id: self._signed_curve_key_algorithm()}}
            )
        )
        one_time_keys = getattr(claim_resp, "one_time_keys", {}) or {}
        device_keys = (one_time_keys.get(user_id) or {}).get(device_id) or {}
        if not isinstance(device_keys, dict) or not device_keys:
            logger.debug(
                "Matrix E2EE: no one-time keys returned for %s / %s",
                user_id,
                device_id,
            )
            return None

        one_time_value = next(iter(device_keys.values()))
        if isinstance(one_time_value, dict):
            one_time_value = one_time_value.get("key")
        if not isinstance(one_time_value, str) or not one_time_value:
            return None

        try:
            session = mv.create_outbound_olm_session(self._account, curve25519, one_time_value)
        except Exception as exc:
            logger.debug("Matrix E2EE: failed to create outbound Olm session: %s", exc)
            return None

        self._olm_sessions[curve25519] = session
        return session

    async def _fetch_room_device_identities(
        self,
        room_id: str,
    ) -> dict[tuple[str, str], dict[str, str]]:
        members = await self._maybe_await(self._client.get_joined_members(room_id))
        user_ids = [str(user_id) for user_id in (members or {}).keys()]
        if not user_ids:
            return {}

        query = await self._maybe_await(self._client.query_keys(set(user_ids)))
        device_keys = getattr(query, "device_keys", {}) or {}

        resolved: dict[tuple[str, str], dict[str, str]] = {}
        for user_id, devices in device_keys.items():
            if not isinstance(devices, dict):
                continue
            for device_id, device in devices.items():
                curve = self._extract_curve25519_key(device)
                if not curve:
                    continue
                ed25519 = self._extract_ed25519_key(device)
                key = (str(user_id), str(device_id))
                resolved[key] = {
                    "curve25519": curve,
                    "ed25519": ed25519,
                }
                self._device_curve_cache[key] = curve
                if ed25519:
                    self._device_ed25519_cache[key] = ed25519

        return resolved

    @staticmethod
    def _canonical_json(payload: dict[str, Any]) -> str:
        return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

    def _build_device_keys_payload(self) -> dict[str, Any]:
        keys = {
            f"curve25519:{self._device_id}": self._curve25519,
            f"ed25519:{self._device_id}": self._ed25519,
        }
        payload = {
            "user_id": self._user_id,
            "device_id": self._device_id,
            "algorithms": [_OLM_ALGORITHM, _MEGOLM_ALGORITHM],
            "keys": keys,
        }
        payload["signatures"] = {
            self._user_id: {
                f"ed25519:{self._device_id}": mv.sign(self._account, self._canonical_json(payload))
            }
        }
        return payload

    def _sign_one_time_key(self, key_value: str) -> dict[str, Any]:
        payload = {"key": key_value}
        payload["signatures"] = {
            self._user_id: {
                f"ed25519:{self._device_id}": mv.sign(self._account, self._canonical_json(payload))
            }
        }
        return payload

    def _refresh_identity_keys_locked(self) -> None:
        keys = mv.account_identity_keys(self._account)
        self._ed25519 = str(keys.get("ed25519", ""))
        self._curve25519 = str(keys.get("curve25519", ""))

    def _load_state_locked(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.state_path.exists():
            return

        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Matrix E2EE: failed to load state file %s: %s", self.state_path, exc)
            return

        if raw.get("version") != _STATE_VERSION:
            return

        account_pickle = raw.get("account_pickle")
        if isinstance(account_pickle, str) and account_pickle:
            try:
                self._account = mv.unpickle_account(account_pickle, self._pickle_key)
            except Exception as exc:
                logger.warning("Matrix E2EE: could not unpickle account state: %s", exc)
                self._account = None

        if self._account is None:
            return

        self._refresh_identity_keys_locked()

        self._olm_sessions.clear()
        for sender_key, pickle in (raw.get("olm_sessions") or {}).items():
            if not isinstance(sender_key, str) or not isinstance(pickle, str):
                continue
            try:
                self._olm_sessions[sender_key] = mv.unpickle_olm_session(pickle, self._pickle_key)
            except Exception:
                continue

        self._inbound_group_sessions.clear()
        for key, pickle in (raw.get("inbound_group_sessions") or {}).items():
            if not isinstance(key, str) or not isinstance(pickle, str):
                continue
            room_id, sender_key, session_id = self._split_key(key, expected=3)
            if not room_id or not sender_key or not session_id:
                continue
            try:
                self._inbound_group_sessions[(room_id, sender_key, session_id)] = (
                    mv.unpickle_inbound_megolm_session(pickle, self._pickle_key)
                )
            except Exception:
                continue

        self._outbound_group_sessions.clear()
        for room_id, row in (raw.get("outbound_group_sessions") or {}).items():
            if not isinstance(room_id, str) or not isinstance(row, dict):
                continue
            pickle = row.get("pickle")
            if not isinstance(pickle, str):
                continue
            try:
                session = mv.unpickle_outbound_megolm_session(pickle, self._pickle_key)
            except Exception:
                continue

            shared_with = row.get("shared_with") or []
            self._outbound_group_sessions[room_id] = _OutboundMegolmState(
                session=session,
                shared_with={str(x) for x in shared_with if isinstance(x, str)},
            )

        self._device_curve_cache.clear()
        self._device_ed25519_cache.clear()
        for key, curve in (raw.get("device_curve_cache") or {}).items():
            if not isinstance(key, str) or not isinstance(curve, str):
                continue
            user_id, device_id = self._split_key(key, expected=2)
            if user_id and device_id:
                self._device_curve_cache[(user_id, device_id)] = curve

        for key, ed25519 in (raw.get("device_ed25519_cache") or {}).items():
            if not isinstance(key, str) or not isinstance(ed25519, str):
                continue
            user_id, device_id = self._split_key(key, expected=2)
            if user_id and device_id:
                self._device_ed25519_cache[(user_id, device_id)] = ed25519

    def _save_state_locked(self) -> None:
        if self._account is None:
            return

        data = {
            "version": _STATE_VERSION,
            "account_pickle": mv.pickle_account(self._account, self._pickle_key),
            "olm_sessions": {
                sender_key: mv.pickle_olm_session(session, self._pickle_key)
                for sender_key, session in self._olm_sessions.items()
            },
            "inbound_group_sessions": {
                self._join_key(room_id, sender_key, session_id): mv.pickle_inbound_megolm_session(
                    session,
                    self._pickle_key,
                )
                for (room_id, sender_key, session_id), session in self._inbound_group_sessions.items()
            },
            "outbound_group_sessions": {
                room_id: {
                    "pickle": mv.pickle_outbound_megolm_session(state.session, self._pickle_key),
                    "shared_with": sorted(state.shared_with),
                }
                for room_id, state in self._outbound_group_sessions.items()
            },
            "device_curve_cache": {
                self._join_key(user_id, device_id): curve
                for (user_id, device_id), curve in self._device_curve_cache.items()
            },
            "device_ed25519_cache": {
                self._join_key(user_id, device_id): ed25519
                for (user_id, device_id), ed25519 in self._device_ed25519_cache.items()
            },
        }

        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True), encoding="utf-8")
        temp.replace(self.state_path)

    @staticmethod
    def _join_key(*parts: str) -> str:
        return _KEY_SEP.join(parts)

    @staticmethod
    def _split_key(value: str, expected: int) -> tuple[str, ...]:
        parts = tuple(value.split(_KEY_SEP))
        if len(parts) != expected:
            return tuple("" for _ in range(expected))
        return parts

    @staticmethod
    async def _maybe_await(value: Any) -> Any:
        if inspect.isawaitable(value):
            return await value
        return value

    @staticmethod
    def _extract_curve25519_key(device_keys_obj: Any) -> str:
        keys = getattr(device_keys_obj, "keys", None)
        if keys is None and isinstance(device_keys_obj, dict):
            keys = device_keys_obj.get("keys")

        if not isinstance(keys, dict):
            return ""

        for key_id, value in keys.items():
            if str(key_id).startswith("curve25519:"):
                return str(value)
        return ""

    @staticmethod
    def _extract_ed25519_key(device_keys_obj: Any) -> str:
        keys = getattr(device_keys_obj, "keys", None)
        if keys is None and isinstance(device_keys_obj, dict):
            keys = device_keys_obj.get("keys")

        if not isinstance(keys, dict):
            return ""

        for key_id, value in keys.items():
            if str(key_id).startswith("ed25519:"):
                return str(value)
        return ""

    @staticmethod
    def _session_key_to_base64(session_key: Any) -> str:
        if isinstance(session_key, str):
            return session_key
        if hasattr(session_key, "to_base64"):
            return session_key.to_base64()
        return str(session_key)

    @staticmethod
    def _signed_curve_key_algorithm() -> Any:
        try:
            from mautrix.types import EncryptionKeyAlgorithm

            return EncryptionKeyAlgorithm.SIGNED_CURVE25519
        except Exception:
            return "signed_curve25519"

    @staticmethod
    def _to_device_event_type() -> Any:
        try:
            from mautrix.types import EventType

            return EventType.find("m.room.encrypted", EventType.Class.TO_DEVICE)
        except Exception:
            return "m.room.encrypted"

    @staticmethod
    def _room_encryption_event_type() -> Any:
        try:
            from mautrix.types import EventType

            return EventType.ROOM_ENCRYPTION
        except Exception:
            return "m.room.encryption"