"""Matrix E2EE helpers backed by python vodozemac bindings.

This module wraps the low-level Olm/Megolm APIs exposed by the
``vodozemac`` package and provides stable helper functions for Hermes.
The wrappers intentionally stay thin so callers can control higher-level
Matrix protocol behavior themselves.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any


class MissingVodozemacDependencyError(RuntimeError):
    """Raised when vodozemac helpers are used without vodozemac installed."""


try:
    import vodozemac as _vodozemac
except Exception:  # pragma: no cover - exercised when dependency is absent
    _vodozemac = None


def _to_bytes(value: bytes | str) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _to_text(value: bytes | str) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else value


def _key_to_base64(key: Any) -> str:
    if isinstance(key, str):
        return key
    if hasattr(key, "to_base64"):
        return key.to_base64()
    return str(key)


def _require_vodozemac() -> Any:
    if _vodozemac is None:
        raise MissingVodozemacDependencyError(
            "vodozemac is required for Matrix E2EE helpers"
        )
    return _vodozemac


def has_required_bindings() -> bool:
    """Return True when the core vodozemac Python bindings are available."""
    vz = _vodozemac
    if vz is None:
        return False

    required_symbols = (
        "Account",
        "Session",
        "GroupSession",
        "InboundGroupSession",
    )
    return all(hasattr(vz, symbol) for symbol in required_symbols)


def _normalize_pickle_key(pickle_key: bytes | str) -> bytes:
    """Return a 32-byte pickle key accepted by vodozemac.

    vodozemac pickle APIs expect a 32-byte key. For callers that provide
    arbitrary passphrases, we derive a stable 32-byte value via SHA-256.
    """
    if isinstance(pickle_key, bytes):
        return pickle_key if len(pickle_key) == 32 else hashlib.sha256(pickle_key).digest()
    return hashlib.sha256(pickle_key.encode("utf-8")).digest()


def create_account() -> Any:
    """Create a new Olm account."""
    vz = _require_vodozemac()
    return vz.Account()


def account_identity_keys(account: Any) -> dict[str, str]:
    """Return account identity keys in Matrix upload format."""
    return {
        "ed25519": _key_to_base64(account.ed25519_key),
        "curve25519": _key_to_base64(account.curve25519_key),
    }


def sign(account: Any, message: str) -> str:
    """Sign a UTF-8 message with the account ed25519 key."""
    signature = account.sign(_to_bytes(message))
    if hasattr(signature, "to_base64"):
        return signature.to_base64()
    return _to_text(signature)


def generate_one_time_keys(account: Any, count: int) -> dict[str, str]:
    """Generate one-time keys and return the updated one-time-key map."""
    account.generate_one_time_keys(count)
    return {str(key_id): _key_to_base64(key) for key_id, key in account.one_time_keys.items()}


def mark_keys_as_published(account: Any) -> None:
    """Mark uploaded one-time/fallback keys as published."""
    account.mark_keys_as_published()


def generate_fallback_key(account: Any) -> dict[str, str]:
    """Generate and return fallback keys for this account."""
    account.generate_fallback_key()
    return {str(key_id): _key_to_base64(key) for key_id, key in account.fallback_key.items()}


def create_outbound_olm_session(account: Any, identity_key: str, one_time_key: str) -> Any:
    """Create an outbound Olm session to another device."""
    return account.create_outbound_session(identity_key, one_time_key)


def create_inbound_olm_session(account: Any, identity_key: str, prekey_message: Any) -> tuple[Any, str]:
    """Create an inbound Olm session from an incoming pre-key message."""
    message = prekey_message
    if hasattr(prekey_message, "to_pre_key"):
        converted = prekey_message.to_pre_key()
        if converted is None:
            raise ValueError("Inbound session creation requires a pre-key message")
        message = converted
    session, plaintext = account.create_inbound_session(identity_key, message)
    return session, _to_text(plaintext)


def encrypt_olm(session: Any, plaintext: str) -> Any:
    """Encrypt plaintext with an Olm session."""
    return session.encrypt(_to_bytes(plaintext))


def decrypt_olm(session: Any, message: Any) -> str:
    """Decrypt an Olm message with an existing session."""
    return _to_text(session.decrypt(message))


def create_outbound_megolm_session() -> Any:
    """Create a new outbound Megolm (group) session."""
    vz = _require_vodozemac()
    return vz.GroupSession()


def create_inbound_megolm_session(session_key: str) -> Any:
    """Create an inbound Megolm session from a base64 session key."""
    vz = _require_vodozemac()
    return vz.InboundGroupSession(session_key)


def import_inbound_megolm_session(exported_session_key: str) -> Any:
    """Import an inbound Megolm session from an exported session key."""
    vz = _require_vodozemac()
    return vz.InboundGroupSession.import_session(exported_session_key)


def encrypt_megolm(session: Any, plaintext: str) -> str:
    """Encrypt plaintext into a base64 Megolm message."""
    return _to_text(session.encrypt(_to_bytes(plaintext)))


def decrypt_megolm(session: Any, ciphertext: str) -> tuple[str, int]:
    """Decrypt a Megolm message and return plaintext with message index."""
    decrypted = session.decrypt(ciphertext)
    return _to_text(decrypted.plaintext), int(decrypted.message_index)


def olm_message_to_matrix_parts(message: Any) -> tuple[int, str]:
    """Convert AnyOlmMessage to Matrix wire ``type`` + base64 body."""
    msg_type, body = message.to_parts()
    body_bytes = _to_bytes(body)
    return int(msg_type), base64.b64encode(body_bytes).decode("ascii")


def olm_message_from_matrix_parts(message_type: int, body_b64: str) -> Any:
    """Build AnyOlmMessage from Matrix wire ``type`` + base64 body."""
    vz = _require_vodozemac()
    body = base64.b64decode(body_b64)
    return vz.AnyOlmMessage.from_parts(int(message_type), body)


def pickle_account(account: Any, pickle_key: bytes | str) -> str:
    return account.pickle(_normalize_pickle_key(pickle_key))


def unpickle_account(pickle: str, pickle_key: bytes | str) -> Any:
    vz = _require_vodozemac()
    return vz.Account.from_pickle(pickle, _normalize_pickle_key(pickle_key))


def pickle_olm_session(session: Any, pickle_key: bytes | str) -> str:
    return session.pickle(_normalize_pickle_key(pickle_key))


def unpickle_olm_session(pickle: str, pickle_key: bytes | str) -> Any:
    vz = _require_vodozemac()
    return vz.Session.from_pickle(pickle, _normalize_pickle_key(pickle_key))


def pickle_outbound_megolm_session(session: Any, pickle_key: bytes | str) -> str:
    return session.pickle(_normalize_pickle_key(pickle_key))


def unpickle_outbound_megolm_session(pickle: str, pickle_key: bytes | str) -> Any:
    vz = _require_vodozemac()
    return vz.GroupSession.from_pickle(pickle, _normalize_pickle_key(pickle_key))


def pickle_inbound_megolm_session(session: Any, pickle_key: bytes | str) -> str:
    return session.pickle(_normalize_pickle_key(pickle_key))


def unpickle_inbound_megolm_session(pickle: str, pickle_key: bytes | str) -> Any:
    vz = _require_vodozemac()
    return vz.InboundGroupSession.from_pickle(pickle, _normalize_pickle_key(pickle_key))
