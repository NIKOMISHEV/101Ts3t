from __future__ import annotations

import base64
import copy
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from .hashing import canonical_json, sha256_hex
from .validation import InputError, parse_timestamp, strict_json_loads, validate_json_value

ALGORITHM = "Ed25519"
ARTIFACT_TYPES = {"discovery-review", "provider-transaction"}
ENVELOPE_FIELDS = {
    "artifact_type", "schema_version", "challenge_id", "issued_at",
    "signing_key_id", "signature_algorithm", "payload_hash", "payload", "signature",
}
HASH = re.compile(r"^[a-f0-9]{64}$")
REGISTRY_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "trusted-key-registry-v2.schema.json"


class RegistryError(InputError):
    """The operator-supplied registry is invalid; do not use it partially."""


def _b64decode(value: Any, length: int) -> bytes:
    if not isinstance(value, str):
        raise InputError("base64 value must be a string")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise InputError("invalid base64 encoding") from exc
    if len(decoded) != length or base64.b64encode(decoded).decode("ascii") != value:
        raise InputError("invalid base64 length or noncanonical encoding")
    return decoded


def _validated_registry(data: Any) -> dict[str, dict[str, Any]]:
    try:
        validate_json_value(data)
        if not isinstance(data, dict) or set(data) != {"registry_version", "keys"}:
            raise RegistryError("registry requires exactly registry_version and keys")
        if data["registry_version"] != "v2" or not isinstance(data["keys"], list):
            raise RegistryError("registry_version must be v2 and keys must be an array")
        registry: dict[str, dict[str, Any]] = {}
        public_keys: set[bytes] = set()
        required = {"key_id", "purpose", "status", "active_at", "public_key"}
        allowed = required | {"retired_at", "revoked_at"}
        for entry in data["keys"]:
            if not isinstance(entry, dict) or not required <= set(entry) or not set(entry) <= allowed:
                raise RegistryError("invalid registry entry fields")
            key_id = entry["key_id"]
            if not isinstance(key_id, str) or not key_id.strip() or key_id in registry:
                raise RegistryError("key IDs must be nonempty and unique")
            purpose, status = entry["purpose"], entry["status"]
            if purpose not in ARTIFACT_TYPES or status not in {"active", "retired", "revoked"}:
                raise RegistryError("invalid key purpose or status")
            public = _b64decode(entry["public_key"], 32)
            if public in public_keys:
                raise RegistryError("physical key material must have exactly one registry key ID")
            public_keys.add(public)
            active_at = parse_timestamp(entry["active_at"])
            retired_at = parse_timestamp(entry["retired_at"]) if "retired_at" in entry else None
            revoked_at = parse_timestamp(entry["revoked_at"]) if "revoked_at" in entry else None
            if retired_at is not None and retired_at <= active_at:
                raise RegistryError("retirement must follow activation")
            if revoked_at is not None and revoked_at < active_at:
                raise RegistryError("revocation must not precede activation")
            if status == "active" and (retired_at is not None or revoked_at is not None):
                raise RegistryError("active keys must not have retirement or revocation dates")
            if status == "retired" and (retired_at is None or revoked_at is not None):
                raise RegistryError("retired keys require retired_at and cannot have revoked_at")
            registry[key_id] = dict(entry)
        return registry
    except RegistryError:
        raise
    except (InputError, TypeError, KeyError, ValueError, OverflowError) as exc:
        raise RegistryError("invalid trust registry") from exc


def load_registry(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    raw_location = path or os.environ.get("DOTHAT_TRUSTED_KEY_REGISTRY")
    if not raw_location:
        return {}
    try:
        data = strict_json_loads(Path(raw_location).read_bytes())
        schema = strict_json_loads(REGISTRY_SCHEMA_PATH.read_bytes())
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        if not validator.is_valid(data):
            raise RegistryError("trusted-key registry does not match its v2 schema")
        return _validated_registry(data)
    except RegistryError:
        raise
    except (InputError, OSError, ValueError, TypeError) as exc:
        raise RegistryError("cannot load trusted-key registry") from exc


def registry_hash(registry: dict[str, dict[str, Any]]) -> str:
    if not isinstance(registry, dict):
        raise RegistryError("registry must be a mapping")
    validated = _validated_registry({"registry_version": "v2", "keys": list(registry.values())})
    if set(validated) != set(registry) or any(key != entry["key_id"] for key, entry in registry.items()):
        raise RegistryError("registry mapping keys must match entry key IDs")
    return sha256_hex({"registry_version": "v2", "keys": [validated[key] for key in sorted(validated)]})


def payload_hash(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        raise InputError("signed payload must be an object")
    return sha256_hex(payload)


def _validate_envelope(artifact: Any, expected_type: str, *, signature_required: bool = True) -> None:
    validate_json_value(artifact)
    fields = ENVELOPE_FIELDS if signature_required else ENVELOPE_FIELDS - {"signature"}
    if not isinstance(artifact, dict) or set(artifact) != fields:
        raise InputError("signed envelope fields are incomplete or unsupported")
    if expected_type not in ARTIFACT_TYPES or artifact["artifact_type"] != expected_type:
        raise InputError("incorrect artifact type")
    if artifact["schema_version"] != "v2" or artifact["signature_algorithm"] != ALGORITHM:
        raise InputError("unsupported envelope version or signature algorithm")
    if not isinstance(artifact["challenge_id"], str) or not artifact["challenge_id"].strip():
        raise InputError("challenge_id must be nonempty")
    if not isinstance(artifact["signing_key_id"], str) or not artifact["signing_key_id"].strip():
        raise InputError("signing_key_id must be nonempty")
    if not isinstance(artifact["payload_hash"], str) or not HASH.fullmatch(artifact["payload_hash"]):
        raise InputError("invalid payload hash")
    payload = artifact["payload"]
    if not isinstance(payload, dict) or payload.get("challenge_id") != artifact["challenge_id"]:
        raise InputError("envelope and payload challenge IDs must match")
    parse_timestamp(artifact["issued_at"])
    if signature_required:
        _b64decode(artifact["signature"], 64)


def sign_artifact(
    artifact_type: str,
    schema_version: str,
    challenge_id: str,
    issued_at: str,
    signing_key_id: str,
    payload: dict[str, Any],
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    envelope = {
        "artifact_type": artifact_type,
        "schema_version": schema_version,
        "challenge_id": challenge_id,
        "issued_at": issued_at,
        "signing_key_id": signing_key_id,
        "signature_algorithm": ALGORITHM,
        "payload_hash": payload_hash(payload),
        "payload": payload,
    }
    _validate_envelope(envelope, artifact_type, signature_required=False)
    # Snapshot JSON so later caller mutation cannot change the returned payload.
    envelope = copy.deepcopy(envelope)
    signature = private_key.sign(canonical_json(envelope).encode("utf-8"))
    return {**envelope, "signature": base64.b64encode(signature).decode("ascii")}


def verify_artifact(
    artifact: dict[str, Any],
    expected_type: str,
    registry: dict[str, dict[str, Any]],
    now: datetime | None = None,
    clock_skew_seconds: int = 60,
) -> tuple[bool, str]:
    """Verify a v2 envelope; trusted caller time is never read from evidence."""
    try:
        _validate_envelope(artifact, expected_type)
        if artifact["payload_hash"] != payload_hash(artifact["payload"]):
            return False, "payload_hash"
        if not isinstance(registry, dict):
            return False, "invalid_registry"
        checked_registry = _validated_registry({"registry_version": "v2", "keys": list(registry.values())})
        if set(checked_registry) != set(registry) or any(key != entry["key_id"] for key, entry in registry.items()):
            return False, "invalid_registry"
        entry = checked_registry.get(artifact["signing_key_id"])
        if entry is None:
            return False, "unknown_key"
        if entry["purpose"] != expected_type:
            return False, "key_purpose"
        # Revocation is retrospective: self-reported issue time is not proof
        # that a signature existed before compromise.
        if entry["status"] == "revoked":
            return False, "revoked_key"
        issued_at = parse_timestamp(artifact["issued_at"])
        if issued_at < parse_timestamp(entry["active_at"]):
            return False, "key_not_active"
        if entry["status"] == "retired" and issued_at >= parse_timestamp(entry["retired_at"]):
            return False, "retired_key"
        current = datetime.now(timezone.utc) if now is None else now
        if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
            return False, "invalid_verification_time"
        if type(clock_skew_seconds) is not int or not 0 <= clock_skew_seconds <= 300:
            return False, "invalid_clock_skew"
        if (issued_at - current.astimezone(timezone.utc)).total_seconds() > clock_skew_seconds:
            return False, "issued_in_future"
        key = Ed25519PublicKey.from_public_bytes(_b64decode(entry["public_key"], 32))
        signed = {key: value for key, value in artifact.items() if key != "signature"}
        key.verify(_b64decode(artifact["signature"], 64), canonical_json(signed).encode("utf-8"))
        return True, "verified"
    except RegistryError:
        return False, "invalid_registry"
    except InvalidSignature:
        return False, "signature"
    except (InputError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        return False, "invalid_artifact"
