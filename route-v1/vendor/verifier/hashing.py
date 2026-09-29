from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import rfc8785

from .validation import InputError, validate_json_value


def canonical_json(value: Any) -> str:
    """Return RFC 8785 JSON Canonicalization Scheme text."""
    validate_json_value(value)
    try:
        return rfc8785.dumps(value).decode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise InputError("input cannot be canonicalized as RFC 8785 JSON") from exc


def sha256_hex(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        payload = bytes(value)
    elif isinstance(value, str):
        validate_json_value(value)
        payload = value.encode("utf-8")
    else:
        payload = canonical_json(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def hash_file(path: str | Path) -> str:
    return sha256_hex(Path(path).read_bytes())


def hash_record(record: Any) -> str:
    return sha256_hex(record)


def hash_object_without_hash(record: Any) -> str:
    if isinstance(record, dict):
        return sha256_hex({key: value for key, value in record.items() if key != "hash"})
    return hash_record(record)


def hash_chain(previous_record: Any | None, record: Any) -> str:
    payload = {
        "previous_record": previous_record,
        "record": {key: value for key, value in record.items() if key != "hash"},
    }
    return sha256_hex(payload)
