"""Strict JSON and timestamp boundaries shared by the verifier and adapters."""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Any

MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_JSON_DEPTH = 64
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$")


class InputError(ValueError):
    """Input cannot safely be used as protocol JSON or a protocol timestamp."""


def parse_timestamp(value: Any) -> datetime:
    """Parse an explicit-offset RFC3339 instant and normalize it to UTC."""
    if not isinstance(value, str) or not RFC3339.fullmatch(value):
        raise InputError("timestamp must be RFC3339 with an explicit UTC offset")
    if value.endswith("-00:00"):
        raise InputError("unknown local offset is not a trusted timestamp")
    if value[-6:-5] in ("+", "-"):
        if int(value[-5:-3]) > 23 or int(value[-2:]) > 59:
            raise InputError("invalid timestamp offset")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise InputError("invalid calendar timestamp") from exc


def validate_json_value(value: Any) -> None:
    """Require finite JCS-compatible values, Unicode strings and safe integers."""
    active_containers: set[int] = set()

    def walk(item: Any, depth: int) -> None:
        if depth > MAX_JSON_DEPTH:
            raise InputError("JSON nesting limit exceeded")
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, str):
            try:
                item.encode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise InputError("JSON string contains invalid Unicode") from exc
            return
        if isinstance(item, int):
            if abs(item) > MAX_SAFE_INTEGER:
                raise InputError("JSON integer exceeds the interoperable safe range")
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise InputError("JSON numbers must be finite")
            return
        if not isinstance(item, (dict, list)):
            raise InputError("value is not a JSON type")
        identity = id(item)
        if identity in active_containers:
            raise InputError("cyclic input is not JSON")
        active_containers.add(identity)
        try:
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise InputError("JSON object names must be strings")
                    walk(key, depth + 1)
                    walk(child, depth + 1)
            else:
                for child in item:
                    walk(child, depth + 1)
        finally:
            active_containers.remove(identity)

    walk(value, 0)


def strict_json_loads(data: str | bytes | bytearray) -> Any:
    """Decode JSON without duplicate names, nonfinite values or lossy coercion."""
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise InputError("duplicate JSON property name")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise InputError("JSON numbers must be finite")

    if isinstance(data, (bytes, bytearray)):
        try:
            data = bytes(data).decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise InputError("JSON must use valid UTF-8") from exc
    if not isinstance(data, str):
        raise InputError("JSON input must be text or UTF-8 bytes")
    try:
        result = json.loads(data, object_pairs_hook=object_pairs, parse_constant=reject_constant)
        validate_json_value(result)
        return result
    except InputError:
        raise
    except (ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise InputError("invalid JSON input") from exc
