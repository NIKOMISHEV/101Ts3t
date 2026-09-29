from __future__ import annotations

import argparse
import json
from pathlib import Path

from .validation import InputError, parse_timestamp, strict_json_loads
from .verifier import invalid_result, verify_document, verify_examples


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify evidence using explicit trusted context. Evidence paths are never resolved automatically.")
    parser.add_argument("path", nargs="?", help="Untrusted evidence document JSON")
    parser.add_argument("--challenge", type=Path, help="Trusted immutable challenge context JSON")
    parser.add_argument("--registry", type=Path, help="Trusted public-key registry JSON")
    parser.add_argument("--trace", type=Path, help="Explicit trace bytes file")
    parser.add_argument("--provider", type=Path, help="Explicit signed provider JSON file")
    parser.add_argument("--previous-record", type=Path, help="Trusted previously stored verification record")
    parser.add_argument("--as-of", help="Trusted historical verification time, RFC3339; current UTC by default")
    args = parser.parse_args()
    try:
        if args.path:
            result = verify_document(strict_json_loads(Path(args.path).read_bytes()),
                trace_bytes=args.trace.read_bytes() if args.trace else None,
                provider_bytes=args.provider.read_bytes() if args.provider else None,
                trusted_key_registry=args.registry,
                trusted_challenge=strict_json_loads(args.challenge.read_bytes()) if args.challenge else None,
                trusted_previous_record=strict_json_loads(args.previous_record.read_bytes()) if args.previous_record else None,
                now=parse_timestamp(args.as_of) if args.as_of else None)
        else:
            result = verify_examples()
    except (InputError, OSError, ValueError) as error:
        result = invalid_result(f"input_or_configuration.{type(error).__name__}: {str(error)[:240]}")
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    if args.path and result["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
