"""Offline replay of the public evidence for one channel-v1 run, whatever its outcome.

It checks the revealed channel declaration against its commitment, the
independently verified RFC 3161 time of that commitment, the channel layer
commitment, and, for a base PASS, the seller-signed channel artifact with the
unchanged deployed verifier. No network requests or payments are performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "vendor"))
from verifier.channel import CHANNELS, declaration_commitment, verify_channel
from verifier.signing import load_registry, registry_hash, verify_artifact
from verifier.validation import InputError, parse_timestamp, strict_json_loads

TRUST_FILE_SHA256 = "770e2a254de6d30ece20aee6de1c62ddcea0229b681dd1e760c071eb149b186f"
MAX_INPUT_BYTES = 128 * 1024
CHALLENGE = re.compile(r"qst_[a-f0-9]{32}")
HASH = re.compile(r"[a-f0-9]{64}")
BASE_STATUSES = ("PASS", "FAIL", "NOT_VERIFIED", "NO_RESULT")


class VerificationFailure(ValueError):
    """A public input failed a named, privacy-safe gate."""


def require(condition: bool, gate: str) -> None:
    if not condition:
        raise VerificationFailure(gate)


def read_limited(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(MAX_INPUT_BYTES + 1)
    require(0 < len(data) <= MAX_INPUT_BYTES, "input_size")
    return data


def pinned_registry() -> dict:
    path = ROOT / "trust" / "production-registry.json"
    require(hashlib.sha256(read_limited(path)).hexdigest() == TRUST_FILE_SHA256, "trust_file_digest")
    return load_registry(path)


def check_vendor() -> None:
    manifest = strict_json_loads((ROOT / "vendor-manifest.json").read_bytes())
    for relative, digest in manifest["files"].items():
        require(hashlib.sha256((ROOT / "vendor" / relative).read_bytes()).hexdigest() == digest, "vendor_source_digest")


def verify_inputs(declaration_bytes: bytes, proof_bytes: bytes | None, channel_bytes: bytes | None, *,
                  challenge_id: str, layer_channel: str, base_status: str, declaration_time: str | None,
                  not_before: str, layer_sha256: str, trusted_registry: dict, now: datetime) -> dict:
    """Internal replay entry; tests supply ephemeral synthetic trust. The CLI always uses the pinned registry.

    not_before and declaration_time are external trust inputs: the Sigstore time of the channel layer
    commitment and the RFC 3161 time of the declaration commitment, both verified by the workflow.
    """
    require(isinstance(challenge_id, str) and CHALLENGE.fullmatch(challenge_id) is not None, "challenge_format")
    require(layer_channel in CHANNELS, "layer_channel")
    require(base_status in BASE_STATUSES, "base_status")
    require(isinstance(layer_sha256, str) and HASH.fullmatch(layer_sha256) is not None, "layer_digest_format")
    require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None, "clock")
    committed = parse_timestamp(not_before)
    require(committed <= now, "commitment_in_future")
    declaration = strict_json_loads(declaration_bytes)
    require(isinstance(declaration, dict) and declaration.get("challenge_id") == challenge_id, "declaration_challenge")
    require(declaration.get("channel") == layer_channel, "declaration_channel")
    require(declaration_commitment(challenge_id, declaration["channel"], declaration["declared_at"],
                                   declaration["salt"]) == declaration["commitment"], "declaration_commitment")
    declared_at = parse_timestamp(declaration["declared_at"])
    require(declared_at <= now, "declaration_in_future")
    stamp = parse_timestamp(declaration_time) if declaration_time else None
    result = {"release": "channel-v1", "challenge_id": challenge_id, "declared_channel": layer_channel,
              "declared_at": declaration["declared_at"], "declaration_commitment": declaration["commitment"],
              "declaration_timestamp": declaration_time, "base_status": base_status,
              "layer_sha256": layer_sha256, "layer_attested_at": not_before,
              "declaration_sha256": hashlib.sha256(declaration_bytes).hexdigest()}
    if declared_at <= committed:
        return {**result, "status": "NOT_VERIFIED", "recorded_channel": None,
                "reason": "The challenge was issued before this channel layer was fixed"}
    if base_status != "PASS":
        return {**result, "status": "NOT_VERIFIED", "recorded_channel": None,
                "reason": "The base purchase is not a PASS" if base_status != "NO_RESULT"
                else "No result was submitted before the run ended"}
    require(proof_bytes is not None, "proof_missing")
    proof = strict_json_loads(proof_bytes)
    channel = strict_json_loads(channel_bytes) if channel_bytes is not None else None
    if channel is not None:
        # No future signature allowance in the public replay; JSON types must match the paid transaction exactly.
        valid, _ = verify_artifact(channel, "provider-transaction", trusted_registry, now=now, clock_skew_seconds=0)
        require(valid, "channel_signature")
        require(channel["challenge_id"] == channel["payload"]["challenge_id"] == challenge_id, "channel_challenge")
        require(all(type(channel["payload"][k]) is type(v) and channel["payload"][k] == v
                    for k, v in proof["provider_artifact"]["payload"].items()), "channel_transaction_types")
        require(parse_timestamp(channel["issued_at"]) <= now, "channel_signature_in_future")
    verdict = verify_channel(proof, channel, declaration, trusted_registry=trusted_registry,
                             declaration_timestamp=stamp, now=now)
    result.update({"status": verdict["status"], "reason": verdict["reason"],
                   "recorded_channel": verdict["recorded_channel"], "recorded": verdict["recorded"],
                   "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
                   "channel_sha256": hashlib.sha256(channel_bytes).hexdigest() if channel_bytes else None,
                   "verification_record_hash": proof["verification_record"]["hash"],
                   "registry_hash": registry_hash(trusted_registry)})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge-id", required=True)
    parser.add_argument("--channel", required=True, choices=CHANNELS)
    parser.add_argument("--base-status", required=True, choices=BASE_STATUSES)
    parser.add_argument("--declaration", required=True, type=Path)
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--channel-artifact", type=Path)
    parser.add_argument("--declaration-time", help="RFC 3161 time of the declaration commitment, verified with openssl")
    parser.add_argument("--not-before", required=True, help="Externally verified channel layer attestation time")
    parser.add_argument("--layer-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        check_vendor()
        result = verify_inputs(
            read_limited(args.declaration), read_limited(args.proof) if args.proof else None,
            read_limited(args.channel_artifact) if args.channel_artifact else None,
            challenge_id=args.challenge_id, layer_channel=args.channel, base_status=args.base_status,
            declaration_time=args.declaration_time, not_before=args.not_before, layer_sha256=args.layer_sha256,
            trusted_registry=pinned_registry(), now=datetime.now(timezone.utc))
    except (VerificationFailure, InputError, OSError, KeyError, TypeError, ValueError, OverflowError):
        # Never echo untrusted values, paths, payloads or exception messages.
        print(json.dumps({"status": "FAIL", "release": "channel-v1", "reason": "Evidence replay rejected"}))
        return 1
    # Exclusive creation prevents replacing an earlier replay.
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "reason": result["reason"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
