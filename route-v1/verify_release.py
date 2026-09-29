"""Offline replay of public, signed evidence for a new route-qualified purchase.

This checks trusted signers' assertions. It cannot recreate private discovery
traces, prove real-world truth independently of those signers, or date challenge
issuance from a public proof. No network requests or payments are performed.
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
from verifier.hashing import hash_object_without_hash, sha256_hex
from verifier.route import PASS_DIMENSIONS, verify_route
from verifier.signing import load_registry, registry_hash, verify_artifact
from verifier.validation import InputError, parse_timestamp, strict_json_loads
from verifier.verifier import PROTOCOL_VERSION, protocol_hash, prompt_hash, validate_schema

ALLOWED_PROTOCOLS = ("bd-commerce/1", "acp/2026-04-17", "ucp/2026-08-25", "ucp/2026-04-08")
TRUST_FILE_SHA256 = "770e2a254de6d30ece20aee6de1c62ddcea0229b681dd1e760c071eb149b186f"
MAX_INPUT_BYTES = 128 * 1024
CHALLENGE = re.compile(r"qst_[a-f0-9]{32}")
ORDER = re.compile(r"bd_[a-f0-9]{32}")
EVENT = re.compile(r"evt_[a-f0-9]{32}")
HASH = re.compile(r"[a-f0-9]{64}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


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
        path = ROOT / "vendor" / relative
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, "vendor_source_digest")


def validate_base(proof: dict, challenge_id: str, registry: dict, now: datetime) -> None:
    """Authenticate signed assertions supporting public PASS, not unsigned metadata."""
    require(isinstance(challenge_id, str) and CHALLENGE.fullmatch(challenge_id) is not None,
            "requested_challenge_format")
    require(not validate_schema(proof, "proof"), "proof_schema")
    record, provider, review = (proof[k] for k in ("verification_record", "provider_artifact", "review_artifact"))
    for value, kind in ((record, "verification"), (provider, "provider"), (review, "review"),
                        (proof["trusted_key_registry"], "registry")):
        require(not validate_schema(value, kind), "base_" + kind + "_schema")
    require(all(v == challenge_id for v in (proof["challenge_id"], record["challenge_id"],
                provider["challenge_id"], review["challenge_id"], provider["payload"]["challenge_id"],
                review["payload"]["challenge_id"])), "base_challenge_binding")
    expected_registry = {"registry_version": "v2", "keys": [registry[k] for k in sorted(registry)]}
    # Array ordering is not a source of authority, but duplicate keys/extra fields are forbidden.
    public_registry = proof["trusted_key_registry"]
    require(public_registry["registry_version"] == "v2" and
            len(public_registry["keys"]) == len(registry) and
            sorted(public_registry["keys"], key=lambda k: k["key_id"]) == expected_registry["keys"],
            "separate_trust_registry")
    require(record["registry_hash"] == registry_hash(registry), "registry_commitment")
    require(record["status"] == "PASS" and set(record["result_summary"]) == PASS_DIMENSIONS and
            all(v == "PASS" for v in record["result_summary"].values()), "base_pass_gates")
    require(record["hash"] == hash_object_without_hash(record), "record_digest")
    require(record["protocol_version"] == PROTOCOL_VERSION and record["protocol_hash"] == protocol_hash(),
            "original_protocol_commitment")
    require(record["prompt_hash"] == prompt_hash(challenge_id), "original_prompt_commitment")
    require(record["policy_version"] == "signed-evidence-v2", "base_policy")
    require(VERSION.fullmatch(record["verifier_version"]) is not None, "verifier_version_format")
    for artifact, kind, digest in ((provider, "provider-transaction", "provider_envelope_hash"),
                                   (review, "discovery-review", "review_envelope_hash")):
        valid, _ = verify_artifact(artifact, kind, registry, now=now, clock_skew_seconds=0)
        require(valid, "base_signature_" + kind)
        require(record[digest] == sha256_hex(artifact), "base_envelope_commitment")
    pp, rp = provider["payload"], review["payload"]
    require(pp["challenge_context_hash"] == rp["challenge_context_hash"] == record["challenge_context_hash"],
            "context_binding")
    for field, source in (("protocol_hash", "protocol_hash"), ("exact_prompt_hash", "prompt_hash"),
                          ("participant_evidence_hash", "participant_evidence_hash"),
                          ("agent_evidence_hash", "agent_evidence_hash"), ("trace_hash", "trace_hash")):
        require(rp[field] == record[source], "review_commitment_" + field)
    require(rp["provider_payload_hash"] == provider["payload_hash"] and rp["review_result"] == "PASS" and
            all(rp[k] is True for k in ("prompt_integrity", "merchant_not_pre_supplied",
                "destination_not_pre_supplied", "usable_chronological_trace", "independent_reach")),
            "signed_discovery_gates")
    require(pp["service"] == "101Ts3t" and pp["currency"] == "EUR" and
            type(pp["amount_minor"]) is int and 1 <= pp["amount_minor"] <= 100 and
            pp["payment_status"] == "PAID" and pp["fulfillment_status"] == "COMPLETED", "signed_payment")
    require(ORDER.fullmatch(pp["transaction_order_reference"]) is not None and
            EVENT.fullmatch(pp["provider_event_reference"]) is not None, "public_reference_format")
    require(VERSION.fullmatch(rp["reviewer_verifier_version"]) is not None, "reviewer_version_format")
    require(parse_timestamp(pp["server_timestamp"]) <= parse_timestamp(provider["issued_at"]) <=
            parse_timestamp(rp["reviewed_at"]) <= parse_timestamp(review["issued_at"]) <=
            parse_timestamp(record["verified_at"]) <= now, "base_chronology")


def verify_inputs(proof_bytes: bytes, route_bytes: bytes, *, challenge_id: str,
                  expected_protocol: str, not_before: str, spec_sha256: str,
                  trusted_registry: dict, now: datetime) -> dict:
    """Internal replay entry; tests explicitly supply ephemeral synthetic trust.

    Production CLI always loads pinned_registry(); it accepts no trust override.
    not_before is an external trust input derived by the publication workflow
    from a verified Sigstore specification attestation, not from submitted proof.
    """
    require(0 < len(proof_bytes) <= MAX_INPUT_BYTES and 0 < len(route_bytes) <= MAX_INPUT_BYTES, "input_size")
    require(expected_protocol in ALLOWED_PROTOCOLS, "expected_protocol")
    require(isinstance(spec_sha256, str) and HASH.fullmatch(spec_sha256) is not None, "spec_digest_format")
    require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None, "clock")
    committed = parse_timestamp(not_before)
    require(committed <= now, "commitment_in_future")
    proof, route = strict_json_loads(proof_bytes), strict_json_loads(route_bytes)
    validate_base(proof, challenge_id, trusted_registry, now)
    # Run the unchanged deployed verifier, including signature, binding, KYA and route semantics.
    result = verify_route(proof, route, trusted_registry=trusted_registry, now=now)
    require(result["status"] == "PASS", "route_did_not_pass")
    require(result["qualified_protocol"] == expected_protocol, "qualified_protocol_mismatch")
    require(route["challenge_id"] == route["payload"]["challenge_id"] == challenge_id,
            "route_challenge_binding")
    # Python equality treats True == 1 and 99.0 == 99. Preserve JSON field
    # types as well as values when binding the separately signed route copy.
    require(all(type(route["payload"][k]) is type(v) and route["payload"][k] == v
                for k, v in proof["provider_artifact"]["payload"].items()), "route_transaction_types")
    # No future signature allowance in the public release replay.
    valid, _ = verify_artifact(route, "provider-transaction", trusted_registry, now=now, clock_skew_seconds=0)
    require(valid, "route_signature")
    started = parse_timestamp(route["payload"]["route_evidence"]["payment_started_at"])
    require(started > committed, "purchase_predates_spec_commitment")
    require(parse_timestamp(route["issued_at"]) <= now, "route_signature_in_future")
    return {
        "release": "route-v1", "status": "PASS", "base_status": "PASS",
        "challenge_id": challenge_id, "qualified_protocol": expected_protocol,
        "payment_started_at": route["payload"]["route_evidence"]["payment_started_at"],
        "specification_sha256": spec_sha256, "specification_attested_at": not_before,
        "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
        "route_sha256": hashlib.sha256(route_bytes).hexdigest(),
        "verification_record_hash": proof["verification_record"]["hash"],
        "registry_hash": registry_hash(trusted_registry),
        "claim": "Trusted provider/reviewer assertions supporting base PASS and matching route evidence replayed offline; payment start follows the externally authenticated specification commitment.",
        "limitations": "Private discovery trace and challenge issuance time are not reconstructed. Record hash is a checksum: backend finalization, unsigned projection fields and record-chain metadata are not independently authenticated by this replay.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge-id", required=True)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--route", required=True, type=Path)
    parser.add_argument("--expected-protocol", required=True, choices=ALLOWED_PROTOCOLS)
    parser.add_argument("--not-before", required=True, help="Externally verified spec attestation RFC3339 timestamp")
    parser.add_argument("--spec-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        check_vendor()
        require(hashlib.sha256((ROOT / "SPECIFICATION.md").read_bytes()).hexdigest() == args.spec_sha256,
                "specification_file_digest")
        result = verify_inputs(read_limited(args.proof), read_limited(args.route),
            challenge_id=args.challenge_id, expected_protocol=args.expected_protocol,
            not_before=args.not_before, spec_sha256=args.spec_sha256,
            trusted_registry=pinned_registry(), now=datetime.now(timezone.utc))
    except (VerificationFailure, InputError, OSError, KeyError, TypeError, ValueError, OverflowError):
        # Never echo untrusted values, paths, payloads, traces or exception messages.
        print(json.dumps({"status": "FAIL", "release": "route-v1", "reason": "Evidence replay rejected"}))
        return 1
    # Exclusive creation prevents replacing an earlier replay, input or historical file.
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
