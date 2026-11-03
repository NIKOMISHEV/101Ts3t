"""Optional route qualification for a separately signed 101Ts3t purchase.

The original v1.0-draft challenge, PASS record and provider-v2 artifact remain
unchanged. This verifier only adds a narrower claim about the merchant-recorded
checkout route and KYA state for a later transaction.
"""
from __future__ import annotations

import argparse
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .hashing import hash_object_without_hash, sha256_hex
from .signing import load_registry, registry_hash, verify_artifact
from .validation import InputError, parse_timestamp, strict_json_loads
from .verifier import PROTOCOL_VERSION, protocol_hash, validate_schema

ROUTES = {"bd-commerce/1", "acp/2026-04-17", "ucp/2026-08-25", "ucp/2026-04-08", "website"}
ROUTE_FIELDS = {"profile", "entry_protocol", "payment_protocol", "payment_instrument",
                "payment_started_at", "provider_envelope_hash", "kya"}
ENVELOPE_FIELDS = {"artifact_type", "schema_version", "challenge_id", "issued_at", "signing_key_id",
                   "signature_algorithm", "payload_hash", "payload", "signature"}
HASH = re.compile(r"^[a-f0-9]{64}$")
PASS_DIMENSIONS = {"DISCOVERY_EVIDENCE", "TRANSACTION_EVIDENCE", "EVIDENCE_INTEGRITY",
                   "VERIFIED_AGENTIC_COMMERCE"}


def _result(status: str, reason: str, protocol: str | None = None) -> dict:
    return {"status": status, "reason": reason, "qualified_protocol": protocol}


def verify_route(proof: dict, route_artifact: dict | None, registry_path: str | Path | None = None,
                 *, trusted_registry: dict | None = None, now: datetime | None = None) -> dict:
    """Require a separate registry path, or a caller-validated registry snapshot.

    The backend may pass its already validated historical registry snapshot;
    an offline caller must pass a registry file obtained through a trusted channel.
    """
    if route_artifact is None:
        return _result("NOT_VERIFIED", "Signed route artifact is missing")
    try:
        if validate_schema(proof, "proof"):
            return _result("FAIL", "Public PASS package has an invalid schema")
        record = proof["verification_record"]
        provider = proof["provider_artifact"]
        review = proof["review_artifact"]
        if any(validate_schema(value, kind) for value, kind in ((record, "verification"),
                                                                (provider, "provider"), (review, "review"))):
            return _result("FAIL", "Public PASS package contains invalid evidence")
        if record["status"] != "PASS" or set(record["result_summary"]) != PASS_DIMENSIONS or any(
                value != "PASS" for value in record["result_summary"].values()):
            return _result("FAIL", "The base purchase is not a complete PASS")
        if record["hash"] != hash_object_without_hash(record):
            return _result("FAIL", "Verification record hash mismatch")
        if record["protocol_version"] != PROTOCOL_VERSION or record["protocol_hash"] != protocol_hash():
            return _result("FAIL", "The PASS record is not for the published original quest")
        if (registry_path is None) == (trusted_registry is None):
            return _result("FAIL", "Exactly one trusted registry source is required")
        registry = load_registry(registry_path) if registry_path is not None else trusted_registry
        if registry_hash(registry) != record["registry_hash"]:
            return _result("FAIL", "Trusted registry does not match the PASS record")
        public_keys = proof["trusted_key_registry"]["keys"]
        if len(public_keys) != len(registry) or {entry["key_id"]: entry for entry in public_keys} != registry:
            return _result("FAIL", "Public and separately trusted registries differ")
        clock = now or datetime.now(timezone.utc)
        if clock.tzinfo is None or clock.utcoffset() is None:
            return _result("FAIL", "Verification clock has no timezone")
        for artifact, kind, commitment in ((provider, "provider-transaction", "provider_envelope_hash"),
                                           (review, "discovery-review", "review_envelope_hash")):
            valid, _ = verify_artifact(artifact, kind, registry, now=clock)
            if not valid or record[commitment] != sha256_hex(artifact):
                return _result("FAIL", "Signed PASS artifact or commitment is invalid")
        if not (proof["challenge_id"] == record["challenge_id"] == provider["challenge_id"]
                == review["challenge_id"] == provider["payload"]["challenge_id"]):
            return _result("FAIL", "PASS artifacts have different challenges")
        pp = provider["payload"]
        rp = review["payload"]
        if (pp["challenge_context_hash"] != record["challenge_context_hash"]
                or rp["challenge_context_hash"] != record["challenge_context_hash"]
                or rp["provider_payload_hash"] != provider["payload_hash"]
                or rp["review_result"] != "PASS" or rp["protocol_hash"] != record["protocol_hash"]
                or rp["exact_prompt_hash"] != record["prompt_hash"]):
            return _result("FAIL", "PASS artifact linkage is invalid")
        if (rp["participant_evidence_hash"] != record["participant_evidence_hash"]
                or rp["agent_evidence_hash"] != record["agent_evidence_hash"]
                or rp["trace_hash"] != record["trace_hash"]
                or any(rp[name] is not True for name in ("prompt_integrity", "merchant_not_pre_supplied",
                                                              "destination_not_pre_supplied", "usable_chronological_trace",
                                                              "independent_reach"))
                or pp["service"] != "101Ts3t" or pp["currency"] != "EUR"
                or type(pp["amount_minor"]) is not int or not 1 <= pp["amount_minor"] <= 100
                or pp["payment_status"] != "PAID" or pp["fulfillment_status"] != "COMPLETED"):
            return _result("FAIL", "Signed discovery or payment does not satisfy the base test")
        if not isinstance(route_artifact, dict) or set(route_artifact) != ENVELOPE_FIELDS:
            return _result("FAIL", "Route artifact envelope has unexpected fields")
        if route_artifact["signing_key_id"] != provider["signing_key_id"]:
            return _result("FAIL", "Route and payment were not attested by the same provider key")
        valid, _ = verify_artifact(route_artifact, "provider-transaction", registry, now=clock)
        if not valid:
            return _result("FAIL", "Route signature or provider key is invalid")
        payload = route_artifact["payload"]
        if not isinstance(payload, dict) or set(payload) != set(pp) | {"route_evidence"} or any(
                payload[key] != value for key, value in pp.items()):
            return _result("FAIL", "Route artifact does not describe the same paid transaction")
        detail = payload["route_evidence"]
        if not isinstance(detail, dict) or set(detail) != ROUTE_FIELDS or detail["profile"] != "bd-commerce-route/1":
            return _result("FAIL", "Route evidence has an invalid profile")
        if detail["provider_envelope_hash"] != sha256_hex(provider):
            return _result("FAIL", "Route evidence is not bound to the original payment artifact")
        if detail["entry_protocol"] not in ROUTES or detail["payment_protocol"] not in ROUTES:
            return _result("FAIL", "Unknown checkout route")
        if detail["payment_instrument"] not in {"shared-payment-token", "hosted-checkout"}:
            return _result("FAIL", "Unknown payment instrument")
        started = parse_timestamp(detail["payment_started_at"])
        if not (started <= parse_timestamp(pp["server_timestamp"]) <= parse_timestamp(provider["issued_at"])
                <= parse_timestamp(route_artifact["issued_at"])):
            return _result("FAIL", "Payment and signature chronology is inconsistent")
        kya = detail["kya"]
        if not isinstance(kya, dict):
            return _result("FAIL", "KYA evidence is malformed")
        if kya.get("level") == "merchant-verified-domain-control":
            if (set(kya) != {"level", "domain_sha256", "verified_at"}
                    or not isinstance(kya["domain_sha256"], str) or not HASH.fullmatch(kya["domain_sha256"])):
                return _result("FAIL", "KYA domain commitment is malformed")
            verified = parse_timestamp(kya["verified_at"])
            if not verified <= started <= verified + timedelta(hours=24):
                return _result("FAIL", "KYA verification was not current at payment start")
        elif kya != {"level": "not-recorded"}:
            return _result("FAIL", "Unknown KYA level")
        if detail["entry_protocol"] != detail["payment_protocol"]:
            return _result("NOT_VERIFIED", "Order and payment used different routes")
        if detail["entry_protocol"] == "website":
            return _result("NOT_VERIFIED", "The purchase used the website")
        if detail["payment_instrument"] != "shared-payment-token" or kya["level"] != "merchant-verified-domain-control":
            return _result("NOT_VERIFIED", "Autonomous payment and current KYA were not both attested")
        return _result("PASS", "The seller signed the same route at order and payment, with current domain-control KYA",
                       detail["entry_protocol"])
    except (InputError, KeyError, OSError, TypeError, ValueError, OverflowError):
        return _result("FAIL", "Malformed or inconsistent route evidence")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--route", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    args = parser.parse_args()
    import json
    try:
        result = verify_route(strict_json_loads(args.proof.read_bytes()),
                              strict_json_loads(args.route.read_bytes()), args.registry)
    except (OSError, ValueError):
        result = _result("FAIL", "Input files could not be read")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
