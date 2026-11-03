"""Channel qualification (channel-v1) for a separately signed 101Ts3t purchase.

The original v1.0-draft challenge, its PASS record, the provider-v2 artifact and
route-v1 stay unchanged. This verifier adds one narrower claim: the payment
channel the operator declared when the challenge was issued is the channel the
seller signed for the same paid transaction.

The declaration is committed at issuance. Its commitment carries an independent
RFC 3161 timestamp; the caller verifies that token separately and passes the
authenticated time. Since channel-v2 the server also names the declared channel
in the prompt it issues (v1.0-draft+channel.<channel>); a run under the neutral
v1.0-draft prompt with a hidden declaration still qualifies, a run under another
channel's prompt does not.
"""
from __future__ import annotations

import argparse
import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .hashing import hash_object_without_hash, sha256_hex
from .signing import load_registry, registry_hash, verify_artifact
from .validation import InputError, parse_timestamp, strict_json_loads
from .verifier import PROMPT_VERSION, PROTOCOL_VERSION, channel_prompt_version, prompt_hash, protocol_hash, validate_schema

CHANNELS = ("mcp", "http-api", "acp", "ucp", "a2a", "browser")
PROTOCOLS = {"bd-commerce/1", "acp/2026-04-17", "ucp/2026-08-25", "ucp/2026-04-08", "website"}
TRANSPORTS = {"mcp", "http", "a2a", "web"}
CHANNEL_FIELDS = {"profile", "entry_protocol", "entry_transport", "payment_protocol", "payment_transport",
                  "payment_instrument", "payment_started_at", "provider_envelope_hash", "kya"}
DECLARATION_FIELDS = {"challenge_id", "channel", "declared_at", "salt", "commitment"}
ENVELOPE_FIELDS = {"artifact_type", "schema_version", "challenge_id", "issued_at", "signing_key_id",
                   "signature_algorithm", "payload_hash", "payload", "signature"}
PASS_DIMENSIONS = {"DISCOVERY_EVIDENCE", "TRANSACTION_EVIDENCE", "EVIDENCE_INTEGRITY",
                   "VERIFIED_AGENTIC_COMMERCE"}
COMMITMENT_PROFILE = "dothat-channel-declaration/1"
TIMESTAMP_WINDOW = timedelta(minutes=5)
HASH = re.compile(r"^[a-f0-9]{64}$")
SALT = re.compile(r"^[a-f0-9]{32}$")
CHALLENGE = re.compile(r"^qst_[a-f0-9]{32}$")

# What the seller must have signed for each channel: protocol and transport at order and at payment.
# The four agent channels also need a shared payment token and a merchant-recorded identity: current
# domain-control KYA, or for UCP alternatively a platform the seller approved and verified by its signature.
DOMAIN_KYA = "merchant-verified-domain-control"
APPROVED_PLATFORM = "merchant-approved-platform"
RULES = {
    "mcp": {"protocols": {"bd-commerce/1"}, "entry_transport": "mcp", "payment_transport": "mcp", "agent": True,
            "identity": {DOMAIN_KYA}},
    "http-api": {"protocols": {"bd-commerce/1"}, "entry_transport": "http", "payment_transport": "http", "agent": True,
                 "identity": {DOMAIN_KYA}},
    "acp": {"protocols": {"acp/2026-04-17"}, "entry_transport": "http", "payment_transport": "http", "agent": True,
            "identity": {DOMAIN_KYA}},
    "ucp": {"protocols": {"ucp/2026-08-25", "ucp/2026-04-08"}, "entry_transport": "http", "payment_transport": "http",
            "agent": True, "identity": {DOMAIN_KYA, APPROVED_PLATFORM}},
    "a2a": {"protocols": {"website"}, "entry_transport": "a2a", "payment_transport": "web", "agent": False,
            "identity": set()},
    "browser": {"protocols": {"website"}, "entry_transport": "web", "payment_transport": "web", "agent": False,
                "identity": set()},
}


def declaration_commitment(challenge_id: str, channel: str, declared_at: str, salt: str) -> str:
    """The value published while the run is open; it reveals nothing until the salt is published."""
    preimage = "\n".join((COMMITMENT_PROFILE, challenge_id, channel, declared_at, salt))
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


def classify(detail: dict) -> str | None:
    """The channel the signed facts describe, ignoring payment authority and KYA."""
    for channel, rule in RULES.items():
        if (detail["entry_protocol"] == detail["payment_protocol"] and detail["entry_protocol"] in rule["protocols"]
                and detail["entry_transport"] == rule["entry_transport"]
                and detail["payment_transport"] == rule["payment_transport"]):
            return channel
    return None


def _result(status: str, reason: str, declared: str | None = None, recorded: str | None = None,
            detail: dict | None = None) -> dict:
    facts = None
    if isinstance(detail, dict):
        facts = {key: detail.get(key) for key in ("entry_protocol", "entry_transport", "payment_protocol",
                                                   "payment_transport", "payment_instrument")}
        facts["kya_level"] = detail.get("kya", {}).get("level") if isinstance(detail.get("kya"), dict) else None
    return {"status": status, "reason": reason, "declared_channel": declared, "recorded_channel": recorded,
            "recorded": facts}


def _check_declaration(declaration: dict, challenge_id: str) -> str | None:
    if not isinstance(declaration, dict) or set(declaration) != DECLARATION_FIELDS:
        return "Channel declaration has unexpected fields"
    if declaration["channel"] not in CHANNELS:
        return "Unknown declared channel"
    if (declaration["challenge_id"] != challenge_id or not isinstance(declaration["salt"], str)
            or not SALT.fullmatch(declaration["salt"]) or not isinstance(declaration["commitment"], str)
            or not HASH.fullmatch(declaration["commitment"])):
        return "Channel declaration is malformed"
    parse_timestamp(declaration["declared_at"])
    if declaration_commitment(challenge_id, declaration["channel"], declaration["declared_at"],
                              declaration["salt"]) != declaration["commitment"]:
        return "Channel declaration does not match its published commitment"
    return None


def _check_base(proof: dict, registry: dict, clock: datetime) -> str | None:
    """The same base gates as route-v1: a complete, signed, linked original-quest PASS."""
    if validate_schema(proof, "proof"):
        return "Public PASS package has an invalid schema"
    record, provider, review = proof["verification_record"], proof["provider_artifact"], proof["review_artifact"]
    if any(validate_schema(value, kind) for value, kind in ((record, "verification"), (provider, "provider"),
                                                             (review, "review"))):
        return "Public PASS package contains invalid evidence"
    if record["status"] != "PASS" or set(record["result_summary"]) != PASS_DIMENSIONS or any(
            value != "PASS" for value in record["result_summary"].values()):
        return "The base purchase is not a complete PASS"
    if record["hash"] != hash_object_without_hash(record):
        return "Verification record hash mismatch"
    if record["protocol_version"] != PROTOCOL_VERSION or record["protocol_hash"] != protocol_hash():
        return "The PASS record is not for the published original quest"
    if registry_hash(registry) != record["registry_hash"]:
        return "Trusted registry does not match the PASS record"
    public_keys = proof["trusted_key_registry"]["keys"]
    if len(public_keys) != len(registry) or {entry["key_id"]: entry for entry in public_keys} != registry:
        return "Public and separately trusted registries differ"
    for artifact, kind, commitment in ((provider, "provider-transaction", "provider_envelope_hash"),
                                       (review, "discovery-review", "review_envelope_hash")):
        valid, _ = verify_artifact(artifact, kind, registry, now=clock)
        if not valid or record[commitment] != sha256_hex(artifact):
            return "Signed PASS artifact or commitment is invalid"
    if not (proof["challenge_id"] == record["challenge_id"] == provider["challenge_id"]
            == review["challenge_id"] == provider["payload"]["challenge_id"]):
        return "PASS artifacts have different challenges"
    pp, rp = provider["payload"], review["payload"]
    if (pp["challenge_context_hash"] != record["challenge_context_hash"]
            or rp["challenge_context_hash"] != record["challenge_context_hash"]
            or rp["provider_payload_hash"] != provider["payload_hash"]
            or rp["review_result"] != "PASS" or rp["protocol_hash"] != record["protocol_hash"]
            or rp["exact_prompt_hash"] != record["prompt_hash"]):
        return "PASS artifact linkage is invalid"
    if (rp["participant_evidence_hash"] != record["participant_evidence_hash"]
            or rp["agent_evidence_hash"] != record["agent_evidence_hash"]
            or rp["trace_hash"] != record["trace_hash"]
            or any(rp[name] is not True for name in ("prompt_integrity", "merchant_not_pre_supplied",
                                                          "destination_not_pre_supplied", "usable_chronological_trace",
                                                          "independent_reach"))
            or pp["service"] != "101Ts3t" or pp["currency"] != "EUR"
            or type(pp["amount_minor"]) is not int or not 1 <= pp["amount_minor"] <= 100
            or pp["payment_status"] != "PAID" or pp["fulfillment_status"] != "COMPLETED"):
        return "Signed discovery or payment does not satisfy the base test"
    return None


def verify_channel(proof: dict, channel_artifact: dict | None, declaration: dict | None,
                   registry_path: str | Path | None = None, *, trusted_registry: dict | None = None,
                   declaration_timestamp: datetime | None = None, now: datetime | None = None) -> dict:
    """Require exactly one trusted registry source, as route-v1 does.

    `declaration_timestamp` is the genTime of the RFC 3161 token over the declaration
    commitment, already verified by the caller against the authority's certificate chain.
    """
    if declaration is None:
        return _result("NOT_VERIFIED", "No channel was declared when the challenge was issued")
    try:
        challenge_id = proof.get("challenge_id") if isinstance(proof, dict) else None
        if not isinstance(challenge_id, str) or not CHALLENGE.fullmatch(challenge_id):
            return _result("FAIL", "Public PASS package has an invalid challenge")
        problem = _check_declaration(declaration, challenge_id)
        if problem:
            return _result("FAIL", problem)
        declared = declaration["channel"]
        if channel_artifact is None:
            return _result("NOT_VERIFIED", "Signed channel artifact is missing", declared)
        if (registry_path is None) == (trusted_registry is None):
            return _result("FAIL", "Exactly one trusted registry source is required", declared)
        registry = load_registry(registry_path) if registry_path is not None else trusted_registry
        clock = now or datetime.now(timezone.utc)
        if clock.tzinfo is None or clock.utcoffset() is None:
            return _result("FAIL", "Verification clock has no timezone", declared)
        problem = _check_base(proof, registry, clock)
        if problem:
            return _result("FAIL", problem, declared)
        if proof["verification_record"]["prompt_hash"] not in {
                prompt_hash(challenge_id, PROMPT_VERSION), prompt_hash(challenge_id, channel_prompt_version(declared))}:
            return _result("FAIL", "The agent was given the prompt of a different channel", declared)
        provider = proof["provider_artifact"]
        pp = provider["payload"]
        if not isinstance(channel_artifact, dict) or set(channel_artifact) != ENVELOPE_FIELDS:
            return _result("FAIL", "Channel artifact envelope has unexpected fields", declared)
        if channel_artifact["signing_key_id"] != provider["signing_key_id"]:
            return _result("FAIL", "Channel and payment were not attested by the same provider key", declared)
        valid, _ = verify_artifact(channel_artifact, "provider-transaction", registry, now=clock)
        if not valid:
            return _result("FAIL", "Channel signature or provider key is invalid", declared)
        payload = channel_artifact["payload"]
        if not isinstance(payload, dict) or set(payload) != set(pp) | {"channel_evidence"} or any(
                payload[key] != value for key, value in pp.items()):
            return _result("FAIL", "Channel artifact does not describe the same paid transaction", declared)
        detail = payload["channel_evidence"]
        if not isinstance(detail, dict) or set(detail) != CHANNEL_FIELDS or detail["profile"] != "bd-commerce-channel/1":
            return _result("FAIL", "Channel evidence has an invalid profile", declared)
        if detail["provider_envelope_hash"] != sha256_hex(provider):
            return _result("FAIL", "Channel evidence is not bound to the original payment artifact", declared)
        if (detail["entry_protocol"] not in PROTOCOLS or detail["payment_protocol"] not in PROTOCOLS
                or detail["entry_transport"] not in TRANSPORTS or detail["payment_transport"] not in TRANSPORTS):
            return _result("FAIL", "Unknown protocol or transport", declared)
        if detail["payment_instrument"] not in {"shared-payment-token", "hosted-checkout"}:
            return _result("FAIL", "Unknown payment instrument", declared)
        started = parse_timestamp(detail["payment_started_at"])
        if not (started <= parse_timestamp(pp["server_timestamp"]) <= parse_timestamp(provider["issued_at"])
                <= parse_timestamp(channel_artifact["issued_at"])):
            return _result("FAIL", "Payment and signature chronology is inconsistent", declared)
        kya = detail["kya"]
        if not isinstance(kya, dict):
            return _result("FAIL", "KYA evidence is malformed", declared)
        if kya.get("level") == DOMAIN_KYA:
            if (set(kya) != {"level", "domain_sha256", "verified_at"}
                    or not isinstance(kya["domain_sha256"], str) or not HASH.fullmatch(kya["domain_sha256"])):
                return _result("FAIL", "KYA domain commitment is malformed", declared)
            verified = parse_timestamp(kya["verified_at"])
            if not verified <= started <= verified + timedelta(hours=24):
                return _result("FAIL", "KYA verification was not current at payment start", declared)
        elif kya.get("level") == APPROVED_PLATFORM:
            if (set(kya) != {"level", "profile_sha256"} or not isinstance(kya["profile_sha256"], str)
                    or not HASH.fullmatch(kya["profile_sha256"])):
                return _result("FAIL", "Approved platform commitment is malformed", declared)
        elif kya != {"level": "not-recorded"}:
            return _result("FAIL", "Unknown KYA level", declared)
        recorded = classify(detail)
        declared_at = parse_timestamp(declaration["declared_at"])
        if declared_at > started:
            return _result("NOT_VERIFIED", "The channel was declared after payment started", declared, recorded, detail)
        if declaration_timestamp is None:
            return _result("NOT_VERIFIED", "The declaration has no verified independent timestamp", declared, recorded,
                           detail)
        if declaration_timestamp.tzinfo is None or declaration_timestamp.utcoffset() is None:
            return _result("FAIL", "Declaration timestamp has no timezone", declared, recorded, detail)
        if not (declared_at - TIMESTAMP_WINDOW <= declaration_timestamp <= declared_at + TIMESTAMP_WINDOW
                and declaration_timestamp <= started):
            return _result("NOT_VERIFIED", "The independent timestamp is not from issuance, before payment", declared,
                           recorded, detail)
        if recorded != declared:
            return _result("NOT_VERIFIED", "The seller signed a different channel from the one declared", declared,
                           recorded, detail)
        if RULES[declared]["agent"] and (detail["payment_instrument"] != "shared-payment-token"
                                         or kya["level"] not in RULES[declared]["identity"]):
            return _result("NOT_VERIFIED", "Autonomous payment and current KYA were not both attested", declared,
                           recorded, detail)
        if not RULES[declared]["agent"] and detail["payment_instrument"] != "hosted-checkout":
            return _result("NOT_VERIFIED", "The payment did not use the checkout page", declared, recorded, detail)
        return _result("PASS", "The seller signed the declared channel at order and payment for the same paid purchase",
                       declared, recorded, detail)
    except (InputError, KeyError, OSError, TypeError, ValueError, OverflowError, AttributeError):
        return _result("FAIL", "Malformed or inconsistent channel evidence")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--channel", type=Path, required=True)
    parser.add_argument("--declaration", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--declaration-timestamp", help="Verified RFC 3161 genTime (RFC 3339)")
    args = parser.parse_args()
    import json
    try:
        stamp = parse_timestamp(args.declaration_timestamp) if args.declaration_timestamp else None
        result = verify_channel(strict_json_loads(args.proof.read_bytes()), strict_json_loads(args.channel.read_bytes()),
                                strict_json_loads(args.declaration.read_bytes()), args.registry,
                                declaration_timestamp=stamp)
    except (OSError, ValueError):
        result = _result("FAIL", "Input files could not be read")
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
