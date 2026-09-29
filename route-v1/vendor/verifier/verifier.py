from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .hashing import hash_object_without_hash, sha256_hex
from .signing import load_registry, registry_hash, verify_artifact
from .validation import InputError, parse_timestamp, strict_json_loads, validate_json_value

ROOT = Path(__file__).resolve().parent.parent
PROTOCOL_VERSION = "v1.0-draft"
PROMPT_VERSION = "v1.0-draft"
VERIFIER_VERSION = "0.2.2"
POLICY_VERSION = "signed-evidence-v2"
CHALLENGE_SERVICE = "101Ts3t"
MAX_TOTAL_PRICE_MINOR = 100
CLOCK_SKEW_SECONDS = 60
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
PROMPT_PATH = ROOT / "prompts" / "official-agent-prompt-v1.0-draft.md"
PROTOCOL_PATH = ROOT / "protocol" / "dothat-quest-evidence-protocol-v1.0-draft.md"
SCHEMA_PATHS = {name: ROOT / "schemas" / f"{stem}-v2.schema.json" for name, stem in {
    "challenge": "challenge-session", "context": "challenge-context", "participant": "participant-evidence",
    "agent": "agent-evidence", "review": "review-evidence", "provider": "provider-evidence",
    "verification": "verification-record", "result": "verification-result"}.items()}
SCHEMA_PATHS["guided"] = ROOT / "schemas" / "guided-submission-v1.schema.json"
SCHEMA_PATHS["proof"] = ROOT / "schemas" / "public-proof-package-v1.schema.json"
SCHEMA_PATHS["registry"] = ROOT / "schemas" / "trusted-key-registry-v2.schema.json"
CONTEXT_FIELDS = ("challenge_id", "created_at", "protocol_version", "protocol_hash", "prompt_version", "exact_prompt", "prompt_hash", "service", "max_budget")
DIMENSIONS = ("DISCOVERY_EVIDENCE", "TRANSACTION_EVIDENCE", "EVIDENCE_INTEGRITY", "VERIFIED_AGENTIC_COMMERCE")
FORMATS = FormatChecker()


@FORMATS.checks("date-time", raises=InputError)
def _protocol_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return True  # JSON Schema type validation handles non-string values.
    parse_timestamp(value)
    return True


def _read_json(path: Path) -> Any:
    return strict_json_loads(path.read_bytes())


def render_prompt(challenge_id: str) -> bytes:
    return PROMPT_PATH.read_text(encoding="utf-8").replace("{{challenge_id}}", challenge_id).encode("utf-8")


def prompt_hash(challenge_id: str) -> str:
    return sha256_hex(render_prompt(challenge_id))


def protocol_hash() -> str:
    return sha256_hex(PROTOCOL_PATH.read_bytes())


def validate_schema(document: Any, schema_name: str) -> list[str]:
    validator = Draft202012Validator(_read_json(SCHEMA_PATHS[schema_name]), format_checker=FORMATS)
    return [f"{'/'.join(map(str, error.absolute_path))}: {error.message}" for error in validator.iter_errors(document)][:20]


def _response(summary: dict[str, str], errors: list[str], record: dict | None = None) -> dict:
    return {"status": summary["VERIFIED_AGENTIC_COMMERCE"], "result_summary": summary, "record": record, "errors": errors}


def invalid_result(reason: str) -> dict:
    summary = dict.fromkeys(DIMENSIONS, "NOT_VERIFIED")
    summary.update(EVIDENCE_INTEGRITY="FAIL", VERIFIED_AGENTIC_COMMERCE="FAIL")
    return _response(summary, [reason])


def _same_reference(*values: Any) -> bool:
    return bool(values) and all(isinstance(value, str) and value.strip() for value in values) and len(set(values)) == 1


def _integrity_failures(document: dict, context: dict, trace: bytes, now: datetime, trusted_previous: dict | None) -> list[str]:
    errors = []
    participant, agent, transaction = (document[name] for name in ("participant_evidence", "agent_evidence", "transaction_evidence"))
    for key in CONTEXT_FIELDS:
        if document[key] != context[key]:
            errors.append(f"challenge_context.{key}")
    if participant["participant_id"] != context["participant_id"]:
        errors.append("challenge_context.participant_id")
    if document["protocol_hash"] != protocol_hash():
        errors.append("protocol_hash")
    expected_prompt = render_prompt(document["challenge_id"])
    if document["exact_prompt"].encode("utf-8") != expected_prompt or participant["exact_prompt"] != document["exact_prompt"]:
        errors.append("exact_prompt")
    if document["prompt_hash"] != sha256_hex(expected_prompt):
        errors.append("prompt_hash")
    for name, evidence in (("participant", participant), ("agent", agent), ("transaction", transaction)):
        if evidence["challenge_id"] != document["challenge_id"] or evidence["service"] != document["service"]:
            errors.append(f"{name}.linkage")
        if hash_object_without_hash(evidence) != evidence["hash"]:
            errors.append(f"{name}.hash")
    if participant["trace_export_share_reference"] != agent["trace_export_share_reference"]:
        errors.append("trace.reference_linkage")
    for name, evidence in (("participant", participant), ("agent", agent)):
        if evidence["trace_hash"] != sha256_hex(trace):
            errors.append(f"{name}.trace_hash")
    if not _same_reference(participant["transaction_order_reference"], agent["transaction_order_reference"], transaction["transaction_order_reference"]):
        errors.append("transaction.references")
    refs = [e["transaction_order_reference"] for e in agent["sequence"] if e["transaction_order_reference"] is not None]
    if not refs or any(not _same_reference(ref, transaction["transaction_order_reference"]) for ref in refs):
        errors.append("agent.transaction_references")
    if transaction["amount_minor"] > document["max_budget"]["amount_minor"] or transaction["currency"] != document["max_budget"]["currency"]:
        errors.append("transaction.budget")
    if transaction["status"] == "PASS" and transaction["amount_minor"] < 1:
        errors.append("transaction.amount")
    created = parse_timestamp(context["created_at"])
    latest = now + timedelta(seconds=CLOCK_SKEW_SECONDS)
    if not created <= parse_timestamp(participant["submitted_at"]) <= latest:
        errors.append("participant.submitted_at")
    prior_sequence, prior_time = 0, created
    for event in agent["sequence"]:
        event_time = parse_timestamp(event["timestamp"])
        if event["sequence"] <= prior_sequence or not prior_time <= event_time <= latest:
            errors.append("agent.chronology")
        prior_sequence, prior_time = event["sequence"], event_time
    previous, previous_hash = document.get("previous_record"), document.get("previous_record_hash")
    if previous is not None or previous_hash is not None or trusted_previous is not None:
        if trusted_previous is None:
            errors.append("previous_record.untrusted")
        else:
            validate_json_value(trusted_previous)
            if validate_schema(trusted_previous, "verification"):
                errors.append("previous_record.schema")
            elif (previous != trusted_previous or previous_hash != trusted_previous["hash"]
                  or hash_object_without_hash(trusted_previous) != trusted_previous["hash"]
                  or trusted_previous["challenge_id"] != context["challenge_id"]
                  or trusted_previous["challenge_context_hash"] != sha256_hex(context)
                  or parse_timestamp(trusted_previous["verified_at"]) > now):
                errors.append("previous_record.linkage")
    return errors


def _checked_artifact(artifact: Any, kind: str, registry: dict, now: datetime, errors: list[str]) -> dict | None:
    if artifact is None:
        errors.append(f"{kind}.missing")
        return None
    if validate_schema(artifact, "review" if kind == "discovery-review" else "provider"):
        errors.append(f"{kind}.schema")
        return None
    if kind == "provider-transaction" and type(artifact["payload"]["amount_minor"]) is not int:
        errors.append("provider-transaction.amount_minor_type")
        return None
    valid, reason = verify_artifact(artifact, kind, registry, now=now, clock_skew_seconds=CLOCK_SKEW_SECONDS)
    if not valid:
        errors.append(f"{kind}.{reason}")
        return None
    return artifact


def _signed_linkage(document: dict, context: dict, review: dict | None, provider: dict | None, errors: list[str]) -> tuple[dict | None, dict | None]:
    transaction = document["transaction_evidence"]
    if provider is not None:
        payload = provider["payload"]
        fields = ("challenge_id", "service", "transaction_order_reference", "amount_minor", "currency", "payment_status", "fulfillment_status")
        if (provider["challenge_id"] != context["challenge_id"] or payload["challenge_context_hash"] != sha256_hex(context)
            or any(payload[key] != transaction[key] for key in fields) or provider["payload_hash"] != transaction["provider_evidence_hash"]
            or not _same_reference(transaction["provider_server_evidence_reference"], payload["provider_event_reference"])):
            errors.append("provider-transaction.linkage")
            provider = None
    if review is not None:
        payload = review["payload"]
        expected = {"challenge_id": context["challenge_id"], "challenge_context_hash": sha256_hex(context),
                    "exact_prompt_hash": context["prompt_hash"], "protocol_hash": context["protocol_hash"],
                    "trace_hash": document["agent_evidence"]["trace_hash"],
                    "participant_evidence_hash": document["participant_evidence"]["hash"],
                    "agent_evidence_hash": document["agent_evidence"]["hash"],
                    "provider_payload_hash": transaction["provider_evidence_hash"]}
        if review["challenge_id"] != context["challenge_id"] or any(payload[key] != value for key, value in expected.items()):
            errors.append("discovery-review.linkage")
            review = None
    return review, provider


def _artifact_chronology(document: dict, review: dict | None, provider: dict | None) -> list[str]:
    errors = []
    last_event = max(parse_timestamp(e["timestamp"]) for e in document["agent_evidence"]["sequence"])
    created = parse_timestamp(document["created_at"])
    if provider is not None and not created <= parse_timestamp(provider["payload"]["server_timestamp"]) <= parse_timestamp(provider["issued_at"]):
        errors.append("provider-transaction.chronology")
    if review is not None:
        reviewed = parse_timestamp(review["payload"]["reviewed_at"])
        if not last_event <= reviewed <= parse_timestamp(review["issued_at"]):
            errors.append("discovery-review.chronology")
        if provider is not None and parse_timestamp(provider["issued_at"]) > reviewed:
            errors.append("review_provider.chronology")
    return errors


def _record(document: dict, context: dict, registry: dict, summary: dict, review: dict | None, provider: dict | None, now: datetime) -> dict:
    record = {"schema_version": "v2", "challenge_id": context["challenge_id"], "challenge_context_hash": sha256_hex(context),
        "protocol_version": PROTOCOL_VERSION, "protocol_hash": protocol_hash(), "prompt_hash": context["prompt_hash"],
        "participant_evidence_hash": document["participant_evidence"]["hash"], "agent_evidence_hash": document["agent_evidence"]["hash"],
        "trace_hash": document["agent_evidence"]["trace_hash"], "transaction_evidence_hash": document["transaction_evidence"]["hash"],
        "review_envelope_hash": sha256_hex(review) if review is not None else None,
        "provider_envelope_hash": sha256_hex(provider) if provider is not None else None,
        "registry_hash": registry_hash(registry), "verifier_version": VERIFIER_VERSION, "policy_version": POLICY_VERSION,
        "verified_at": now.isoformat().replace("+00:00", "Z"), "previous_record_hash": document.get("previous_record_hash"),
        "status": summary["VERIFIED_AGENTIC_COMMERCE"], "result_summary": summary}
    record["hash"] = hash_object_without_hash(record)
    return record


def verify_document(document: dict[str, Any], trace_bytes: bytes | None = None, provider_bytes: bytes | None = None,
                    trusted_key_registry: str | Path | None = None, *, trusted_challenge: dict | None = None,
                    now: datetime | None = None, trusted_previous_record: dict | None = None) -> dict[str, Any]:
    """Authority inputs come from caller-controlled config/storage, never the evidence body.

    Client-selected filesystem references are never opened. The caller supplies bytes.
    """
    summary = dict.fromkeys(DIMENSIONS, "NOT_VERIFIED")
    try:
        validate_json_value(document)
        schema_errors = validate_schema(document, "challenge")
        if schema_errors:
            return invalid_result("challenge.schema: " + "; ".join(schema_errors))
        if trusted_challenge is None:
            return _response(summary, ["trusted_challenge.missing"])
        validate_json_value(trusted_challenge)
        if validate_schema(trusted_challenge, "context"):
            return invalid_result("trusted_challenge.schema")
        # JSON Schema's integer type also accepts 99.0; wire money must be actual
        # integer minor units, never a boolean, floating value, or decimal alias.
        money_values = [trusted_challenge["max_budget"]["amount_minor"], document["max_budget"]["amount_minor"],
                        document["transaction_evidence"]["amount_minor"]]
        money_values.extend(event["observed_price_minor"] for event in document["agent_evidence"]["sequence"]
                            if event["observed_price_minor"] is not None)
        if any(type(value) is not int for value in money_values):
            return invalid_result("money.minor_units_integer_required")
        clock = now if now is not None else datetime.now(timezone.utc)
        if not isinstance(clock, datetime) or clock.tzinfo is None or clock.utcoffset() is None:
            return invalid_result("verification_time.invalid")
        clock = clock.astimezone(timezone.utc)
        if trace_bytes is None:
            return _response(summary, ["trace.bytes_missing"])
        if not isinstance(trace_bytes, bytes) or not 0 < len(trace_bytes) <= MAX_ARTIFACT_BYTES:
            return invalid_result("trace.invalid_size_or_type")
        if provider_bytes is not None and (not isinstance(provider_bytes, bytes) or not 0 < len(provider_bytes) <= MAX_ARTIFACT_BYTES):
            return invalid_result("provider.invalid_size_or_type")
        registry = load_registry(trusted_key_registry)
        errors = _integrity_failures(document, trusted_challenge, trace_bytes, clock, trusted_previous_record)
        artifact_errors = []
        review = _checked_artifact(document.get("review_evidence"), "discovery-review", registry, clock, artifact_errors)
        provider_data = strict_json_loads(provider_bytes) if provider_bytes is not None else None
        if provider_bytes is not None and provider_data is None:
            # Explicit JSON null is an invalid supplied artifact, not absence.
            artifact_errors.append("provider-transaction.schema")
            provider = None
        else:
            provider = _checked_artifact(provider_data, "provider-transaction", registry, clock, artifact_errors)
        review, provider = _signed_linkage(document, trusted_challenge, review, provider, artifact_errors)
        errors.extend(_artifact_chronology(document, review, provider))
        # Absence is incomplete evidence; supplied artifacts that fail trust,
        # authenticity or linkage checks are integrity failures.
        invalid_artifact_errors = [error for error in artifact_errors if not error.endswith(".missing")]
        summary["EVIDENCE_INTEGRITY"] = ("FAIL" if errors or invalid_artifact_errors else
                                         "NOT_VERIFIED" if artifact_errors else "PASS")
        if not errors and not invalid_artifact_errors:
            if review is not None:
                payload = review["payload"]
                predicates = ("prompt_integrity", "merchant_not_pre_supplied", "destination_not_pre_supplied", "usable_chronological_trace", "independent_reach")
                if payload["review_result"] == "FAIL" or any(payload[key] is False for key in predicates):
                    summary["DISCOVERY_EVIDENCE"] = "FAIL"
                elif payload["review_result"] == "PASS" and all(payload[key] is True for key in predicates):
                    summary["DISCOVERY_EVIDENCE"] = "PASS"
            if provider is not None:
                payload = provider["payload"]
                if payload["payment_status"] == "DECLINED" or payload["fulfillment_status"] == "NOT_COMPLETED":
                    summary["TRANSACTION_EVIDENCE"] = "FAIL"
                elif payload["payment_status"] == "PAID" and payload["fulfillment_status"] == "COMPLETED" and document["transaction_evidence"]["status"] == "PASS":
                    summary["TRANSACTION_EVIDENCE"] = "PASS"
        gates = [summary[key] for key in DIMENSIONS[:3]]
        summary["VERIFIED_AGENTIC_COMMERCE"] = "FAIL" if "FAIL" in gates else "PASS" if all(value == "PASS" for value in gates) else "NOT_VERIFIED"
        result = _response(summary, errors + artifact_errors, _record(document, trusted_challenge, registry, summary, review, provider, clock))
        return invalid_result("verification_result.schema") if validate_schema(result, "result") else result
    except (InputError, ValueError, TypeError, UnicodeError, OSError, RecursionError, OverflowError) as error:
        return invalid_result(f"input_or_configuration.{type(error).__name__}: {str(error)[:240]}")


def verify_examples(base_dir: Path | str | None = None) -> dict[str, dict[str, Any]]:
    root = Path(base_dir) if base_dir is not None else ROOT
    names = ("verified-pass.json", "discovery-not-verified.json", "failed-payment.json", "tampered-evidence.json")
    return {name: verify_document(_read_json(root / "examples" / name)) for name in names}
