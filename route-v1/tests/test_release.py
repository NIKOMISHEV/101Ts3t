"""SYNTHETIC TESTS ONLY: ephemeral keys and invented transactions, never purchase evidence."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import verify_release as replay
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from verifier import signing
from verifier.hashing import hash_object_without_hash, sha256_hex
from verifier.signing import registry_hash, sign_artifact
from verifier.verifier import prompt_hash, protocol_hash

NOW = datetime(2026, 9, 29, 12, 4, tzinfo=timezone.utc)
COMMITTED = "2026-09-29T12:00:00Z"
CID = "qst_" + "a" * 32
HISTORICAL = "qst_44e153fc16fe3fa91520e5f6922ae4c9"
HISTORICAL_SHA = "c032d43de422161baaf10857a03e9870112f3aa5cae8cd73ed026462c165a16a"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def make_case(protocol="ucp/2026-08-25"):
    provider_key, reviewer_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    keys = {}
    for name, purpose, key in (("synthetic-provider", "provider-transaction", provider_key),
                               ("synthetic-reviewer", "discovery-review", reviewer_key)):
        keys[name] = {"key_id": name, "purpose": purpose, "status": "active",
                      "active_at": "2026-01-01T00:00:00Z",
                      "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode()}
    pp = {"challenge_id": CID, "challenge_context_hash": "1" * 64,
          "service": "101Ts3t", "transaction_order_reference": "bd_" + "b" * 32,
          "amount_minor": 99, "currency": "EUR", "payment_status": "PAID",
          "fulfillment_status": "COMPLETED", "provider_event_reference": "evt_" + "c" * 32,
          "server_timestamp": "2026-09-29T12:02:00Z"}
    rp = {"challenge_id": CID, "challenge_context_hash": "1" * 64,
          "exact_prompt_hash": prompt_hash(CID), "trace_hash": "2" * 64,
          "protocol_hash": protocol_hash(), "reviewer_verifier_version": "synthetic-only-v1",
          "reviewed_at": "2026-09-29T12:03:00Z", "review_result": "PASS",
          "participant_evidence_hash": "3" * 64, "agent_evidence_hash": "4" * 64,
          **{k: True for k in ("prompt_integrity", "merchant_not_pre_supplied", "destination_not_pre_supplied",
                               "usable_chronological_trace", "independent_reach")}}
    record = {"schema_version": "v2", "challenge_id": CID, "protocol_version": "v1.0-draft",
              "verifier_version": "0.2.2", "policy_version": "signed-evidence-v2",
              "verified_at": "2026-09-29T12:03:30Z", "status": "PASS",
              "result_summary": dict.fromkeys(replay.PASS_DIMENSIONS, "PASS"),
              "challenge_context_hash": "1" * 64, "protocol_hash": protocol_hash(),
              "prompt_hash": prompt_hash(CID), "participant_evidence_hash": "3" * 64,
              "agent_evidence_hash": "4" * 64, "trace_hash": "2" * 64,
              "transaction_evidence_hash": "5" * 64, "previous_record_hash": None}
    case = {"provider_key": provider_key, "reviewer_key": reviewer_key, "registry": keys,
            "pp": pp, "rp": rp, "record": record,
            "provider_time": "2026-09-29T12:02:00Z", "review_time": "2026-09-29T12:03:00Z",
            "route_time": "2026-09-29T12:03:20Z",
            "detail": {"profile": "bd-commerce-route/1", "entry_protocol": protocol,
                       "payment_protocol": protocol, "payment_instrument": "shared-payment-token",
                       "payment_started_at": "2026-09-29T12:01:00Z",
                       "kya": {"level": "merchant-verified-domain-control", "domain_sha256": "6" * 64,
                               "verified_at": "2026-09-29T11:59:00Z"}}}
    refresh(case)
    return case


def refresh(c):
    p = sign_artifact("provider-transaction", "v2", c["pp"]["challenge_id"], c["provider_time"],
                      "synthetic-provider", c["pp"], c["provider_key"])
    c["rp"]["provider_payload_hash"] = p["payload_hash"]
    r = sign_artifact("discovery-review", "v2", c["rp"]["challenge_id"], c["review_time"],
                      "synthetic-reviewer", c["rp"], c["reviewer_key"])
    v = c["record"]
    v.update(provider_envelope_hash=sha256_hex(p), review_envelope_hash=sha256_hex(r),
             registry_hash=registry_hash(c["registry"]))
    v["hash"] = hash_object_without_hash(v)
    c["proof"] = {"package_version": "v1", "challenge_id": CID, "verification_record": copy.deepcopy(v),
                  "provider_artifact": p, "review_artifact": r,
                  "trusted_key_registry": {"registry_version": "v2", "keys": list(c["registry"].values())}}
    c["detail"]["provider_envelope_hash"] = sha256_hex(p)
    c["route"] = sign_artifact("provider-transaction", "v2", c["pp"]["challenge_id"], c["route_time"],
                 "synthetic-provider", {**c["pp"], "route_evidence": c["detail"]}, c["provider_key"])


def run_case(c, **overrides):
    args = dict(challenge_id=CID, expected_protocol=c["detail"]["entry_protocol"], not_before=COMMITTED,
                spec_sha256="7" * 64, trusted_registry=c["registry"], now=NOW)
    args.update(overrides)
    return replay.verify_inputs(encoded(c["proof"]), encoded(c["route"]), **args)


def corrupt_signature(artifact):
    signature = bytearray(base64.b64decode(artifact["signature"]))
    signature[0] ^= 1
    artifact["signature"] = base64.b64encode(signature).decode()


class ReleaseTests(unittest.TestCase):
    def rejected(self, c, **overrides):
        with self.assertRaises((replay.VerificationFailure, ValueError, TypeError, KeyError)):
            run_case(c, **overrides)

    def test_all_four_supported_protocols_have_complete_signed_baselines(self):
        for protocol in replay.ALLOWED_PROTOCOLS:
            with self.subTest(protocol=protocol):
                c = make_case(protocol)
                original = encoded(c["proof"])
                result = run_case(c)
                self.assertEqual((result["status"], result["qualified_protocol"]), ("PASS", protocol))
                self.assertEqual(encoded(c["proof"]), original)

    def test_requested_id_and_expected_protocol_are_external_constraints(self):
        c = make_case()
        self.rejected(c, challenge_id="qst_" + "d" * 32)
        self.rejected(c, expected_protocol="acp/2026-04-17")
        self.rejected(c, expected_protocol="website")

    def test_unsigned_projection_cannot_relabel_signed_purchase(self):
        c = make_case(); changed = "qst_" + "d" * 32
        c["proof"]["challenge_id"] = changed
        r = c["proof"]["verification_record"]; r["challenge_id"] = changed
        r["hash"] = hash_object_without_hash(r)
        self.rejected(c, challenge_id=changed)

    def test_different_signed_route_challenge_order_payment_and_binding(self):
        for field in ("challenge_id", "transaction_order_reference", "provider_event_reference", "challenge_context_hash"):
            with self.subTest(field=field):
                c = make_case(); payload = copy.deepcopy(c["route"]["payload"])
                payload[field] = ("qst_" + "d" * 32 if field == "challenge_id" else
                                  "bd_" + "d" * 32 if field == "transaction_order_reference" else
                                  "evt_" + "d" * 32 if field == "provider_event_reference" else "d" * 64)
                c["route"] = sign_artifact("provider-transaction", "v2", payload["challenge_id"], c["route_time"],
                                          "synthetic-provider", payload, c["provider_key"])
                self.rejected(c)
        c = make_case(); c["detail"]["provider_envelope_hash"] = "0" * 64
        c["route"] = sign_artifact("provider-transaction", "v2", CID, c["route_time"], "synthetic-provider",
                                  {**c["pp"], "route_evidence": c["detail"]}, c["provider_key"])
        self.rejected(c)

    def test_all_base_gates_and_discovery_claims_are_required(self):
        for field in replay.PASS_DIMENSIONS:
            c = make_case(); c["record"]["result_summary"][field] = "NOT_VERIFIED"; refresh(c); self.rejected(c)
        for field in ("prompt_integrity", "merchant_not_pre_supplied", "destination_not_pre_supplied",
                      "usable_chronological_trace", "independent_reach"):
            c = make_case(); c["rp"][field] = False; refresh(c); self.rejected(c)

    def test_signed_route_cannot_coerce_payment_json_types(self):
        for amount, route_amount in ((1, True), (99, 99.0)):
            c = make_case(); c["pp"]["amount_minor"] = amount; refresh(c)
            self.assertEqual(run_case(c)["status"], "PASS")
            payload = copy.deepcopy(c["route"]["payload"]); payload["amount_minor"] = route_amount
            c["route"] = sign_artifact("provider-transaction", "v2", CID, c["route_time"],
                                      "synthetic-provider", payload, c["provider_key"])
            self.rejected(c)

    def test_invalid_signed_amount_currency_service_and_completion(self):
        for value in (0, 101, -1, True, "99", 99.5):
            c = make_case(); c["pp"]["amount_minor"] = value; refresh(c); self.rejected(c)
        for field, value in (("currency", "USD"), ("service", "other"), ("payment_status", "PENDING"),
                              ("fulfillment_status", "NOT_COMPLETED")):
            c = make_case(); c["pp"][field] = value; refresh(c); self.rejected(c)
        for value in (1, 100):
            c = make_case(); c["pp"]["amount_minor"] = value; refresh(c)
            self.assertEqual(run_case(c)["status"], "PASS")

    def test_record_hash_prompt_protocol_and_review_commitments(self):
        c = make_case(); c["proof"]["verification_record"]["hash"] = "0" * 64; self.rejected(c)
        for field in ("protocol_hash", "prompt_hash", "trace_hash", "participant_evidence_hash", "agent_evidence_hash"):
            c = make_case(); c["record"][field] = "0" * 64; refresh(c); self.rejected(c)
        # Even internally consistent signed prompt hashes must identify the unchanged official prompt.
        c = make_case(); c["record"]["prompt_hash"] = c["rp"]["exact_prompt_hash"] = "0" * 64
        refresh(c); self.rejected(c)

    def test_payment_start_must_follow_external_commitment_strictly(self):
        c = make_case()
        self.rejected(c, not_before="2026-09-29T12:01:00Z")
        self.rejected(c, not_before="2026-09-29T15:01:00+03:00")
        self.rejected(c, not_before="2026-09-29T12:01:01Z")
        self.rejected(c, not_before="2026-09-30T00:00:00Z")
        self.rejected(c, not_before="2026-09-29T12:00:00")

    def test_signed_chronology_and_future_signature(self):
        for field, value in (("provider_time", "2026-09-29T12:01:30Z"),
                             ("review_time", "2026-09-29T12:02:30Z"),
                             ("route_time", "2026-09-29T12:04:01Z")):
            c = make_case(); c[field] = value; refresh(c); self.rejected(c)
        c = make_case(); c["record"]["verified_at"] = "2026-09-29T12:02:50Z"; refresh(c); self.rejected(c)

    def test_kya_freshness_boundaries_and_domain_hash(self):
        c = make_case(); c["detail"]["kya"]["verified_at"] = "2026-09-28T12:01:00Z"; refresh(c)
        self.assertEqual(run_case(c)["status"], "PASS")
        for at in ("2026-09-28T12:00:59Z", "2026-09-29T12:01:01Z"):
            c = make_case(); c["detail"]["kya"]["verified_at"] = at; refresh(c); self.rejected(c)
        c = make_case(); c["detail"]["kya"]["domain_sha256"] = "example.com"; refresh(c); self.rejected(c)
        c = make_case(); c["detail"]["kya"] = {"level": "not-recorded"}; refresh(c); self.rejected(c)

    def test_website_hosted_and_mixed_routes_cannot_qualify(self):
        for field, value in (("entry_protocol", "website"), ("payment_protocol", "acp/2026-04-17"),
                              ("payment_instrument", "hosted-checkout")):
            c = make_case(); c["detail"][field] = value; refresh(c)
            self.rejected(c, expected_protocol="ucp/2026-08-25")

    def test_embedded_attacker_registry_cannot_grant_itself_trust(self):
        trusted = make_case(); attacker = make_case()
        self.rejected(attacker, trusted_registry=trusted["registry"])
        self.rejected(attacker, trusted_registry=replay.pinned_registry())
        c = make_case(); c["proof"]["trusted_key_registry"]["keys"].append(c["registry"]["synthetic-provider"])
        self.rejected(c)

    def test_revocation_and_key_lifecycle_are_enforced(self):
        for key in ("synthetic-provider", "synthetic-reviewer"):
            c = make_case(); c["registry"][key]["status"] = "revoked"; refresh(c); self.rejected(c)
            c = make_case(); c["registry"][key]["status"] = "retired"
            c["registry"][key]["retired_at"] = "2026-09-29T12:00:00Z"; refresh(c); self.rejected(c)
            c = make_case(); c["registry"][key]["active_at"] = "2026-09-30T00:00:00Z"; refresh(c); self.rejected(c)

    def test_signature_only_mutations_are_rejected(self):
        # Every mutation begins with a valid PASS and repairs unsigned commitments;
        # cryptographic signature validation must be the failing gate.
        for target in ("route", "provider_artifact", "review_artifact"):
            with self.subTest(target=target):
                c = make_case(); self.assertEqual(run_case(c)["status"], "PASS")
                artifact = c["route"] if target == "route" else c["proof"][target]
                corrupt_signature(artifact)
                if target != "route":
                    r = c["proof"]["verification_record"]
                    field = "provider_envelope_hash" if target == "provider_artifact" else "review_envelope_hash"
                    r[field] = sha256_hex(artifact); r["hash"] = hash_object_without_hash(r)
                    if target == "provider_artifact":
                        c["detail"]["provider_envelope_hash"] = sha256_hex(artifact)
                        c["route"] = sign_artifact("provider-transaction", "v2", CID, c["route_time"],
                            "synthetic-provider", {**c["pp"], "route_evidence": c["detail"]}, c["provider_key"])
                self.rejected(c)

    def test_malformed_json_size_and_private_fields_fail_closed(self):
        c = make_case()
        for target in ("proof", "route"):
            c = make_case(); c[target]["submission_token"] = "SYNTHETIC-PRIVATE-MARKER"; self.rejected(c)
        for target in ("pp", "rp"):
            c = make_case(); c[target]["trace_utf8"] = "SYNTHETIC-PRIVATE-MARKER"; refresh(c); self.rejected(c)
        with self.assertRaises(ValueError):
            replay.strict_json_loads(b'{"status":"PASS","status":"FAIL"}')
        with self.assertRaises(replay.VerificationFailure):
            replay.verify_inputs(b"x" * (replay.MAX_INPUT_BYTES + 1), b"{}", challenge_id=CID,
                expected_protocol="bd-commerce/1", not_before=COMMITTED, spec_sha256="7" * 64,
                trusted_registry=c["registry"], now=NOW)

    def test_deployed_vendor_and_separate_production_trust_are_pinned(self):
        replay.check_vendor()
        registry = replay.pinned_registry()
        self.assertEqual(registry_hash(registry), "c4c6f5c1bd4989f699645e5112d950148ac10ed50d53dd3862793ed4a8c131e4")

    def test_embedded_registry_rejects_private_fields_and_wrong_version(self):
        c = make_case(); c["proof"]["trusted_key_registry"]["private_note"] = "SYNTHETIC-MARKER"
        self.rejected(c)
        c = make_case(); c["proof"]["trusted_key_registry"]["registry_version"] = "other"
        self.rejected(c)

    def test_unsigned_record_metadata_is_explicitly_outside_signature_claim(self):
        c = make_case(); r = c["proof"]["verification_record"]
        r["transaction_evidence_hash"] = "0" * 64
        r["previous_record_hash"] = "9" * 64
        r["verified_at"] = "2026-09-29T12:03:45Z"
        r["hash"] = hash_object_without_hash(r)
        result = run_case(c)
        self.assertEqual(result["status"], "PASS")
        self.assertIn("unsigned projection fields", result["limitations"])
        self.assertIn("not independently authenticated", result["limitations"])

    def test_original_real_proof_stays_unchanged_and_is_not_new_route_evidence(self):
        path = ROOT.parent / "records" / HISTORICAL / "proof.json"
        before = path.read_bytes(); self.assertEqual(hashlib.sha256(before).hexdigest(), HISTORICAL_SHA)
        proof = replay.strict_json_loads(before)
        replay.validate_base(proof, HISTORICAL, replay.pinned_registry(), NOW)
        self.assertEqual(replay.verify_route(proof, None, trusted_registry=replay.pinned_registry(), now=NOW)["status"],
                         "NOT_VERIFIED")
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
