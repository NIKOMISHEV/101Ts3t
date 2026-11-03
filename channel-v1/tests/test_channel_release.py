"""SYNTHETIC TESTS ONLY: ephemeral keys and invented transactions, never purchase evidence."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import verify_channel_release as replay
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from verifier.channel import CHANNELS, RULES, declaration_commitment
from verifier.hashing import hash_object_without_hash, sha256_hex
from verifier.signing import registry_hash, sign_artifact
from verifier.verifier import prompt_hash, protocol_hash

NOW = datetime(2026, 11, 3, 12, 6, tzinfo=timezone.utc)
LAYER_FIXED = "2026-11-03T11:00:00Z"
DECLARED = "2026-11-03T11:58:00Z"
STAMPED = "2026-11-03T11:58:01Z"
CID = "qst_" + "a" * 32
SALT = "9" * 32


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def make_case(channel):
    provider_key, reviewer_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    keys = {}
    for name, purpose, key in (("synthetic-provider", "provider-transaction", provider_key),
                               ("synthetic-reviewer", "discovery-review", reviewer_key)):
        keys[name] = {"key_id": name, "purpose": purpose, "status": "active", "active_at": "2026-01-01T00:00:00Z",
                      "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode()}
    pp = {"challenge_id": CID, "challenge_context_hash": "1" * 64, "service": "101Ts3t",
          "transaction_order_reference": "bd_" + "b" * 32, "amount_minor": 99, "currency": "EUR",
          "payment_status": "PAID", "fulfillment_status": "COMPLETED", "provider_event_reference": "evt_" + "c" * 32,
          "server_timestamp": "2026-11-03T12:02:00Z"}
    rp = {"challenge_id": CID, "challenge_context_hash": "1" * 64, "exact_prompt_hash": prompt_hash(CID),
          "trace_hash": "2" * 64, "protocol_hash": protocol_hash(), "reviewer_verifier_version": "synthetic-only-v1",
          "reviewed_at": "2026-11-03T12:03:00Z", "review_result": "PASS", "participant_evidence_hash": "3" * 64,
          "agent_evidence_hash": "4" * 64,
          **{k: True for k in ("prompt_integrity", "merchant_not_pre_supplied", "destination_not_pre_supplied",
                               "usable_chronological_trace", "independent_reach")}}
    record = {"schema_version": "v2", "challenge_id": CID, "protocol_version": "v1.0-draft", "verifier_version": "0.2.2",
              "policy_version": "signed-evidence-v2", "verified_at": "2026-11-03T12:03:30Z", "status": "PASS",
              "result_summary": dict.fromkeys(("DISCOVERY_EVIDENCE", "TRANSACTION_EVIDENCE", "EVIDENCE_INTEGRITY",
                                               "VERIFIED_AGENTIC_COMMERCE"), "PASS"),
              "challenge_context_hash": "1" * 64, "protocol_hash": protocol_hash(), "prompt_hash": prompt_hash(CID),
              "participant_evidence_hash": "3" * 64, "agent_evidence_hash": "4" * 64, "trace_hash": "2" * 64,
              "transaction_evidence_hash": "5" * 64, "previous_record_hash": None}
    rule = RULES[channel]
    protocol = sorted(rule["protocols"])[0]
    detail = {"profile": "bd-commerce-channel/1", "entry_protocol": protocol, "entry_transport": rule["entry_transport"],
              "payment_protocol": protocol, "payment_transport": rule["payment_transport"],
              "payment_instrument": "shared-payment-token" if rule["agent"] else "hosted-checkout",
              "payment_started_at": "2026-11-03T12:01:00Z",
              "kya": ({"level": "merchant-verified-domain-control", "domain_sha256": "6" * 64,
                       "verified_at": "2026-11-03T11:59:00Z"} if rule["agent"] else {"level": "not-recorded"})}
    case = {"provider_key": provider_key, "reviewer_key": reviewer_key, "registry": keys, "pp": pp, "rp": rp,
            "record": record, "detail": detail, "channel": channel,
            "declaration": {"challenge_id": CID, "channel": channel, "declared_at": DECLARED, "salt": SALT,
                            "commitment": declaration_commitment(CID, channel, DECLARED, SALT)}}
    refresh(case)
    return case


def refresh(c):
    p = sign_artifact("provider-transaction", "v2", CID, "2026-11-03T12:02:00Z", "synthetic-provider", c["pp"],
                      c["provider_key"])
    c["rp"]["provider_payload_hash"] = p["payload_hash"]
    r = sign_artifact("discovery-review", "v2", CID, "2026-11-03T12:03:00Z", "synthetic-reviewer", c["rp"],
                      c["reviewer_key"])
    v = c["record"]
    v.update(provider_envelope_hash=sha256_hex(p), review_envelope_hash=sha256_hex(r),
             registry_hash=registry_hash(c["registry"]))
    v["hash"] = hash_object_without_hash(v)
    c["proof"] = {"package_version": "v1", "challenge_id": CID, "verification_record": copy.deepcopy(v),
                  "provider_artifact": p, "review_artifact": r,
                  "trusted_key_registry": {"registry_version": "v2", "keys": list(c["registry"].values())}}
    c["detail"]["provider_envelope_hash"] = sha256_hex(p)
    c["artifact"] = sign_artifact("provider-transaction", "v2", CID, "2026-11-03T12:03:20Z", "synthetic-provider",
                                  {**c["pp"], "channel_evidence": c["detail"]}, c["provider_key"])


def run_case(c, artifact="default", **overrides):
    artifact = c["artifact"] if artifact == "default" else artifact
    args = dict(challenge_id=CID, layer_channel=c["channel"], base_status="PASS", declaration_time=STAMPED,
                not_before=LAYER_FIXED, layer_sha256="7" * 64, trusted_registry=c["registry"], now=NOW)
    args.update(overrides)
    return replay.verify_inputs(encoded(c["declaration"]), encoded(c["proof"]),
                                None if artifact is None else encoded(artifact), **args)


class ChannelReleaseTests(unittest.TestCase):
    def test_every_channel_layer_has_a_complete_signed_pass(self):
        for channel in CHANNELS:
            with self.subTest(channel=channel):
                result = run_case(make_case(channel))
                self.assertEqual((result["status"], result["recorded_channel"]), ("PASS", channel), result["reason"])

    def test_unsuccessful_runs_are_recorded_not_rejected(self):
        c = make_case("mcp")
        self.assertEqual(run_case(c, base_status="FAIL")["reason"], "The base purchase is not a PASS")
        self.assertEqual(run_case(c, base_status="NO_RESULT")["status"], "NOT_VERIFIED")
        self.assertEqual(run_case(c, artifact=None)["reason"], "Signed channel artifact is missing")
        self.assertEqual(run_case(c, declaration_time=None)["status"], "NOT_VERIFIED")
        c["detail"]["payment_transport"] = "http"
        refresh(c)
        self.assertEqual(run_case(c)["status"], "NOT_VERIFIED")

    def test_a_challenge_issued_before_the_layer_was_fixed_cannot_pass(self):
        result = run_case(make_case("acp"), not_before="2026-11-03T11:58:30Z")
        self.assertEqual(result["reason"], "The challenge was issued before this channel layer was fixed")

    def test_declaration_must_match_its_commitment_and_layer(self):
        c = make_case("ucp")
        with self.assertRaises(replay.VerificationFailure):
            run_case(c, layer_channel="acp")
        c["declaration"]["channel"] = "acp"
        with self.assertRaises(replay.VerificationFailure):
            run_case(c, layer_channel="acp")

    def test_corrupted_or_retyped_channel_signature_is_rejected(self):
        c = make_case("mcp")
        broken = copy.deepcopy(c["artifact"])
        signature = bytearray(base64.b64decode(broken["signature"]))
        signature[0] ^= 1
        broken["signature"] = base64.b64encode(signature).decode()
        with self.assertRaises(replay.VerificationFailure):
            run_case(c, artifact=broken)
        retyped = copy.deepcopy(c)
        retyped["detail"]["kya"]["verified_at"] = "2026-11-01T11:59:00Z"
        refresh(retyped)
        self.assertEqual(run_case(retyped)["status"], "FAIL")

    def test_vendor_files_match_their_manifest(self):
        replay.check_vendor()
        manifest = json.loads((ROOT / "vendor-manifest.json").read_text(encoding="utf-8"))
        self.assertIn("verifier/channel.py", manifest["files"])
        route = json.loads((ROOT.parent / "route-v1" / "vendor-manifest.json").read_text(encoding="utf-8"))
        for name, digest in route["files"].items():
            self.assertEqual(manifest["files"][name], digest, name)
        trust = (ROOT / "trust" / "production-registry.json").read_bytes()
        self.assertEqual(hashlib.sha256(trust).hexdigest(), replay.TRUST_FILE_SHA256)


if __name__ == "__main__":
    unittest.main()
