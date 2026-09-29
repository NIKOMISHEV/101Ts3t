"""Publication boundary tests. All attestation and HTTP evidence is synthetic.

No test contacts a merchant, GitHub, payment service or attestation service.
These tests establish fail-closed helper behaviour, not a real transaction PASS.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


SOURCE = Path(__file__).resolve().parents[1] / "release.py"
SPEC = importlib.util.spec_from_file_location("publication_under_test", SOURCE)
publication = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publication)

REVISION = "a" * 40
DIGEST = "b" * 64
CHALLENGE = "qst_" + "c" * 32
EVENT = "evt_" + "d" * 32
HISTORICAL = "qst_44e153fc16fe3fa91520e5f6922ae4c9"


def gh_result(subject_digest=DIGEST, predicate_type=publication.SPEC_TYPE):
    return [{"verificationResult": {
        "statement": {
            "predicateType": predicate_type,
            "subject": [{"name": "synthetic-manifest.json", "digest": {"sha256": subject_digest}}],
            "predicate": {"attested_at": "1990-01-01T00:00:00Z"},
        },
        "verifiedTimestamps": [{"type": "Tlog", "timestamp": "2000-01-01T00:00:00Z"}],
    }}]


class TrustedTimestampTests(unittest.TestCase):
    def verify(self, value):
        return publication.verified_timestamp(value, DIGEST, publication.SPEC_TYPE)

    def test_uses_latest_tlog_time_not_later_tsa_and_normalizes_utc(self):
        result = gh_result()
        result[0]["verificationResult"]["verifiedTimestamps"] = [
            {"type": "Tlog", "timestamp": "2000-01-01T00:00:00Z"},
            {"type": "Tlog", "timestamp": "2000-01-01T01:00:01+01:00"},
            {"type": "TimestampAuthority", "timestamp": "2000-01-01T01:00:10+01:00"},
        ]
        self.assertEqual(self.verify(result), "2000-01-01T00:00:01Z")

    def test_tsa_only_is_not_a_transparency_log_commitment(self):
        result = gh_result()
        result[0]["verificationResult"]["verifiedTimestamps"] = [
            {"type": "TimestampAuthority", "timestamp": "2000-01-01T00:00:00Z"}]
        with self.assertRaises(ValueError):
            self.verify(result)

    def test_unknown_timestamp_type_is_not_a_transparency_log_commitment(self):
        result = gh_result()
        result[0]["verificationResult"]["verifiedTimestamps"][0]["type"] = "TrustedTime"
        with self.assertRaises(ValueError):
            self.verify(result)

    def test_rejects_malformed_or_ambiguous_timestamps(self):
        bad_times = [None, True, 946684800, "", "2000-01-01", "2000-01-01T00:00:00",
                     "2000-01-01 00:00:00Z", "2000-13-01T00:00:00Z",
                     "2000-02-30T00:00:00Z", "2000-01-01T24:00:00Z",
                     "2000-01-01T00:00:60Z", "2000-01-01T00:00:00+25:00",
                     "2000-01-01T00:00:00Z\n", "2000-01-01T00:00:00.1234567890Z"]
        for timestamp in bad_times:
            with self.subTest(timestamp=timestamp):
                result = gh_result()
                result[0]["verificationResult"]["verifiedTimestamps"][0]["timestamp"] = timestamp
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    self.verify(result)

    def test_rejects_future_observer_time(self):
        result = gh_result()
        result[0]["verificationResult"]["verifiedTimestamps"][0]["timestamp"] = "9999-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "future"):
            self.verify(result)

    def test_no_fallback_to_predicate_raw_bundle_or_current_time(self):
        for timestamps in ([], None, [{"type": "CurrentTime", "timestamp": "2000-01-01T00:00:00Z"}]):
            with self.subTest(timestamps=timestamps):
                result = gh_result()
                result[0]["verificationResult"]["verifiedTimestamps"] = timestamps
                result[0]["bundle"] = {"verificationMaterial": {"integratedTime": 946684800}}
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    self.verify(result)
        result = gh_result()
        del result[0]["verificationResult"]["verifiedTimestamps"]
        with self.assertRaises((ValueError, TypeError, KeyError)):
            self.verify(result)

    def test_an_invalid_extra_timestamp_cannot_hide_behind_a_valid_one(self):
        result = gh_result()
        result[0]["verificationResult"]["verifiedTimestamps"].append(
            {"type": "CurrentTime", "timestamp": "1999-01-01T00:00:00Z"})
        with self.assertRaisesRegex(ValueError, "externally authenticated"):
            self.verify(result)

    def test_subject_digest_must_match_exactly(self):
        bad_subjects = [[], [{"digest": {"sha256": "e" * 64}}],
                        [{"digest": {"sha256": DIGEST, "sha512": "f" * 128}}],
                        [{"digest": {"sha256": DIGEST}}, {"digest": {"sha256": DIGEST}}],
                        [{"name": "synthetic-manifest.json"}]]
        for subjects in bad_subjects:
            with self.subTest(subjects=subjects):
                result = gh_result()
                result[0]["verificationResult"]["statement"]["subject"] = subjects
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    self.verify(result)

    def test_wrong_predicate_type_rejected(self):
        with self.assertRaisesRegex(ValueError, "predicate type"):
            self.verify(gh_result(predicate_type=publication.PASS_TYPE))

    def test_requires_exactly_one_verified_attestation(self):
        for result in (None, {}, [], gh_result() * 2, [{"statement": gh_result()[0]["verificationResult"]["statement"]}]):
            with self.subTest(result=result):
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    self.verify(result)


class GitHubVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.subject = Path(self.temporary.name) / "manifest with spaces.json"
        self.subject.write_bytes(b"synthetic subject\n")
        self.bundle = self.subject.parent / "bundle.json"
        self.bundle.write_bytes(b"untrusted bundle bytes, never parsed as trusted timestamps")
        self.output = json.dumps(gh_result(publication.digest(self.subject.read_bytes())))

    def test_gh_is_identity_constrained_and_success_checked(self):
        with patch.object(publication.subprocess, "run", return_value=SimpleNamespace(stdout=self.output)) as run:
            timestamp = publication.verify_attestation(self.subject, self.bundle, "route-freeze.yml",
                                                       publication.SPEC_TYPE, REVISION)
        self.assertEqual(timestamp, "2000-01-01T00:00:00Z")
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["gh", "attestation", "verify", str(self.subject)])
        expected_flags = {
            "--bundle": str(self.bundle), "--repo": publication.REPO,
            "--signer-workflow": publication.REPO + "/.github/workflows/route-freeze.yml",
            "--source-ref": "refs/heads/main", "--source-digest": REVISION,
            "--predicate-type": publication.SPEC_TYPE, "--format": "json",
        }
        for flag, value in expected_flags.items():
            self.assertEqual(command[command.index(flag) + 1], value)
            self.assertEqual(command.count(flag), 1)
        self.assertIn("--deny-self-hosted-runners", command)
        self.assertEqual(run.call_args.kwargs, {
            "check": True, "capture_output": True, "text": True, "timeout": 120})

    def test_failed_gh_does_not_consume_valid_looking_stdout(self):
        failure = subprocess.CalledProcessError(1, ["gh"], output=self.output)
        with patch.object(publication.subprocess, "run", side_effect=failure), \
             patch.object(publication, "verified_timestamp") as timestamp:
            with self.assertRaises(subprocess.CalledProcessError):
                publication.verify_attestation(self.subject, self.bundle, "route-freeze.yml",
                                                publication.SPEC_TYPE, REVISION)
            timestamp.assert_not_called()

    def test_successful_gh_with_wrong_subject_still_rejected(self):
        with patch.object(publication.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(gh_result()))):
            with self.assertRaisesRegex(ValueError, "subject"):
                publication.verify_attestation(self.subject, self.bundle, "route-freeze.yml",
                                                publication.SPEC_TYPE, REVISION)

    def test_successful_gh_with_non_json_output_fails_closed(self):
        with patch.object(publication.subprocess, "run", return_value=SimpleNamespace(stdout="verified!")):
            with self.assertRaises(ValueError):
                publication.verify_attestation(self.subject, self.bundle, "route-freeze.yml",
                                                publication.SPEC_TYPE, REVISION)


class FrozenInputsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for directory in ("route-v1", "workflow-support/tests", ".github/workflows", "records/old", "route-attestations/v1"):
            (self.root / directory).mkdir(parents=True)
        self.put("route-v1/SPECIFICATION.md", b"synthetic rules\n")
        self.put(".gitattributes", b"* -text\n")
        self.put("route-v1/verify_release.py", b"synthetic verifier\n")
        self.put("workflow-support/release.py", b"synthetic publication code\n")
        self.put("workflow-support/tests/test_guard.py", b"synthetic tests\n")
        for workflow in publication.WORKFLOWS:
            self.put(".github/workflows/" + workflow, b"synthetic workflow\n")
        self.put("records/old/proof.json", b'{"historical":"untouched"}\n')
        self.put("TEST-SPECIFICATION.md", b"old specification\n")
        baseline = {"files": {name: publication.digest((self.root / name).read_bytes())
                              for name in ("records/old/proof.json", "TEST-SPECIFICATION.md")}}
        self.put("workflow-support/historical-files.json", publication.encode(baseline))
        self.frozen = publication.manifest(REVISION, self.root)
        self.put("route-attestations/v1/manifest.json", publication.encode(self.frozen))

    def put(self, name, value):
        (self.root / name).write_bytes(value)

    def test_unchanged_manifest_and_history_are_accepted(self):
        self.assertEqual(publication.check_manifest(self.root), self.frozen)
        self.assertIn("workflow-support/tests/test_guard.py", self.frozen["files"])
        self.assertIn(".gitattributes", self.frozen["files"])
        for workflow in publication.WORKFLOWS:
            self.assertIn(".github/workflows/" + workflow, self.frozen["files"])

    def test_mutated_input_is_rejected(self):
        self.put("route-v1/SPECIFICATION.md", b"weakened rules\n")
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            publication.check_manifest(self.root)

    def test_missing_input_is_rejected(self):
        (self.root / "route-v1/verify_release.py").unlink()
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            publication.check_manifest(self.root)

    def test_new_input_is_rejected(self):
        self.put("workflow-support/new_helper.py", b"new execution path\n")
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            publication.check_manifest(self.root)

    def test_mutated_workflow_is_rejected(self):
        self.put(".github/workflows/route-anchor.yml", b"changed publishing permissions\n")
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            publication.check_manifest(self.root)

    def test_missing_required_workflow_is_rejected(self):
        (self.root / ".github/workflows/route-freeze.yml").unlink()
        with self.assertRaises(FileNotFoundError):
            publication.check_manifest(self.root)

    def test_changed_checkout_byte_preservation_policy_is_rejected(self):
        self.put(".gitattributes", b"* text=auto\n")
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            publication.check_manifest(self.root)

    def test_missing_checkout_byte_preservation_policy_is_rejected(self):
        (self.root / ".gitattributes").unlink()
        with self.assertRaises(FileNotFoundError):
            publication.check_manifest(self.root)

    def test_generated_python_cache_does_not_change_frozen_inputs(self):
        cache = self.root / "route-v1/__pycache__"
        cache.mkdir()
        (cache / "verify.cpython-312.pyc").write_bytes(b"generated cache")
        self.assertEqual(publication.check_manifest(self.root), self.frozen)

    def test_old_historical_content_cannot_change(self):
        self.put("records/old/proof.json", b'{"status":"PASS"}\n')
        with self.assertRaisesRegex(ValueError, "Historical file changed"):
            publication.check_manifest(self.root)

    def test_old_historical_file_cannot_disappear(self):
        (self.root / "TEST-SPECIFICATION.md").unlink()
        with self.assertRaises(FileNotFoundError):
            publication.check_history(self.root)

    def test_invalid_source_revision_rejected(self):
        for revision in ("main", "a" * 39, "A" * 40, "a" * 40 + "\n", "--source-ref=other"):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                publication.manifest(revision, self.root)

    def test_write_new_does_not_overwrite_historical_bytes(self):
        target = self.root / "records/old/proof.json"
        original = target.read_bytes()
        with self.assertRaises(FileExistsError):
            publication.write_new(target, b"replacement")
        self.assertEqual(target.read_bytes(), original)


class PublicDownloadTests(unittest.TestCase):
    def response(self, kind="proof", data=b"{}", status=200, url=None):
        expected = ("https://api.dothat.quest/api/proofs/" + CHALLENGE if kind == "proof" else
                    "https://branddesign.host/commerce/v1/evidence/" + EVENT + "/route")
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = status
        response.geturl.return_value = expected if url is None else url
        response.read.return_value = data
        return response

    def test_invalid_ids_and_kind_are_rejected_before_network(self):
        cases = [("proof", "qst_" + "c" * 31), ("proof", CHALLENGE + "?token=x"),
                 ("proof", "../../private"), ("proof", EVENT), ("proof", "qst_" + "C" * 32),
                 ("route", CHALLENGE), ("route", EVENT + "/../private"),
                 ("route", EVENT + "\n"), ("private", CHALLENGE)]
        with patch.object(publication.urllib.request, "build_opener") as opener:
            for kind, identifier in cases:
                with self.subTest(kind=kind, identifier=identifier), self.assertRaises(ValueError):
                    publication.download(kind, identifier)
            opener.assert_not_called()

    def test_valid_ids_use_only_fixed_public_endpoints_and_bounded_reads(self):
        for kind, identifier in (("proof", CHALLENGE), ("route", EVENT)):
            with self.subTest(kind=kind):
                response = self.response(kind)
                with patch.object(publication.urllib.request, "build_opener") as build:
                    build.return_value.open.return_value = response
                    self.assertEqual(publication.download(kind, identifier), b"{}")
                build.assert_called_once_with(publication.NoRedirect)
                request = build.return_value.open.call_args.args[0]
                self.assertEqual(request.full_url, response.geturl.return_value)
                self.assertEqual(request.get_method(), "GET")
                self.assertEqual(request.get_header("Accept"), "application/json")
                self.assertIsNone(request.get_header("Authorization"))
                self.assertEqual(build.return_value.open.call_args.kwargs, {"timeout": 30})
                response.read.assert_called_once_with(publication.MAX_BYTES + 1)

    def test_redirect_handler_rejects_redirect_instead_of_following_it(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, "redirects"):
                publication.NoRedirect().redirect_request(None, None, code, "redirect", {}, "https://other.example/")

    def test_changed_response_url_or_non_200_cannot_be_used(self):
        for response in (self.response(url="https://other.example/proof"), self.response(status=302),
                         self.response(status=404), self.response(status=206)):
            with self.subTest(status=response.status, url=response.geturl.return_value):
                with patch.object(publication.urllib.request, "build_opener") as build:
                    build.return_value.open.return_value = response
                    with self.assertRaisesRegex(ValueError, "response"):
                        publication.download("proof", CHALLENGE)
                    response.read.assert_not_called()

    def test_empty_or_oversize_response_rejected(self):
        for data in (b"", b"x" * (publication.MAX_BYTES + 1)):
            with self.subTest(size=len(data)):
                with patch.object(publication.urllib.request, "build_opener") as build:
                    build.return_value.open.return_value = self.response(data=data)
                    with self.assertRaisesRegex(ValueError, "size limit"):
                        publication.download("proof", CHALLENGE)

    def test_exact_size_limit_is_permitted(self):
        data = b"x" * publication.MAX_BYTES
        with patch.object(publication.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = self.response(data=data)
            self.assertEqual(publication.download("proof", CHALLENGE), data)


class RunPreflightTests(unittest.TestCase):
    def test_invalid_challenge_and_protocol_reject_before_attestation_or_network(self):
        cases = [("qst_bad", "acp/2026-04-17"), (CHALLENGE, "unrecognized"),
                 (CHALLENGE + "\n", "ucp/2026-08-25")]
        for challenge, protocol in cases:
            with self.subTest(challenge=challenge, protocol=protocol):
                with patch.dict(os.environ, {"CHALLENGE_ID": challenge, "EXPECTED_PROTOCOL": protocol}), \
                     patch.object(publication, "authenticate_freeze") as authenticate, \
                     patch.object(publication, "download") as download:
                    with self.assertRaises(ValueError):
                        publication.prepare_run()
                    authenticate.assert_not_called()
                    download.assert_not_called()

    def test_historical_record_cannot_be_relabelled_as_a_fresh_route_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical = root / "records" / HISTORICAL
            historical.mkdir(parents=True)
            original = b"historical public evidence bytes"
            (historical / "proof.json").write_bytes(original)
            with patch.object(publication, "ROOT", root), \
                 patch.dict(os.environ, {"CHALLENGE_ID": HISTORICAL, "EXPECTED_PROTOCOL": "acp/2026-04-17"}), \
                 patch.object(publication, "authenticate_freeze") as authenticate, \
                 patch.object(publication, "download") as download:
                with self.assertRaisesRegex(ValueError, "Historical base record"):
                    publication.prepare_run()
                authenticate.assert_not_called()
                download.assert_not_called()
            self.assertEqual((historical / "proof.json").read_bytes(), original)
            self.assertFalse((root / "route-records").exists())

    def test_existing_route_record_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "route-records" / CHALLENGE).mkdir(parents=True)
            with patch.object(publication, "ROOT", root), \
                 patch.dict(os.environ, {"CHALLENGE_ID": CHALLENGE, "EXPECTED_PROTOCOL": "acp/2026-04-17"}), \
                 patch.object(publication, "authenticate_freeze") as authenticate, \
                 patch.object(publication, "download") as download:
                with self.assertRaisesRegex(ValueError, "already exists"):
                    publication.prepare_run()
                authenticate.assert_not_called()
                download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
