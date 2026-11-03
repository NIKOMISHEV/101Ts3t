"""Publication rules for the channel layers. Offline; no attestation or download is made."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import publish

SHA = "a" * 40


class PublishTests(unittest.TestCase):
    def test_each_layer_commits_to_its_own_rules_and_the_shared_release(self):
        mcp, acp = publish.manifest("mcp", SHA), publish.manifest("acp", SHA)
        self.assertIn("channels-v2/mcp/README.md", mcp["files"])
        self.assertNotIn("channels-v2/acp/README.md", mcp["files"])
        self.assertIn("channel-v2/vendor/verifier/channel.py", mcp["files"])
        self.assertIn(".github/workflows/channel-v2-record.yml", acp["files"])
        shared = {k: v for k, v in mcp["files"].items() if not k.startswith("channels-v2/")}
        self.assertEqual(shared, {k: v for k, v in acp["files"].items() if not k.startswith("channels-v2/")})
        self.assertFalse(any("/runs/" in name or "/freeze/" in name for name in mcp["files"]))
        with self.assertRaises(ValueError):
            publish.manifest("fax", SHA)

    def test_attestations_are_checked_against_the_v2_workflows_only(self):
        source = (Path(publish.__file__)).read_text(encoding="utf-8")
        import re
        named = set(re.findall(r'"(channel[a-z0-9-]*\.yml)"', source))
        self.assertEqual(named, set(publish.WORKFLOWS))

    def test_only_transparency_log_time_from_gh_verification_counts(self):
        statement = {"predicateType": publish.LAYER_TYPE, "subject": [{"digest": {"sha256": "d" * 64}}]}
        good = [{"verificationResult": {"statement": statement, "verifiedTimestamps": [
            {"type": "Tlog", "timestamp": "2026-11-03T10:00:00Z"}]}}]
        self.assertEqual(publish.verified_timestamp(good, "d" * 64, publish.LAYER_TYPE), "2026-11-03T10:00:00Z")
        only_tsa = [{"verificationResult": {"statement": statement, "verifiedTimestamps": [
            {"type": "TimestampAuthority", "timestamp": "2026-11-03T10:00:00Z"}]}}]
        with self.assertRaises(ValueError):
            publish.verified_timestamp(only_tsa, "d" * 64, publish.LAYER_TYPE)
        with self.assertRaises(ValueError):
            publish.verified_timestamp(good, "e" * 64, publish.LAYER_TYPE)

    def test_rfc3161_time_is_read_from_openssl_and_fractions_round_up(self):
        self.assertEqual(publish.openssl_time("Status: Granted.\nTime stamp: Nov  3 10:03:30 2026 GMT\n"),
                         "2026-11-03T10:03:30Z")
        self.assertEqual(publish.openssl_time("Time stamp: Dec 31 23:59:59.5 2026 GMT"), "2027-01-01T00:00:00Z")
        with self.assertRaises(ValueError):
            publish.openssl_time("Time stamp: unavailable")

    def test_a_run_in_progress_is_never_recorded(self):
        body = json.dumps({"challenge_id": "qst_" + "b" * 32, "status": "IN_PROGRESS", "commitment": "c" * 64}).encode()
        with tempfile.TemporaryDirectory() as temp, \
                patch.dict(os.environ, {"CHALLENGE_ID": "qst_" + "b" * 32, "RUNNER_TEMP": temp, "GITHUB_SHA": SHA}), \
                patch.object(publish, "download", return_value=body):
            with self.assertRaises(ValueError):
                publish.prepare_run()


if __name__ == "__main__":
    unittest.main()
