"""Require the real negative-signature tests to fail under an accept-all primitive.

This runs only synthetic in-memory fixtures. It performs no network requests,
does not alter vendored code, and never creates a public transaction record.
"""
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "tests"))
from test_release import ReleaseTests, signing


class AcceptAllPublicKey:
    @staticmethod
    def from_public_bytes(_value):
        return AcceptAllPublicKey()

    def verify(self, _signature, _message):
        return None


def main():
    stream = io.StringIO()
    with patch.object(signing, "Ed25519PublicKey", AcceptAllPublicKey):
        suite = unittest.TestSuite([ReleaseTests("test_signature_only_mutations_are_rejected")])
        result = unittest.TextTestRunner(stream=stream).run(suite)
    # All three otherwise-valid provider/reviewer/route forgeries must trigger
    # assertion failures when cryptographic validation is deliberately removed.
    detected = len(result.failures) == 3 and not result.errors
    print("SYNTHETIC accept-all mutation: " + ("DETECTED (3 signature oracles failed)" if detected else "NOT DETECTED"))
    return 0 if detected else 1


if __name__ == "__main__":
    raise SystemExit(main())
