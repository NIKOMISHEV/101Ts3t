# Pre-event specification attestation

This Sigstore attestation fixes the public test rules before the first
invited transaction. It does not assert that a transaction or PASS has
already occurred.

GitHub/Sigstore attestation: https://github.com/NIKOMISHEV/101Ts3t/attestations/48749208

Verify it with:

```text
gh attestation verify TEST-SPECIFICATION.md -R NIKOMISHEV/101Ts3t --predicate-type https://dothat.quest/attestations/test-specification/v1
```
