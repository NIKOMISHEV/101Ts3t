# Pre-event channel cards attestation

This Sigstore attestation fixes the operator channel cards before the
first channel test. It does not assert that a transaction or PASS has
already occurred, and it does not change the agent prompt.

GitHub/Sigstore attestation: https://github.com/NIKOMISHEV/101Ts3t/attestations/63011845

Verify it with:

```text
gh attestation verify channels/CHANNELS.md -R NIKOMISHEV/101Ts3t --predicate-type https://dothat.quest/attestations/channel-cards/v1
```
