# Offline route qualification release v1

This directory adds reproducible verification for a **future new purchase**.
It makes no claim that a new route-qualified purchase has already happened.
Read [the fixed specification](SPECIFICATION.md) before a new run.

The original files outside this directory remain historical records. In
particular, the original specification and PASS package must not be rewritten
or reinterpreted as an ACP/UCP result.

## Install and test

Use Python 3.12 in an isolated environment. Dependency installation may use the
network; evidence verification itself does not.

```sh
python -m venv .venv
# Activate the environment using your operating system's normal command.
python -m pip install --require-hashes -r route-v1/requirements.lock
python -m unittest discover -s route-v1/tests -v
python route-v1/check_signature_mutation.py
```

Run these commands from the repository root. The suite covers complete signed
synthetic PASS fixtures for all four protocols and isolated negative mutations:
requested and signed IDs, transaction references, signature-only corruption,
cross-links and hashes, original prompt, base gates, positive bounded amounts,
time ordering, KYA freshness, untrusted/revoked/retired keys, malformed input and
private fields. It also replays the original real base proof and checks its
immutable SHA-256 while requiring its missing route to remain NOT_VERIFIED.

`check_signature_mutation.py` temporarily replaces Ed25519 verification only in
memory with an accept-all implementation. It must detect three failing
signature-oracle assertions (provider, reviewer and route). A green synthetic
suite or mutation test is implementation evidence, never a production purchase.
No fixture private key is serialized or published.

## Replay an eligible real package

First authenticate the frozen release manifest and its Sigstore attestation
using the repository publication workflow. Check the approved repository and
workflow identity, the subject digest and transparency-log verification before
extracting its integrated time. The manifest must commit this specification
and the exact verifier/trust/workflow files being used.

Obtain the privacy-safe finalized public proof for the requested challenge and
its matching provider-signed route artifact. The publication workflow performs
the constrained download; the replay CLI does not download arbitrary URLs.

```sh
python route-v1/verify_release.py \
  --challenge-id qst_REPLACE_WITH_32_LOWERCASE_HEX \
  --proof /path/to/proof.json \
  --route /path/to/route.json \
  --expected-protocol ucp/2026-04-08 \
  --not-before VERIFIED_SPEC_ATTESTATION_RFC3339_TIME \
  --spec-sha256 VERIFIED_MANIFEST_SPECIFICATION_SHA256 \
  --output /new/path/to/replay.json
```

These placeholders are deliberately not runnable evidence. The four allowed
protocols are listed in the specification. `--spec-sha256` is the SHA-256 of
`SPECIFICATION.md`, taken from the authenticated manifest. `--not-before` is
the verified Sigstore manifest attestation time, not an operator-selected date
or an evidence field. The CLI checks the local spec digest but relies on the
caller to authenticate that timestamp and manifest. A standalone invocation
with fabricated trust inputs does not establish a pre-event commitment.

The output parent directory must exist and the output file must be new. Exit
code 0 and a PASS JSON summary mean the public signed claims passed replay.
Verification rejection returns exit code 1, prints a fixed non-sensitive error,
and writes no result. No `--registry` or `--now` override exists in the CLI.
The internal Python API accepts explicit synthetic test trust and time solely
to test the boundary; publication must invoke the production CLI.

## Source and trust provenance

- `vendor/` contains byte-preserved public verifier, schema, prompt and protocol
  files from the operator's deployed DoThat Quest release
  `20260929-route-binding`, hash-matched to production on 29 September 2026.
  [vendor-manifest.json](vendor-manifest.json) records their SHA-256 values.
- The release wrapper adds requested-ID and expected-protocol constraints,
  exact original-prompt binding, stricter public chronology and future-time
  checks, pinned trust, bounded public inputs and the pre-event payment boundary.
  It does not modify the production backend or the vendored verifier.
- [trust/production-registry.json](trust/production-registry.json) was exported
  by the operator through an existing authenticated SSH connection to the
  production service. Only public key metadata was exported, independently of
  the submitted proof. File SHA-256:
  `770e2a254de6d30ece20aee6de1c62ddcea0229b681dd1e760c071eb149b186f`.
  Canonical registry commitment:
  `c4c6f5c1bd4989f699645e5112d950148ac10ed50d53dd3862793ed4a8c131e4`.
  Future key rotation or revocation requires a new reviewed release.
- Historical proof SHA-256:
  `c032d43de422161baaf10857a03e9870112f3aa5cae8cd73ed026462c165a16a`.
  Its original [Sigstore attestation](https://github.com/NIKOMISHEV/101Ts3t/attestations/48971853)
  is a historical provenance reference, not this release's trust bootstrap.

## Limits

This is an offline replay of public evidence signed by identified trusted
parties. It cannot independently observe the real payment, reconstruct private
traces or prove that a trusted signer told the truth. The package has no signed
challenge-issuance timestamp: a fresh challenge is a required operating rule,
while the enforceable public time boundary is signed `payment_started_at`.
Commitments to private evidence and previous records are preserved, not
reconstructed from omitted private data. Static pinned trust does not discover
future compromise or revocation on its own.

The verification record's hash is an integrity checksum, not a backend
signature. Some projection fields, including `transaction_evidence_hash`,
`previous_record_hash` and `verified_at`, are not themselves bound by the
provider/reviewer signatures. The wrapper checks their schema and applicable
chronology, but cannot independently authenticate backend FINALIZED state or
the entire historical record chain. Downloading from the fixed HTTPS API and
attesting exact bytes preserves the retrieved projection's provenance; the
replay's cryptographic claim is limited to the signed assertions and their
checked cross-links.

Strict public schemas and reference formats reject unexpected fields, but no
software can guarantee that a trusted signer has not hidden information inside
an otherwise valid public value. Review the package before publication. Keep
raw traces, credentials, private keys and payment capabilities out of Git.

Route qualification is separate from platform onboarding. Neither a successful
replay nor a Sigstore timestamp means native Google/OpenAI checkout approval.
