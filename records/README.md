# Public verification records

The first public record is the finalized `PASS` for
[`qst_44e153fc16fe3fa91520e5f6922ae4c9`](./qst_44e153fc16fe3fa91520e5f6922ae4c9/).
The [public verifier](https://api.dothat.quest/api/verifications/qst_44e153fc16fe3fa91520e5f6922ae4c9)
reports `FINALIZED` / `PASS`. The related sources are the
[privacy-safe public proof](https://api.dothat.quest/api/proofs/qst_44e153fc16fe3fa91520e5f6922ae4c9),
[GitHub/Sigstore attestation](https://github.com/NIKOMISHEV/101Ts3t/attestations/48971853),
[Zenodo implementation archive, version 1.3](https://zenodo.org/records/22878834),
and [pre-published test rules](../TEST-SPECIFICATION.md).

The [record directory](./qst_44e153fc16fe3fa91520e5f6922ae4c9/)
contains the public proof package, the small predicate used by GitHub Actions,
and the [Sigstore verification bundle](./qst_44e153fc16fe3fa91520e5f6922ae4c9/proof.sigstore.json).
Raw traces, participant identifiers, payment details, credentials and
submission capabilities are not stored here.

The [GitHub/Sigstore attestation](https://github.com/NIKOMISHEV/101Ts3t/attestations/48971853)
anchors the exact package files and the public workflow that produced them.
The provider and reviewer artifacts in the package support the transaction
claim; the attestation alone does not prove a payment.
