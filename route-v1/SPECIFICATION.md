# Additional route qualification: fixed test specification v1

This is an additive, pre-event specification for a new 101Ts3t purchase. It does
not replace `TEST-SPECIFICATION.md`, the original `v1.0-draft` protocol, the
original prompt, signed-evidence format `v2`, or any historical PASS, proof,
workflow or Sigstore attestation.

## Commitment before the event

Before an eligible new run, freeze and publicly attest a release manifest that
commits this specification, the verifier, tests, schemas, original protocol and
prompt, dependency lock, separately authenticated public trust registry, and
the publication workflows. The manifest's verified Sigstore transparency-log
integrated time is the pre-event boundary. Neither a Git author date, a local
clock supplied by a participant, nor a date inside transaction evidence can
replace that external timestamp.

The operator must issue a **fresh Official Quest challenge after that
commitment**, then undertake a new purchase. The signed route's
`payment_started_at` must be strictly later than the verified commitment time.
The public proof does not expose an independently authenticated challenge
issuance timestamp; offline replay can enforce the signed payment-start
boundary, but cannot independently prove the fresh-issuance rule. Do not
describe that limitation as an independently verified issuance-time check.

## Neutral challenge and original result

The agent receives only the exact server-issued prompt and opaque challenge
context. The operator must not provide the merchant, domain, URL, endpoint,
product identifier, checkout link, protocol selection or discovery route.
Seller-specific payment and domain-verification instructions may be obtained
only after independent discovery. The operator must authorize a real positive
payment with the original EUR 1.00 total ceiling. The current offer is EUR 0.99.
Each purchase needs its own challenge. Implementation and synthetic tests are
not completed purchases.

The original proof must attest all four base gates as PASS:
`DISCOVERY_EVIDENCE`, `TRANSACTION_EVIDENCE`, `EVIDENCE_INTEGRITY` and
`VERIFIED_AGENTIC_COMMERCE`. It must bind the original prompt and protocol,
reviewed evidence commitments, successful positive EUR payment of 1–100 cents,
and completed fulfillment for the same requested challenge.

## Additional route result

The run records exactly one expected protocol, chosen for verification of the
actual independently discovered result, never inserted into the agent prompt:

- `bd-commerce/1`
- `acp/2026-04-17`
- `ucp/2026-08-25`
- `ucp/2026-04-08`

An additional PASS requires a separately signed `bd-commerce-route/1` artifact
from the same trusted provider key as the original payment. It must reproduce
the original signed transaction fields exactly, bind the original provider
envelope hash, and record the same supported protocol at order entry and
payment. It must record a shared payment token and merchant-verified DNS domain
control KYA, with a valid domain hash and verification time at or before payment
start, no more than 24 hours earlier. KYA asserts domain control only, not buyer
legal identity or authority to spend.

Payment start, provider event, provider signature and route signature must be
chronological. The discovery review must follow the provider signature; the
base record must follow the review. Future signatures or a future base record
are rejected by this offline release. Website/hosted checkout, mixed protocols,
absent route evidence or missing KYA cannot become an additional route PASS.
They do not erase an existing original PASS.

## Independent public replay and trust

The offline verifier accepts a requested challenge ID, exact public proof bytes,
exact signed route bytes, an expected supported protocol, the externally
verified specification commitment timestamp, and the committed specification
hash. It verifies Ed25519 signatures, RFC 8785 payload/envelope commitments,
record hash, original prompt/protocol commitments, key roles and lifecycles,
all public cross-links, amounts, chronology and KYA.

Only `trust/production-registry.json`, pinned in this release and obtained by the
operator through authenticated production SSH, supplies trusted keys. Keys
included in an arbitrary submitted proof are not a source of authority. The
embedded snapshot must exactly match the separately trusted registry. This
release has no CLI trust override. Revoked keys fail regardless of claimed
signature date; retirement limits the accepted signing interval. Key changes
or newly learned compromise require a separately reviewed trust/release update,
not silently changing this frozen snapshot.

The wrapper requires a known public schema with no added private fields and
restricted public references. It has no network, checkout, payment or evidence
submission capability. A successful replay summary commits exact file hashes;
it does not contain payment credentials, raw traces, participant identities or
private evidence. Synthetic fixtures use fresh in-memory test keys and are
never eligible for publication under the production trust root.

## Publication and meaning

Only after successful independent replay may the new route package be
immutably published under a new challenge and separately attested. Preserve
the original proof, signed route artifact, replay summary, release manifest
commitment and attestation evidence so another party can repeat the checks.
Do not label a failed, missing, synthetic or merely implemented route as PASS.

Sigstore establishes the publishing workflow identity, committed bytes and
transparency-log time. The trusted provider and reviewer signatures establish
who attested the transaction and discovery findings. Neither mechanism proves
the real-world truth of a dishonest trusted signer's statement. Public replay
does not reproduce private discovery traces, the private full evidence graph,
challenge issuance, or every record-chain predecessor.

The public verification record hash is a checksum, not a backend signature.
Unsigned projection fields such as `transaction_evidence_hash`,
`previous_record_hash` and `verified_at` are schema/chronology checked but are
not independently authenticated by provider/reviewer signatures. Exact-byte
retrieval and publication preserve that public projection's provenance; they
must not be described as independent cryptographic verification of backend
FINALIZED state or the complete record chain.

An ACP/UCP route PASS describes the merchant-recorded interoperable route. It
does not establish Google or OpenAI native checkout approval, allowlisting,
Merchant Center eligibility, or execution inside a particular consumer AI app.
Any future report must distinguish those claims from this narrower test.

The historical challenge `qst_44e153fc16fe3fa91520e5f6922ae4c9` remains its
original September 2026 PASS. It has no signed route artifact and is not a new
route-qualified purchase under this specification.
