# DoThat Quest Evidence Protocol v1.0 Draft

## Scope and compatibility

This draft verifies evidence for independent discovery and purchase of the service `101Ts3t`, with a fixed maximum total price of EUR 1.00. It defines the verifier and API contract. The repository includes a persistent reference backend; the protocol itself does not make purchases or establish that any particular deployment or provider integration is live.

The public protocol is **Protocol v1.0 Draft**, serialized as `protocol_version: v1.0-draft`. The official prompt is separately versioned as `prompt_version: v1.0-draft` and remains `prompts/official-agent-prompt-v1.0-draft.md`. Current signed evidence, challenge context, registry, record and result formats use the **v2 schemas**; artifact format v2 does not rename the public protocol. The earlier internally named `dothat-quest-evidence-protocol-v2.0-draft.md` remains unchanged historical draft material and is not the active protocol. Legacy format-v1 schemas are historical and are not accepted as current evidence. Protocol hashes cover the exact bytes of this active v1.0-draft protocol file. Prompt hashes cover the exact UTF-8 rendered prompt, including the challenge identifier, without Unicode or line-ending normalization.

## Neutral challenge and trusted context

The agent may receive the service name, EUR 1.00 total-price limit, challenge identifier, and the official evidence instructions. It must not receive a merchant identity, destination, checkout URL, endpoint, SKU, referral, or suggested discovery route. It must independently find an offer and record externally observable actions and results. Hidden reasoning is not evidence and is not required.

A trusted challenge issuer creates an immutable context before activity starts: `challenge_id`, `created_at`, `protocol_version`, `protocol_hash`, `prompt_version`, `exact_prompt`, `prompt_hash`, `service`, `max_budget`, and an opaque `participant_id`. The official budget is exactly `max_budget: {"amount_minor": 100, "currency": "EUR"}` (EUR 1.00); a client cannot choose a lower or higher official budget. The context is supplied separately to the verifier from trusted storage, never accepted merely because it appears in submitted JSON. Its `challenge_context_hash` is SHA-256 over its RFC 8785 canonical JSON.

The trust boundary is the caller that supplies `trusted_challenge`, the configured registry, verification time, and any trusted previous record. A self-generated local context is useful for synthetic tests but does not establish a real server-issued challenge. A successful offline result is meaningful only under that explicit trust assumption.

## Evidence and exact bindings

Participant and agent evidence are untrusted submissions. Their status flags, hashes, attestations, and `independent_discovery` assertion cannot independently produce PASS. The verifier hashes the actual separately supplied trace bytes and checks their links to both evidence objects. Trace references are opaque descriptions and never authorize filesystem access or network retrieval. `transaction_evidence.provider_server_evidence_reference` is the provider event identifier and must exactly equal the signed provider payload's `provider_event_reference`. It has no filesystem-path, URL, or artifact-location meaning. The provider artifact itself is supplied separately as bytes.

The review and provider envelopes require `artifact_type`, `schema_version: v2`, nonempty `challenge_id`, `issued_at`, `signing_key_id`, `signature_algorithm: Ed25519`, `payload_hash`, `payload`, and `signature`. Envelope and payload challenge identifiers must agree. Both payloads bind the exact trusted `challenge_context_hash`.

The discovery review additionally binds the exact prompt hash, protocol hash, trace hash, participant-evidence hash, agent-evidence hash, and provider-payload hash. It records the review time and reviewer/verifier version, prompt integrity, absence of pre-supplied merchant/destination information, usability of the chronological trace, independent reach, and the review result. This prevents a valid review from being transplanted onto different participant data, a rewritten agent sequence, or a different provider transaction.

The provider payload binds the challenge, context, service, transaction reference, `amount_minor`, EUR currency, payment and fulfillment status, provider event reference, and server timestamp. Transaction references must agree across all applicable evidence layers; the unsigned transaction reference to the provider event must exactly match the signed provider event identifier. Final transaction success requires PAID payment, COMPLETED fulfillment, and an integer `amount_minor` from 1 through 100 inclusive. A zero-value authorization or order is not proof of a real payment and cannot satisfy the transaction gate.

All current monetary values are integer EUR cents. Budget and transaction/provider values use `amount_minor`; trace offer prices use `observed_price_minor`, which may be an integer or null when unobserved. JSON monetary values must use integer tokens and remain integers after parsing: reject booleans, numeric strings, decimal forms such as `100.0`, exponent forms such as `1e2`, and fractional cents. Do not round or coerce them. The obsolete `amount` and `observed_price` fields are not accepted by current evidence schemas. For example, EUR 0.99 is `amount_minor: 99`, and EUR 1.01 is `amount_minor: 101`, which exceeds the quest cap.

A signature authenticates what an authorized reviewer or provider attested; it does not independently prove that their observations were truthful. The reviewer must actually inspect the evidence, and the provider signer must attest only to events verified in its own system. No participant-controlled signer may be enrolled as a trusted production reviewer or provider merely to make a test pass.

## Canonicalization and signatures

JSON must be parsed strictly before verification: duplicate object member names, non-finite numbers, invalid Unicode, unsupported schemas, and values outside the canonicalizer's supported number domain are rejected. RFC 8785 canonical JSON is supplied by the `rfc8785` library, not by ordinary JSON key sorting.

`payload_hash` is SHA-256 of the RFC 8785 canonical payload bytes. The Ed25519 signing input is the UTF-8 canonical JSON of the complete envelope without only its `signature` field. This includes artifact type, schema version, challenge identifier, issuance time, key identifier, algorithm, payload hash, and payload. Signature and public-key encodings use strict Base64. Public keys embedded in evidence are not trusted.

## Registry, rotation, and compromise

The registry is explicit trusted configuration using `trusted-key-registry-v2.schema.json`. Each entry requires `key_id`, `purpose`, `status`, `active_at`, and `public_key`; `status` is `active`, `retired`, or `revoked`. Validate the registry version, entries, key identifiers, purposes, timestamps, and Ed25519 public-key encodings before use. Duplicate key identifiers and reuse of one physical key under any two identifiers are invalid, including across reviewer/provider roles; one physical key has one immutable key identifier. File order must never select a replacement key. The registry cannot be supplied through an evidence body. Its canonical hash is retained in each generated record so the verification trust snapshot can be identified.

`active_at` is the first allowed issuance time. Ordinary rotation retains the old public-key entry with `status: retired` and a required `retired_at` later than activation; artifacts issued before retirement remain eligible for historical verification. Active entries cannot contain retirement or revocation timestamps. Use a new key identifier and key material for a replacement key.

`status: revoked` denotes compromise or loss of trust, not ordinary retirement; optional `revoked_at` is audit metadata, never a historical-acceptance cutoff. A revoked key is rejected for all artifacts under the current registry, even when their signer-controlled `issued_at` is backdated before the revocation time. An Ed25519 signature alone cannot establish when signing happened. No trusted timestamp service is implemented. Retired-key history remains conditional on that key not later being declared compromised.

The operator must obtain registry updates through an authenticated channel and retain the snapshots needed for audit. A hash identifies a registry snapshot; it does not authenticate its publisher. Re-evaluating a previously stored PASS with a changed registry is an explicit new verification, not a silent mutation of historical output.

## Time, chronology, and replay

Timestamps must be real timezone-aware RFC 3339 date-times, with no unknown `-00:00` offset and at most six fractional-second digits. The trusted verification clock is authoritative; evidence cannot select it. Creation, sequence events, provider events, review and issuance times are checked against their applicable ordering rules. A fixed 60-second clock-skew allowance bounds accepted future evidence relative to verification; it is not an unbounded future timestamp or a client override. Numeric sequence order alone does not establish chronological evidence. Previous-record verification time must not be later than the current verification time.

Trace events must be chronological and no earlier than challenge creation. The provider's server event must be no earlier than creation and no later than provider issuance; the final trace event may legitimately observe that provider event afterwards. The review must be no earlier than both the last trace event and provider issuance, and no later than review issuance. Participant submission time must be no earlier than creation and within the verification clock allowance. An unsigned client report of payment failure is not a verified provider failure.

Each signature is bound to the challenge context and relevant evidence hashes. Reusing evidence under another challenge, participant, start time, prompt, trace, or transaction must not produce PASS. The stateless verifier intentionally permits rechecking the same evidence against the same context and trust snapshot. This is verification replay, not another purchase and not evidence of a second completed challenge. A fixed explicit verification time supports reproducible offline checks; the live integration must supply its own current clock.

Persistent duplicate prevention, challenge ownership, uniqueness of provider events across issued challenges, idempotency, and lifecycle locking belong to the future backend. The API contract requires challenge-scoped submission capabilities and atomic idempotency handling. Its GET routes return safe public projections; the full authenticated verification result is returned by evidence submission. No backend protections are claimed as implemented by this repository.

## PASS and record semantics

Final PASS requires all of: valid current schemas, the separately trusted challenge context, actual trace integrity, all context and evidence linkages, acceptable chronological checks, a valid trusted signed discovery review with successful findings, and valid trusted provider evidence for successful payment and fulfillment within budget. Client-supplied PASS summaries cannot establish success.

`EVIDENCE_INTEGRITY` covers both unsigned evidence consistency and signed-artifact validation. A present artifact with an invalid schema, payload hash, signature, unknown or revoked key, or incorrect challenge/context/evidence linkage makes integrity FAIL. Chronological or other integrity contradictions also make it FAIL. If a required signed artifact is absent and no integrity failure is established, integrity is NOT_VERIFIED. Integrity can be PASS only after both signed artifacts have been validated and linked successfully. A valid signed negative review or provider result may preserve integrity PASS while its discovery/transaction dimension and the final result are FAIL. Missing trust or evidence never establishes final PASS, and any FAIL dimension takes precedence over NOT_VERIFIED.

Every verifier call returns the documented `verification-result-v2` wrapper: `status`, `result_summary`, `record` (or null), and `errors`. The entire wrapper is schema-validated; callers must not strip diagnostic fields to pretend it is a record. A record is generated only when its required inputs can be represented safely.

The v2 record binds the context, participant, agent, trace, transaction, complete review envelope, complete provider envelope, and registry hashes, together with protocol/prompt hashes, verifier and policy versions, verification time, statuses, and an optional previous-record hash. Envelope hashes include signature, signing key and issuance metadata. The record's own `hash` excludes only that self-hash field.

A previous record must be supplied separately from trusted storage. A submitted previous object and a recomputed hash do not establish history. The verifier checks schema, self-hash, challenge/context identity, time ordering, and exact linkage to the trusted prior record. Hash linking is not a transparency log, a record signature, or proof of an append-only public history. Publication authenticity and tamper-resistant retention require a separately designed backend and operational process.

## Privacy, versions, and review gates

Keep traces and original signing envelopes private by default. Evidence must not expose payment details, credentials, tokens, private keys, or unrelated personal information. Use opaque server-generated participant identifiers. Public projections contain only protocol/challenge metadata and verification-record commitments. A valid record hash is an integrity commitment, not permission to disclose the underlying evidence.

Once published, protocol versions and their associated artifacts must be immutable. This is still an unpublished draft. Its public protocol version and evidence-format version are distinct; the active protocol hash and the earlier internal draft's hash are not interchangeable. A future published protocol change requires a new protocol version; a format change requires its own explicit schema version. All bundled examples are synthetic. Test keys are temporary fixtures, never production trust anchors.

Before any backend integration, run schema and explicit fixture validation, full response-wrapper validation, the positive and adversarial verifier suite, and the isolated signature-bypass mutation check. A test suite must detect disabled signature verification. Production key custody, issuer identity, authentication, storage, rate limits, lifecycle enforcement, registry distribution, and deployment still require implementation and independent integration tests.
