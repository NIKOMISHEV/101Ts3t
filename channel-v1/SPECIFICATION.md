# Channel qualification (channel-v1) for the 101Ts3t test

The original Official Quest, its PASS and route-v1 are unchanged. Channel
qualification is a separate result for a **new** purchase. It answers one
question: was the purchase made through the payment channel the operator
declared before the run?

## Declaration

- The operator may name one channel when issuing the challenge:
  `mcp`, `http-api`, `acp`, `ucp`, `a2a` or `browser`.
- The channel never enters the challenge context or the prompt. The agent gets
  the same neutral prompt as every other run.
- While the run is open only a commitment is public:
  SHA-256 of `dothat-channel-declaration/1`, the challenge ID, the channel,
  the issuance time and a random salt, one per line.
- The commitment is timestamped at issuance by an independent RFC 3161
  authority. Anyone can check the token with
  `openssl ts -verify -digest <commitment> -in token.tsr -CAfile <trust store>`.
- After the run ends (finalized, revoked or expired) the channel and salt are
  published, so anyone can recompute the commitment.

## What the seller signs

For each new completed purchase the seller signs a separate artifact,
`bd-commerce-channel/1`, at
`branddesign.host/commerce/v1/evidence/{event}/channel`. It is bound to the
original payment artifact and records, as observed by the seller's server:
protocol and transport at order creation, protocol and transport at payment,
the payment instrument, the payment start time and the KYA state.

## Channel rules

| Channel | Protocol at order and payment | Transport order / payment | Payment |
|---|---|---|---|
| mcp | bd-commerce/1 | mcp / mcp | shared payment token, current KYA |
| http-api | bd-commerce/1 | http / http | shared payment token, current KYA |
| acp | acp/2026-04-17 | http / http | shared payment token, current KYA |
| ucp | ucp/2026-08-25 or ucp/2026-04-08 | http / http | shared payment token, current KYA or a platform the seller approved |
| a2a | website | a2a / web | checkout page |
| browser | website | web / web | checkout page |

## Results

- **PASS**: base PASS; the channel artifact is valid and describes the same
  paid transaction; the signed facts match the declared channel; the
  declaration was independently timestamped within five minutes of issuance
  and before payment started.
- **NOT_VERIFIED**: valid evidence that does not prove the declared channel,
  for example another channel, a missing artifact or a missing timestamp.
- **FAIL**: forged, unbound or malformed evidence.

Every declared run is listed under `/api/channels/{channel}/runs` once it has
ended, successful or not. Open runs are never listed, so the list cannot tell
an agent its own channel.
