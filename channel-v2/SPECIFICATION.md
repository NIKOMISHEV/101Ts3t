# Channel qualification (channel-v2) for the 101Ts3t test

The original Official Quest, its PASS and route-v1 are unchanged. Channel
qualification is a separate result for a **new** purchase. It answers one
question: was the purchase made through the payment channel the operator
declared before the run?

## Declaration

- The operator may name one channel when issuing the challenge:
  `mcp`, `http-api`, `acp`, `ucp`, `a2a` or `browser`.
- The server then issues the prompt of that channel, prompt version
  `v1.0-draft+channel.<channel>` (`vendor/prompts/`): the unchanged
  v1.0-draft prompt plus one paragraph, "Payment channel for this test", that
  names the channel and tells the agent not to buy through any other channel.
  It never names the seller, a website, a URL, a server or a link; the agent
  still has to find the seller and its channel endpoint on its own. The prompt
  is part of `challenge_context_hash`, which the seller binds into the order.
- The declaration is also committed:
  SHA-256 of `dothat-channel-declaration/1`, the challenge ID, the channel,
  the issuance time and a random salt, one per line.
- The commitment is timestamped at issuance by an independent RFC 3161
  authority. Anyone can check the token with
  `openssl ts -verify -digest <commitment> -in token.tsr -CAfile <trust store>`.
- After the run ends (finalized, revoked or expired) the channel and salt are
  published, so anyone can recompute the commitment.
- Runs issued with the neutral prompt belong to channel-v1 and are recorded
  there.

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
  and before payment started; the agent's prompt was the prompt of the
  declared channel; the challenge was issued after the channel layer was fixed.
- **NOT_VERIFIED**: valid evidence that does not prove the declared channel,
  for example another channel, a missing artifact or a missing timestamp.
- **FAIL**: forged, unbound or malformed evidence.

Every declared run is listed under `/api/channels/{channel}/runs` once it has
ended, successful or not.
