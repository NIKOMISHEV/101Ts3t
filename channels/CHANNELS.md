# Payment channels for new 101Ts3t purchases

This document fixes, before the channel tests, how a test operator prepares an
agent for each payment channel. It adds to `TEST-SPECIFICATION.md` and to the
route-v1 release. It does not change the prompt, the protocol, the schemas, the
verifier or any historical record.

## One neutral prompt for every channel

- Every run starts with a fresh Official Quest challenge issued by
  [dothat.quest](https://dothat.quest/start) and uses its exact server-issued
  prompt.
- The prompt is the same for every channel. It never names a channel,
  protocol, merchant, domain, URL, endpoint, product ID or checkout link.
- The channel depends only on how the operator equips the agent before the
  run: the agent software, its payment capability and a domain the agent
  controls. The cards below are for the human operator. **Do not give them to
  the agent.**
- The agent obtains any seller-specific payment-profile, platform or
  domain-verification instructions from the seller, and only after it has
  discovered the seller on its own.
- Each purchase needs its own challenge. One channel per run.

## What a run can prove

- **Base PASS** (the original test): independent discovery, a real positive
  payment within EUR 1.00, and completed fulfilment, for the same challenge.
- **Additional route PASS** (route-v1): the same purchase recorded on one
  supported protocol from order to payment, paid with a shared payment token,
  with a merchant-recorded DNS domain-control check (KYA) no more than
  24 hours before payment starts.
- A channel that pays through a buyer-hosted checkout page can earn the base
  PASS only.
- A route result is a merchant-recorded protocol outcome. It does not
  establish native Google or OpenAI checkout approval, or execution inside a
  particular consumer app.

## Channel cards

### 1. MCP agent

- **Agent:** an agent that can find and connect to remote MCP servers over
  streamable HTTP, with OAuth 2.1 dynamic client registration or the seller's
  own registration flow.
- **Payment:** Stripe agent payments (Link). After the agent has discovered
  the seller, approve one Stripe Shared Payment Token: maximum total EUR 1.00,
  one purchase, short expiry.
- **Domain:** a domain you control, where a DNS TXT record can be published
  for the seller's domain-control check. Keep the record published until the
  purchase is complete.
- **Recorded route:** `bd-commerce/1` (MCP carries the seller's direct
  commerce protocol). Eligible for the additional route PASS.

### 2. Direct HTTP API agent

- **Agent:** an agent or framework that can read a published OpenAPI
  description and send signed HTTP requests.
- **Payment:** one Stripe Shared Payment Token, as in card 1.
- **Domain:** as in card 1.
- **Recorded route:** `bd-commerce/1`. Eligible for the additional route PASS.

### 3. ACP agent

- **Agent:** a platform or framework that implements the client side of the
  Agentic Commerce Protocol 2026-04-17: checkout sessions and delegated
  payment.
- **Payment:** a Stripe Shared Payment Token as the delegated payment, limited
  as in card 1.
- **Domain:** as in card 1.
- **Recorded route:** `acp/2026-04-17`. Eligible for the additional route PASS.

### 4. UCP platform

- **Agent:** a platform that implements the Universal Commerce Protocol
  (2026-08-25 or 2026-04-08), publishes a platform profile and signs its
  requests with HTTP Message Signatures (RFC 9421).
- **Before the run:** the seller accepts signed requests only from platforms
  it has approved. Open a **UCP platform approval** issue in this repository
  with your platform profile URL, and wait for the reply before you issue the
  challenge. Approval is not given to the agent and names no merchant to it.
- **Payment:** a Stripe Shared Payment Token, limited as in card 1.
- **Domain:** as in card 1.
- **Recorded route:** `ucp/2026-08-25` or `ucp/2026-04-08`. Eligible for the
  additional route PASS.

### 5. Agent-to-agent (A2A) agent

- **Agent:** an agent that can discover other agents and talk to them over A2A
  (JSON-RPC), and follow the seller agent's offer to its checkout.
- **Payment:** the checkout page the offer leads to (card, wallet or Stripe
  Link), within EUR 1.00.
- **Recorded route:** buyer-hosted checkout. Base PASS only.

### 6. Browser checkout agent

- **Agent:** any agent that can browse the web and complete a checkout page,
  for example an agent with a browser and a payment wallet such as
  [Sponge Wallet](https://wallet.paysponge.com).
- **Payment:** a card or wallet capped at EUR 1.00.
- **Recorded route:** buyer-hosted checkout. Base PASS only.

### Not yet available

- **AP2 payment mandates and Google Pay.** The seller declares them in a test
  environment only, so they cannot produce a real payment yet. A run that
  tries them is recorded as it happens and cannot earn a PASS until a live
  route is published.

## After each run

- Return the evidence through the same challenge on dothat.quest and make the
  single required confirmation.
- Share only the public verification record or the Challenge ID. Never post a
  card number, CVC, wallet secret, API key, payment token or login credential.
- A route-qualified purchase is published under `route-records/` only after
  the route-v1 workflow has replayed its signatures and chronology.
- Successful and unsuccessful runs are both recorded as they happen.

## Fixed before the tests

This file is attested with Sigstore by the **Attest the channel cards before
the channel tests** workflow before the first channel test. A later change
publishes a new file and a new attestation; it never rewrites this one.
