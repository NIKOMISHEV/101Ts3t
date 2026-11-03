# Channel layer v2: Direct HTTP API agent

This folder is the channel-v2 evidence layer for the **http-api** channel. It
holds the rules below, their own pre-event Sigstore commitment (`freeze/`) and
one record for every ended run of this channel (`runs/<challenge>/`),
successful or not.

Operator setup: card in [CHANNELS.md](../../channels/CHANNELS.md).

## What a PASS in this layer proves

The order and the payment both reached the seller's HTTP API directly from the agent, with the agent's own signed requests.

The seller signs these facts for the same paid purchase in a separate artifact,
`bd-commerce-channel/1`, bound to the original payment artifact:

| Signed fact | Required value |
|---|---|
| Protocol at order and at payment | bd-commerce/1 |
| Transport at order | `http` |
| Transport at payment | `http` |
| Payment | A Stripe shared payment token, with the seller's DNS domain-control check (KYA) for the agent no more than 24 hours before payment started. |

The run must also be a base PASS of the original test (independent discovery,
a real positive payment within EUR 1.00 and completed fulfilment).

## The prompt

When the operator chooses **http-api** on
[dothat.quest/start](https://dothat.quest/start), the server issues prompt
version `v1.0-draft+channel.http-api`: the unchanged v1.0-draft prompt plus
this paragraph and nothing else.

> Payment channel for this test:
>
> Use the seller's HTTP API directly for both the order and the payment (not MCP and not a web page). Complete the seller's agent identity verification (KYA) before paying, and pay with a Stripe Shared Payment Token. Do not complete the purchase through any other channel. If this channel cannot be used, record why and stop without buying.

It names the channel only, never the seller, a website, a URL, a server or a
link. The agent still has to find the seller on its own. Template:
[official-agent-prompt-v1.0-draft+channel.http-api.md](../../channel-v2/vendor/prompts/official-agent-prompt-v1.0-draft+channel.http-api.md).

## The declaration

The channel is also committed at issuance and timestamped by an independent
RFC 3161 authority. After the run the channel and salt are published and the
commitment can be recomputed. A PASS needs that timestamp within five minutes
of issuance and before payment started, and an issuance after this layer was
fixed.

## Results

- **PASS**: everything above holds.
- **NOT_VERIFIED**: valid evidence that does not prove this channel, or a run
  without a base PASS. It is recorded like any other run.
- **FAIL**: forged, unbound or malformed evidence.

Live list of ended runs: `https://api.dothat.quest/api/channels/http-api/runs`.
Rules for every channel: [channel-v2/SPECIFICATION.md](../../channel-v2/SPECIFICATION.md).
Runs issued with the neutral prompt before 3 November 2026: [channels/http-api](../../channels/http-api/README.md) (channel-v1).
