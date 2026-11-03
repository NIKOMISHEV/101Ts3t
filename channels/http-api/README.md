# Channel layer: Direct HTTP API agent

This folder is the separate evidence layer for the **http-api** channel. It holds
the rules below, their own pre-event Sigstore commitment (`freeze/`) and one
record for every ended run declared for this channel (`runs/<challenge>/`),
successful or not.

Operator setup: card 2 in [CHANNELS.md](https://github.com/NIKOMISHEV/101Ts3t/blob/main/channels/CHANNELS.md). Never give it to the agent.

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

## The declaration

The operator declares **http-api** when issuing the challenge on
[dothat.quest](https://dothat.quest/start). The channel never enters the prompt.
While the run is open only a commitment is public, timestamped by an independent
RFC 3161 authority. After the run the channel and salt are published and the
commitment can be recomputed. A PASS needs that timestamp within five minutes of
issuance and before payment started, and an issuance after this layer was fixed.

## Results

- **PASS**: everything above holds.
- **NOT_VERIFIED**: valid evidence that does not prove this channel, or a run
  without a base PASS. It is recorded like any other run.
- **FAIL**: forged, unbound or malformed evidence.

Live list of ended runs: `https://api.dothat.quest/api/channels/http-api/runs`.
Rules for every channel: [channel-v1/SPECIFICATION.md](../../channel-v1/SPECIFICATION.md).
