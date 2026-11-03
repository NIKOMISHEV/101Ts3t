# Channel layer: Browser checkout agent

This folder is the separate evidence layer for the **browser** channel. It holds
the rules below, their own pre-event Sigstore commitment (`freeze/`) and one
record for every ended run declared for this channel (`runs/<challenge>/`),
successful or not.

Operator setup: card 6 in [CHANNELS.md](https://github.com/NIKOMISHEV/101Ts3t/blob/main/channels/CHANNELS.md). Never give it to the agent.

## What a PASS in this layer proves

The order and the payment were both made on the seller's website pages.

The seller signs these facts for the same paid purchase in a separate artifact,
`bd-commerce-channel/1`, bound to the original payment artifact:

| Signed fact | Required value |
|---|---|
| Protocol at order and at payment | website |
| Transport at order | `web` |
| Transport at payment | `web` |
| Payment | The seller's checkout page (card, wallet or Stripe Link). No KYA is required. |

The run must also be a base PASS of the original test (independent discovery,
a real positive payment within EUR 1.00 and completed fulfilment).

## The declaration

The operator declares **browser** when issuing the challenge on
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

Live list of ended runs: `https://api.dothat.quest/api/channels/browser/runs`.
Rules for every channel: [channel-v1/SPECIFICATION.md](../../channel-v1/SPECIFICATION.md).
