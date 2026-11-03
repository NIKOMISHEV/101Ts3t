# Channel layer v2: Browser checkout agent

This folder is the channel-v2 evidence layer for the **browser** channel. It
holds the rules below, their own pre-event Sigstore commitment (`freeze/`) and
one record for every ended run of this channel (`runs/<challenge>/`),
successful or not.

Operator setup: card in [CHANNELS.md](../../channels/CHANNELS.md).

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

## The prompt

When the operator chooses **browser** on
[dothat.quest/start](https://dothat.quest/start), the server issues prompt
version `v1.0-draft+channel.browser`: the unchanged v1.0-draft prompt plus
this paragraph and nothing else.

> Payment channel for this test:
>
> Use only web pages in a browser: order the service on the seller's website and pay on the checkout page. Do not complete the purchase through any other channel. If this channel cannot be used, record why and stop without buying.

It names the channel only, never the seller, a website, a URL, a server or a
link. The agent still has to find the seller on its own. Template:
[official-agent-prompt-v1.0-draft+channel.browser.md](../../channel-v2/vendor/prompts/official-agent-prompt-v1.0-draft+channel.browser.md).

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

Live list of ended runs: `https://api.dothat.quest/api/channels/browser/runs`.
Rules for every channel: [channel-v2/SPECIFICATION.md](../../channel-v2/SPECIFICATION.md).
Runs issued with the neutral prompt before 3 November 2026: [channels/browser](../../channels/browser/README.md) (channel-v1).
