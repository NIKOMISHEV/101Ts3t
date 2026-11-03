# Payment channel evidence layers

> New channel tests since 3 November 2026 give the agent the prompt of the chosen channel and are
> recorded in [channels-v2](../channels-v2/README.md). The channel-v1 layers below stay unchanged
> for runs issued with the neutral prompt.

Each payment channel has its own evidence layer: its rules, its own Sigstore
commitment made before the first channel test, and one record for every ended
run declared for it, successful or not.

| Layer | Operator card | Can prove |
|---|---|---|
| [mcp](mcp/README.md) | 1 | MCP order and payment, token, KYA |
| [http-api](http-api/README.md) | 2 | Direct HTTP API order and payment, token, KYA |
| [acp](acp/README.md) | 3 | ACP 2026-04-17 checkout and delegated payment |
| [ucp](ucp/README.md) | 4 | UCP order and payment by an approved platform or KYA agent |
| [a2a](a2a/README.md) | 5 | Offer from the seller's AI representative over A2A, checkout page |
| [browser](browser/README.md) | 6 | Order and payment on the seller's website |

Operator cards: [CHANNELS.md](CHANNELS.md) (attested 03.11.2026, unchanged).
Rules and replay: [channel-v1](../channel-v1/README.md).
Live lists: `https://api.dothat.quest/api/channels` and
`https://api.dothat.quest/api/channels/<channel>/runs`.
