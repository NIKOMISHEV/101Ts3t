# Payment channel evidence layers, v2

Since 3 November 2026 the operator chooses the channel on dothat.quest/start
and the agent gets the prompt of that channel: the unchanged v1.0-draft prompt
plus one paragraph that names the payment channel, never the seller, a
website, a URL, a server or a link. Each channel has its own layer: its rules
and prompt, its own Sigstore commitment made before its first v2 test, and one
record for every ended run, successful or not.

| Layer | Channel |
|---|---|
| [mcp](mcp/README.md) | MCP agent |
| [http-api](http-api/README.md) | Direct HTTP API agent |
| [acp](acp/README.md) | ACP agent |
| [ucp](ucp/README.md) | UCP platform |
| [a2a](a2a/README.md) | Agent-to-agent (A2A) agent |
| [browser](browser/README.md) | Browser checkout agent |

Rules and replay: [channel-v2](../channel-v2/README.md).
Operator cards: [channels/CHANNELS.md](../channels/CHANNELS.md).
Earlier runs with the neutral prompt: [channels/](../channels/README.md) (channel-v1, unchanged).
Live lists: `https://api.dothat.quest/api/channels` and
`https://api.dothat.quest/api/channels/<channel>/runs`.
