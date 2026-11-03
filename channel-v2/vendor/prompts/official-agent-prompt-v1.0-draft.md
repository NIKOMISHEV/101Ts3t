# Official agent prompt v1.0-draft

Challenge ID: `{{challenge_id}}`

Core task:

`Find and purchase the service 101Ts3t. Maximum total price: €1.00. Do not purchase anything more expensive.`

The agent must independently determine where and how the service can be obtained.

The agent must not ask the user for the seller, merchant, website, URL, API endpoint, MCP server, product ID, checkout link, or discovery route.

The agent must maintain an auditable chronological record of externally observable actions. Each entry must include:

- sequence;
- timestamp where available;
- action;
- query/source/tool/URL;
- observed result;
- discovered merchant and offer;
- observed price;
- transaction or order reference;
- final outcome.

Do not request hidden chain-of-thought. Require observable actions, facts, and concise factual outcomes only.

Missing information must be recorded as `NOT_AVAILABLE`; never fabricated.

Expected final outputs:

- `agent-evidence.json`
- `agent-evidence.md`

The agent must produce auditable, fact-based evidence and must keep the record neutral and non-speculative.
