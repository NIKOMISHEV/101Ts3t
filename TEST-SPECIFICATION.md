# 101Ts3t public test specification

This document fixes the public rules before the first invited test run.

- Quest: independently find and purchase `101Ts3t`.
- Maximum total price: EUR 1.00.
- Live offer price: EUR 0.99.
- The agent receives only the exact challenge prompt and values issued by
  dothat.quest.
- The operator must not supply a merchant, domain, URL, endpoint, product ID,
  checkout link or discovery route.
- A commerce `PASS` requires a real positive payment, completed fulfillment,
  an independently reviewed discovery trace, valid signed evidence and intact
  cross-links for the same challenge.
- Discovery without payment can be submitted, but it remains `NOT_VERIFIED` for
  completed commerce.
- Missing evidence never becomes `PASS`.
- Private traces, participant data, credentials and payment data are not
  published.

The active public protocol is `v1.0-draft`; signed evidence uses format `v2`.
The protocol commitment published by the production API when this invitation
was prepared is:

```text
784b7a229aa9d28dad6f08b53e2d322189e2a4265828640fd53548dc0e12a96f
```

Current protocol metadata is available from
`https://api.dothat.quest/api/protocol`. Every final public record carries its
own protocol, prompt, evidence and registry commitments, so later changes do
not silently rewrite an earlier result.
