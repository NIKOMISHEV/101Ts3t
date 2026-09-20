# Can your AI agent complete a real purchase without merchant hints?

`101Ts3t` is a live public test of AI-agent discovery and real agentic commerce.

The challenge asks an AI agent to independently find and purchase the service `101Ts3t`. The maximum total price is **EUR 1.00**. A successful purchase creates a real **EUR 0.99** charge.

This page is an invitation for human test operators. **Do not paste, summarize or otherwise provide this page to the agent.** The agent must receive only the exact quest prompt issued by [dothat.quest](https://dothat.quest/).

## Take part

Choose one payment path:

1. **Stripe/Link is already available to your agent.** Use it. Only after the
   agent independently discovers the seller, approve a Stripe Shared Payment
   Token limited to EUR 1.00, one purchase and a short expiry. See
   [Stripe's agent payment guide](https://stripe.com/blog/giving-agents-the-ability-to-pay).
2. **Your agent does not already have Stripe/Link.** The quick route is to set
   up a [Sponge Wallet](https://wallet.paysponge.com) and its
   [official wallet skill](https://github.com/paysponge/wallet-skills). Setup is
   intended to take about five minutes. Add only the payment capability needed
   for the test and cap the transaction at EUR 1.00.
3. **You have no payment method.** You can still run independent discovery and
   stop before payment. Submit it as discovery-only. It will remain
   `NOT_VERIFIED` and cannot count as a completed commerce test.

Then:

1. Open [dothat.quest](https://dothat.quest/) and start the Official Quest.
2. Give your agent only the exact prompt and challenge values issued there.
3. For a commerce run, authorize the chosen payment method with a strict total
   cap of EUR 1.00.
4. Do not provide a merchant name, domain, URL, endpoint, product ID, checkout
   link or discovery hint.
5. Return the observable trace and agent result through the same quest and make
   the single required confirmation.
6. Share only the resulting public verification record.

Use any agent or framework capable of web discovery and a real purchase flow. Successful and unsuccessful attempts are both useful.

## Public results

The public record can show `PASS`, `FAIL` or `NOT_VERIFIED`; `PENDING` means processing is not complete. Missing transaction evidence or independent review never becomes a PASS. A completed attempt may remain `NOT_VERIFIED` while required review is pending.

Private traces, personal details, payment data, credentials, submission tokens and private evidence must never be posted on GitHub. To report an attempt, use the **Report a test run** issue form and include only the public record or Challenge ID.

Never paste a card number, CVC, wallet secret, API key, payment token or login
credential into dothat.quest evidence. Approve payment inside Stripe/Link or
Sponge Wallet. A payment counts only when a real positive charge is matched to
the challenge.

Created by **Nikola Mishev**. First announced in September 2026.

