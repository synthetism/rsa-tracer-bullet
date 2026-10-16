# The RSA tracer bullet — the loop, by hand

**One service, one agent that has never signed up, and no shared secret anywhere.** An agent with no
account is admitted, attributed and metered, and every refusal is a receipted artifact rather than a
log line.

Not a product. A test harness that happens to speak HTTP — the funnel here is ~300 lines because
the hard part is already in the packages.

**This repository is frozen.** It is evidence of what was believed in October 2026, not a codebase to
improve — the loop it proves is the product, and the product is many parts working together. Findings
do not land here; they go to `rsa/PRODUCT-SPEC.md` in `private-docs`.

## Run it

Two terminals. Bob first.

```bash
npm install
npm run build

# one terminal
node dist/service-cli.js --root .rsa --port 8099 --meters 3

# another
node dist/alice.js --root .rsa --url http://127.0.0.1:8099 --symbol ACME
```

```
alice  did:key:z6MkoHAwme8rqYgVy5txajbKyW1wTGSkvQvt2Pwi3C3qdfAz
  → asking http://127.0.0.1:8099 what it requires
  ✓ market-read v1, signed by the service — did:key:z6MksZJeG2YPq1i5kb5wGUdASSodv53MhiR1neECA1BdVumn
  → presenting the authorization
  ✓ session           c2bd1cbc-b927-4dfd-b594-2cc114ef0d7e
  ✓ authentication    c2bd1cbc-b927-4dfd-b594-2cc114ef0d7e
  ✓ its issuer is the service that authorised us — the handshake holds
  → asking the pool what is left
  ✓ balance           3 call(s) in https://api.example.com/market
  → calling /work for ACME
  ✓ data              [{"symbol":"ACME","bid":101.25,"ask":101.4,"at":"2026-10-16T09:00:00.000Z"},
                       {"symbol":"ACME","bid":101.1,"ask":101.3,"at":"2026-10-16T09:01:00.000Z"}]
  ✓ receipt           urn:credential:receipt-credential:6011443f5551f29f625e5cad
                      verdict honoured
  2 call(s) left in the pool
```

**Two parties, two roots.** `.rsa/alice/{keys,vault}` and `.rsa/bob/{keys,vault}`. Alice's process
holds nothing of Bob's, and Bob's holds nothing of Alice's. Neither has a password, a token, or an
account, and the private keys never leave `0700` folders of `0600` files.

## Two fixed vaults, seeded once

```bash
node dist/seed-cli.js .rsa
```

The keys are **derived from labels**, so the DIDs are stable and the Authorisation VC is issued
**once**. Run `seed` again and you get the same two DIDs and the same credential — nothing is
reissued. That is not a test convenience, it is the shape of a credential: an authorisation is
bought, and buying it again is a new authorisation, not a repeat of the old one.

A derived key is a fixture and not a pretence of a secret — the material is reproducible from a
string in `src/seed.ts`, so committing the seed commits nothing. A real party calls
`IKeyStore.create` and never knows its key at all.

## What the service requires, before it will look at anything

`GET /requirement` returns the **VP Language**, signed by the service that will enforce it — so a
caller learns what is needed *from the party that will check it*, and a lookalike cannot talk an
agent into over-disclosure. Alice verifies it against the issuer on her own authorisation.

## The handshake, in the order it happens

```
1  Alice ──► GET /requirement          signed data, checked against her own authorization
2  Alice ──► POST /challenge { aud }   the window is ours: nonce, expiresIn
3  Alice ──► present()                 her key, her authorization, inside our window
4  Alice ──► POST /admit { vp }         five checks, cheapest first
5  Bob   ──► session + Authentication VC + the same id in both
6  Alice ──► verify(authentication)    ← and compares its issuer to her authorization's
7  Alice ──► POST /balance             what is left — and it bills nothing
8  Alice ──► POST /work { session, nonce, request, sig }    no token, ever
9  Bob   ──► data + receipt
```

**Step 5 issues no receipt and moves no counter.** Nothing has been called, so there is nothing to
receipt, and a receipt for a call that did not happen would be a lie the service signed.

**Step 6 is the half everyone forgets.** Bob proves control of the issuer key; Alice proves control
of the holder key. A service cannot impersonate another service — it would have to hold that
service's private key — and the test suite proves it by standing up a lookalike that speaks the
whole protocol and watching Alice refuse it.

The comparison is this one, and only this one:

```ts
authentication.issuer.id === authorization.issuer.id
```

Not against `holder`: the holder is Alice, so that comparison is `BobDID === AliceDID`. An
authorisation names two parties, and "the service that authenticated me is the service that
authorised me" compares the two issuers.

## Every call, no token

`FLOW.md` §5, and it is the point of the whole design. Nothing reusable crosses the wire:

```
sig = sign( "synthetism:rsa:call:v1" ‖ session ‖ nonce ‖ sha256(canonical(request)) )
```

The session id is a **name**, and it authorises nothing on its own. The nonce is single-use. The
signature is checked against the key **pinned at admission** — never against a key the caller
offers now, or "verify the signature" becomes "verify *a* signature".

That is why a stolen presentation is survivable, and there is a test that proves it: a captured VP
*admits* — it is a valid signature over bytes, and a captured one is presentable — and the session
it opens is worthless to the thief, because they cannot sign for Alice's key.

## The boundary

The funnel fronts a market API that has never heard of credentials. It takes an API key, exactly as
it does today, and **it is not changed**. The funnel holds that key, reads it at start, and never
puts it in a credential, a receipt, a response or a log. A test asserts that nothing the agent
receives contains it.

## What this is not

- **No lease.** The session row is the session; the runtime token is Stage 3.
- **No `driver-meter`.** The meter is a plain counter in the funnel. It consumes *after* a
  successful call, which oversells under concurrency — that is exactly what `P4`'s atomic
  `reserve → call → settle` replaces.
- **No MCP, no buyer of last resort.** Those are Stages 2 and 4.
- **No version echo.** The requirement is published and versioned, and a request names no version —
  deliberately. An old requirement does not make a request fail; a *check* does. So a refusal carries
  the requirement being enforced *now*, and the caller re-reads the contract from the refusal instead
  of having to ask for it separately.
- **No balance on the authorisation.** `/balance` answers it on the open session, because a balance is
  a number that moves and a credential is a document signed once. What a call *costs* is the
  service's policy — `meters` is service configuration here, and a service may have no meter at all.

## Tests

```bash
npm test
```

Nineteen rows, and most of them assert a **refusal** — a gate you have never seen refuse is a gate
you do not know works.
