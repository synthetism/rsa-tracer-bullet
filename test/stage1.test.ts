/**
 * Stage 1 — the loop, by hand, observed rather than assumed.
 *
 * Every row in `STARTUP.md`'s acceptance table, and a few the table implies. **The failures
 * are the point**: a gate you have never seen refuse is a gate you do not know works, so most
 * of these assert a *refusal* and check that it is the refusal it claims to be.
 *
 * Two parties, seeded once per stage. Nothing here re-authorises anything — that is what the
 * fixed vaults are for.
 */

import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { didKeyFromPublicKey } from "@synthetism/did";
import { generateKeyPair, hexPrivateKeyToPem } from "@synthetism/keys";
import {
  type AuthorizationSubject,
  type ISigner,
  type VerifiableCredential,
  createUnsigned,
  issue,
} from "@synthetism/vc";
import { createUnsignedPresentation, present, type Challenge } from "@synthetism/vp";
import { validate } from "@synthetism/query";
import { ajvEngine } from "@synthetism/engine-ajv";
import { afterEach, describe, expect, it } from "vitest";
import { callSigningInput, digestOf } from "../src/call.js";
import { SERVICE_AUD, aliceAgent, bobService, type ServiceOverrides } from "../src/compose.js";
import { openFunnel } from "../src/funnel.js";
import { AUTHORIZED_SCOPE, POOL, type Seeded, seed } from "../src/seed.js";
import { type Running, startService } from "../src/service.js";
import { openWallet } from "../src/stores.js";
import type { Quote, Upstream } from "../src/upstream.js";

const UPSTREAM_KEY = "upstream-key-that-nobody-else-sees";
const scratch: string[] = [];
const services: Running[] = [];

afterEach(async () => {
  for (const service of services.splice(0)) await service.close();
  for (const directory of scratch.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function tempDir(): string {
  const directory = mkdtempSync(join(tmpdir(), "synthetism-rsa-"));
  scratch.push(directory);
  return directory;
}

/** Two seeded parties, a running service, and Alice pointed at it. */
async function stage(overrides: ServiceOverrides = {}) {
  const root = tempDir();
  const seeded = await seed(root);
  const funnel = await bobService(seeded, overrides);
  const service = await startService(funnel, { port: 0 });
  services.push(service);
  const agent = await aliceAgent(seeded, service.url);
  return { root, seeded, funnel, service, agent };
}

/** Alice's signer, for the rows that have to speak the wire without her client. */
async function aliceSigner(seeded: Seeded): Promise<ISigner> {
  return openWallet(seeded.alice.root).store.signer(seeded.alice.kid);
}

async function post(
  url: string,
  path: string,
  body: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(`${url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

async function challenge(url: string): Promise<Challenge> {
  const asked = await post(url, "/challenge", { aud: SERVICE_AUD });
  return asked.body as unknown as Challenge;
}

/** A presentation Alice builds against a challenge, carrying what she was given. */
async function presents(
  seeded: Seeded,
  challenged: Challenge,
  at?: Date,
  credentials: VerifiableCredential<AuthorizationSubject>[] = [seeded.authorization],
) {
  const signer = await aliceSigner(seeded);
  const unsigned = createUnsignedPresentation({
    holder: { id: seeded.alice.did, name: "alice" },
    credentials,
  });
  const { presentation } = await present(
    unsigned,
    signer,
    challenged,
    at === undefined ? {} : { now: at },
  );
  return presentation;
}

/** A stranger with a key, for the rows about somebody else's credential. */
function stranger(): { did: string; signer: ISigner } {
  const { privateKey, publicKey } = generateKeyPair("ed25519", { format: "hex" });
  const pem = hexPrivateKeyToPem(privateKey);
  if (pem === null) throw new Error("no pem");

  const key = createPrivateKey(pem);
  return {
    did: didKeyFromPublicKey(publicKey),
    signer: { sign: async (data: string) => nodeSign(null, Buffer.from(data), key).toString("base64url") },
  };
}

describe("the loop", () => {
  it("★ admits an agent that has no account, no password and no signup", async () => {
    const { agent, seeded } = await stage();

    const learned = await agent.learn();
    expect(learned.ok).toBe(true);

    const admitted = await agent.admit();
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;

    // The session id and the Authentication VC's id are the same identifier — one covering
    // the durable record and the runtime reference.
    expect(admitted.value.authentication.id).toBe(admitted.value.session);

    // It cites what it was opened under, which is what makes it auditable.
    expect(admitted.value.authentication.credentialSubject.authorizationId).toBe(
      seeded.authorizationId,
    );
    expect(admitted.value.authentication.credentialSubject.holder.id).toBe(seeded.alice.did);

    // Admission costs nothing: nothing has been called yet.
    expect(admitted.value.remaining).toBe(3);
  });

  it("carries the call through and receipts it", async () => {
    const { agent, seeded } = await stage();

    const admitted = await agent.admit();
    expect(admitted.ok).toBe(true);
    if (!admitted.ok) return;

    const called = await agent.call({ symbol: "ACME" });
    expect(called.ok).toBe(true);
    if (!called.ok) return;

    expect(called.value.data).toEqual([
      { symbol: "ACME", bid: 101.25, ask: 101.4, at: "2026-10-16T09:00:00.000Z" },
      { symbol: "ACME", bid: 101.1, ask: 101.3, at: "2026-10-16T09:01:00.000Z" },
    ]);
    expect(called.value.remaining).toBe(2);

    // The receipt is the *service's* shape, extending the base: the three fields every receipt
    // shares, plus what only this service can know.
    expect(called.value.receipt.credentialSubject).toMatchObject({
      holder: { id: seeded.alice.did },
      verdict: "honoured",
      pool: seeded.pool,
      units: 1,
    });
    expect(called.value.receipt.issuer.id).toBe(seeded.bob.did);

    // It cites the **artifact**, not the row — and they are the same string, which is the point:
    // the session id *is* the Authentication VC's `id`. The row dies at expiry; this does not.
    expect(called.value.receipt.credentialSubject.authenticationId).toBe(admitted.value.session);
  });

  it("reads the balance without billing anything", async () => {
    const { agent } = await stage({ meters: 3 });
    expect((await agent.admit()).ok).toBe(true);

    const before = await agent.balance();
    expect(before.ok).toBe(true);
    if (!before.ok) return;
    expect(before.value.remaining).toBe(3);

    expect((await agent.call({ symbol: "ACME" })).ok).toBe(true);

    const after = await agent.balance();
    if (!after.ok) return;
    expect(after.value.remaining).toBe(2);
  });

  it("decrements the meter once per call, and no more", async () => {
    const { agent } = await stage({ meters: 3 });
    expect((await agent.admit()).ok).toBe(true);

    expect((await agent.call({ symbol: "ACME" })).ok).toBe(true);
    const second = await agent.call({ symbol: "GLOBEX" });
    expect(second.ok).toBe(true);
    if (second.ok) expect(second.value.remaining).toBe(1);
  });
});

describe("the window", () => {
  it("★ refuses the same presentation a second time — a VP is single use", async () => {
    const { seeded, service } = await stage();

    const vp = await presents(seeded, await challenge(service.url));

    const first = await post(service.url, "/admit", { vp });
    expect(first.status).toBe(200);

    const again = await post(service.url, "/admit", { vp });
    expect(again.body.refusal).toBe("replayed");
    expect(again.status).toBe(409);
  });

  it("★ refuses a presentation addressed to another service", async () => {
    const { seeded, service } = await stage();

    // A challenge from *this* funnel, presented under a different `aud`. The nonce is ours;
    // the audience is not, and the presentation is worthless here.
    const ours = await challenge(service.url);
    const vp = await presents(seeded, { ...ours, aud: "https://somewhere.else.example" });

    const refused = await post(service.url, "/admit", { vp });
    expect(refused.body.refusal).toBe("unverifiable");
    expect(JSON.stringify(refused.body.errors)).toMatch(/aud .* is not this verifier/);
  });

  it("refuses a challenge addressed to another service", async () => {
    const { service } = await stage();

    const refused = await post(service.url, "/challenge", { aud: "https://lookalike.example" });
    expect(refused.status).toBe(400);
    expect(refused.body.refusal).toBe("not-this-service");

    // No receipt: nobody has identified themselves as anybody yet, and a receipt needs an
    // addressee. Inventing one would make it a lie about who was refused.
    expect(refused.body.receipt).toBeUndefined();
  });

  it("refuses a window that has already passed", async () => {
    const { seeded, service } = await stage();

    const vp = await presents(
      seeded,
      await challenge(service.url),
      new Date(Date.now() - 3_600_000),
    );

    const refused = await post(service.url, "/admit", { vp });
    expect(refused.body.refusal).toBe("expired");
  });
});

describe("what the credential says", () => {
  it("★ refuses a call the authorization does not cover, and receipts the refusal", async () => {
    const { seeded, service } = await stage({ scope: ["read", "write"] });

    const vp = await presents(seeded, await challenge(service.url));

    const refused = await post(service.url, "/admit", { vp });
    expect(refused.body.refusal).toBe("out-of-scope");
    expect(refused.status).toBe(403);

    // Refusals are products. This one is signed, says what did not happen, and is quotable
    // by the party it refused.
    const receipt = refused.body.receipt as
      | VerifiableCredential<{ verdict: string; authenticationId?: string }>
      | undefined;
    expect(receipt?.credentialSubject.verdict).toBe("breached");
    expect(receipt?.issuer.id).toBe(seeded.bob.did);

    // And it cites no authentication: nothing was opened. The base receipt does not imply one,
    // which is why `authenticationId` is optional on the service's extension.
    expect(receipt?.credentialSubject.authenticationId).toBeUndefined();

    // The refusal carries the requirement the caller should have built against. This is what
    // replaced the version echo: the request names no version, and the caller still learns —
    // because an old requirement does not make a request fail. A check does.
    const published = refused.body.requirement as {
      credentialSubject: {
        requirement: {
          version: string;
          parameters?: { scope?: string[] };
          requirements: Record<
            string,
            { match?: { type?: string; properties?: Record<string, unknown> } }
          >;
        };
      };
    };
    const requirement = published.credentialSubject.requirement;

    // The demanded scope is *declared* where a human reads it…
    expect(requirement.parameters?.scope).toEqual(["read", "write"]);

    // …and *enforced* where a validator reads it. This assertion used to demand
    // `match.scope` deep-equal `["read", "write"]`, which was asserting the bug: an array is
    // not a schema, so `scope` was an unknown keyword, ajv ignored it, and the requirement
    // accepted every credential offered. `match` must be a JSON Schema, and the tests below
    // check it from the accepting side.
    const match = requirement.requirements.authorization?.match;
    expect(match?.type).toBe("object");
    expect(Object.keys(match?.properties ?? {}).sort()).toEqual(["resource", "scope"]);
  });

  it("★ refuses an authorization edited after it was signed — by signature, not by a rule", async () => {
    const { seeded, service } = await stage();

    const widened = {
      ...seeded.authorization,
      credentialSubject: {
        ...seeded.authorization.credentialSubject,
        scope: ["read", "write"],
      },
    } as VerifiableCredential<AuthorizationSubject>;

    const vp = await presents(seeded, await challenge(service.url), undefined, [widened]);

    const refused = await post(service.url, "/admit", { vp });
    expect(refused.body.refusal).toBe("unverifiable");
    expect(JSON.stringify(refused.body.errors)).toMatch(/does not match the signed payload/);
  });

  it("★ refuses an issuer this service does not accept", async () => {
    const { seeded, service } = await stage();

    // Perfectly valid — signed by somebody the service has never heard of. The signature is
    // good, the binding is good, and it is still refused: this is the one check that is
    // *policy*, and it belongs to the service.
    const mallory = stranger();
    const { credential } = await issue(
      createUnsigned<AuthorizationSubject>({
        subject: { holder: { id: seeded.alice.did }, scope: ["read"], resource: seeded.pool },
        type: "AuthorizationCredential",
        issuer: { id: mallory.did, name: "mallory" },
      }),
      mallory.signer,
    );

    const vp = await presents(seeded, await challenge(service.url), undefined, [credential]);

    const refused = await post(service.url, "/admit", { vp });
    expect(refused.body.refusal).toBe("unknown-issuer");
  });

  it("refuses when the pool has nothing left, without calling upstream", async () => {
    let asked = 0;
    const counted: Upstream = {
      name: "counted",
      async quotes(): Promise<Quote[]> {
        asked += 1;
        return [];
      },
    };

    const { agent } = await stage({ meters: 0, upstream: counted });

    const admitted = await agent.admit();
    expect(admitted.ok).toBe(false);
    if (!admitted.ok) expect(admitted.refusal).toBe("meter-empty");

    expect(asked).toBe(0);
  });
});

describe("the call", () => {
  it("★ refuses a spent nonce — signing the session id alone would be a replayable token", async () => {
    const { agent, seeded, service } = await stage();
    expect((await agent.admit()).ok).toBe(true);

    // Alice signs one call by hand, and sends it twice.
    const signer = await aliceSigner(seeded);
    const admitted = await agent.admit();
    if (!admitted.ok) throw new Error("expected a second admission to fail — a spent nonce");

    const nonce = randomUUID();
    const request = { symbol: "GLOBEX" };
    const digest = digestOf(request);
    const sig = await signer.sign(
      callSigningInput({ session: admitted.value.session, nonce, digest }),
    );

    const first = await post(service.url, "/work", {
      session: admitted.value.session,
      nonce,
      request,
      sig,
    });
    expect(first.status).toBe(200);

    const again = await post(service.url, "/work", {
      session: admitted.value.session,
      nonce,
      request,
      sig,
    });
    expect(again.body.refusal).toBe("replayed");
  });

  it("★ refuses a session that is gone, with no receipt for a caller it cannot name", async () => {
    const { seeded, service } = await stage();
    const signer = await aliceSigner(seeded);

    const refused = await post(service.url, "/work", {
      session: randomUUID(),
      nonce: randomUUID(),
      request: { symbol: "ACME" },
      sig: await signer.sign("anything"),
    });

    expect(refused.body.refusal).toBe("session-gone");
    expect(refused.body.receipt).toBeUndefined();
  });

  it("refuses a session that has expired", async () => {
    const { seeded, service } = await stage({ sessionSeconds: 0 });

    const vp = await presents(seeded, await challenge(service.url));
    const admitted = await post(service.url, "/admit", { vp });
    expect(admitted.status).toBe(200);

    const session = admitted.body.session as string;
    const signer = await aliceSigner(seeded);
    const nonce = randomUUID();
    const request = { symbol: "ACME" };

    const refused = await post(service.url, "/work", {
      session,
      nonce,
      request,
      sig: await signer.sign(
        callSigningInput({ session, nonce, digest: digestOf(request) }),
      ),
    });

    expect(refused.body.refusal).toBe("session-gone");
    expect(JSON.stringify(refused.body.errors)).toMatch(/expired/);
  });

  it("★ a captured presentation admits, and the session is worthless without the key", async () => {
    const { seeded, service } = await stage();

    const vp = await presents(seeded, await challenge(service.url));

    // The attacker has the presentation — a valid one, correctly signed by Alice. It admits:
    // a VP is a signature over bytes, and a captured one is presentable. That is *expected*.
    const stolen = await post(service.url, "/admit", { vp });
    expect(stolen.status).toBe(200);

    const session = stolen.body.session as string;

    // And it buys them nothing, because the session is pinned to Alice's key. The thief can
    // present a stolen credential; they cannot sign for it.
    const thief = stranger();
    const nonce = randomUUID();
    const request = { symbol: "ACME" };

    const refused = await post(service.url, "/work", {
      session,
      nonce,
      request,
      sig: await thief.signer.sign(
        callSigningInput({ session, nonce, digest: digestOf(request) }),
      ),
    });

    expect(refused.body.refusal).toBe("bad-call");
    expect(JSON.stringify(refused.body.errors)).toMatch(/pinned in the session/);
  });
});

describe("the boundary", () => {
  it("★ never lets the upstream key reach the agent", async () => {
    const { agent } = await stage({ upstreamKey: UPSTREAM_KEY });
    expect((await agent.admit()).ok).toBe(true);

    const called = await agent.call({ symbol: "ACME" });
    expect(called.ok).toBe(true);

    // Nothing the agent received — not the admission, not the data, not the receipt — carries
    // the service's credential for the upstream.
    const heard = JSON.stringify(called);
    expect(heard).not.toContain(UPSTREAM_KEY);
    expect(heard).not.toContain("upstream-key");
  });

  it("★ refuses a service that is not the one that authorised us", async () => {
    const { seeded, service } = await stage();

    // A lookalike: it speaks the same protocol, accepts Bob's authorisations, and answers at
    // the same `aud`. Everything about it is right except whose key it holds.
    const impostor = stranger();
    const rogue = openFunnel({
      service: { did: impostor.did, signer: impostor.signer },
      aud: SERVICE_AUD,
      requirement: { name: "market-read", version: "1", pool: seeded.pool, scope: seeded.scope },
      issuers: [seeded.bob.did],
      meters: { [seeded.pool]: 3 },
      upstream: { name: "none", quotes: async () => [] },
      upstreamKey: "irrelevant",
    });

    const rogueService = await startService(rogue, { port: 0 });
    services.push(rogueService);

    const wronged = await aliceAgent(seeded, rogueService.url);
    const refused = await wronged.admit();

    // Alice refuses it herself. She never needed the real service to tell her — she compared
    // the issuer against the one on her own authorization. **A service cannot impersonate
    // another service: it would have to hold that service's private key.**
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.refusal).toBe("unknown-issuer");
      expect(refused.errors.join(" ")).toMatch(/not the service that authorised us/);
    }

    // And the real service is untouched by any of it.
    expect((await post(service.url, "/challenge", { aud: SERVICE_AUD })).status).toBe(200);
  });

  it("publishes its requirement, signed, before anything is presented", async () => {
    const { service, seeded } = await stage();

    const published = (await (await fetch(`${service.url}/requirement`)).json()) as {
      issuer: { id: string };
      credentialSubject: { requirement: { name: string; version: string } };
    };

    expect(published.issuer.id).toBe(seeded.bob.did);
    expect(published.credentialSubject.requirement.name).toBe("market-read");
  });

  it("★ publishes a `match` that is a schema, and it refuses the wrong pool", async () => {
    const { service, seeded } = await stage();
    const published = await (await fetch(`${service.url}/requirement`)).json();

    // `validate` is subject-blind — it judges type, holder and `match`, and verification of
    // proofs is `@synthetism/vp`'s job. So these are plain parsed JSON, which is also what
    // the generic signature is for.
    const authorization = (resource: string, scope: string[]) => ({
      type: ["VerifiableCredential", "AuthorizationCredential"],
      credentialSubject: { holder: { id: seeded.alice.did }, scope, resource },
    });

    const judge = (credential: unknown) =>
      validate({
        document: published,
        credentials: [credential],
        holder: seeded.alice.did,
        engine: ajvEngine(),
      });

    // What Alice actually holds passes.
    expect(judge(authorization(POOL, AUTHORIZED_SCOPE))).toEqual({ ok: true, failures: [] });

    // Everything below used to **pass**, because the published `match` was
    // `{ scope: [...], resource: "..." }` — an array where a schema belongs. `scope` was
    // then an unknown keyword, ajv ignored it, and the requirement accepted whatever it was
    // offered. A requirement that accepts anything demands nothing, so these assertions are
    // the ones that keep the requirement honest.
    const wrongPool = judge(authorization("https://api.example.com/elsewhere", AUTHORIZED_SCOPE));
    expect(wrongPool.ok).toBe(false);
    expect(wrongPool.failures.map((failure) => failure.reason)).toEqual(["not-a-match"]);

    const noScope = judge(authorization(POOL, []));
    expect(noScope.ok).toBe(false);
    expect(noScope.failures.map((failure) => failure.reason)).toEqual(["not-a-match"]);

    const emptySubject = judge({
      type: ["VerifiableCredential", "AuthorizationCredential"],
      credentialSubject: { holder: { id: seeded.alice.did } },
    });
    expect(emptySubject.ok).toBe(false);
  });
});
