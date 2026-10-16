/**
 * The composition — Bob's service and Alice's agent, built the same way everywhere.
 *
 * The by-hand scripts and the tests build from *here* so they cannot drift: if the funnel
 * the tests exercise is configured differently from the one you run in a terminal, the tests
 * are testing something nobody runs.
 */

import type { VerifiableCredential, AuthorizationSubject } from "@synthetism/vc";
import { openAgent, type Agent } from "./agent.js";
import { openFunnel, type Funnel } from "./funnel.js";
import type { Seeded } from "./seed.js";
import { openUpstream, type Upstream } from "./upstream.js";
import { openWallet } from "./stores.js";

/** The service's id. What the agent signs `aud` for, and what a lookalike cannot claim. */
export const SERVICE_AUD = "https://api.example.com";

export interface ServiceOverrides {
  /** Calls in the pool. Small by default, so "the meter is empty" is reachable by hand. */
  meters?: number;
  /** The upstream's key. Read at start, held by the funnel, and never handed to the agent. */
  upstreamKey?: string;
  /** What this funnel demands. Defaults to what the authorisation grants. */
  scope?: string[];
  /** How long a session lives. `0` makes it expired on arrival. */
  sessionSeconds?: number;
  /** The upstream itself, so a test can count what reached it. */
  upstream?: Upstream;
  now?: () => Date;
}

export async function bobService(
  seeded: Seeded,
  overrides: ServiceOverrides = {},
): Promise<Funnel> {
  const signer = await openWallet(seeded.bob.root).store.signer(seeded.bob.kid);

  return openFunnel({
    service: { did: seeded.bob.did, signer },
    aud: SERVICE_AUD,
    requirement: {
      name: "market-read",
      version: "1",
      pool: seeded.pool,
      scope: overrides.scope ?? seeded.scope,
    },
    // The one policy in the composition: this service accepts the issuers it trusts, and at
    // v1 that is itself. A reseller arrives as an entry in this list, not as a new check.
    issuers: [seeded.bob.did],
    meters: { [seeded.pool]: overrides.meters ?? 3 },
    upstream: overrides.upstream ?? openUpstream(),
    upstreamKey: overrides.upstreamKey ?? "upstream-key-that-nobody-else-sees",
    ...(overrides.sessionSeconds === undefined ? {} : { sessionSeconds: overrides.sessionSeconds }),
    ...(overrides.now === undefined ? {} : { now: overrides.now }),
  });
}

export async function aliceAgent(seeded: Seeded, url: string): Promise<Agent> {
  const signer = await openWallet(seeded.alice.root).store.signer(seeded.alice.kid);

  return openAgent({
    party: { did: seeded.alice.did, alias: seeded.alice.alias },
    signer,
    authorization: seeded.authorization as VerifiableCredential<AuthorizationSubject>,
    service: { url, aud: SERVICE_AUD },
  });
}
