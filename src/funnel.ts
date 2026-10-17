/**
 * The funnel — the gate. Bob's side, and the only component that must refuse.
 *
 * Five checks, cheapest first, network last. In `SPEC.md` §3 the ordering matters because
 * the last one is a network call; here nothing is, and the honest reason is worth writing
 * down: **`did:key` resolves offline**, so "issuer is trusted" is an allowlist lookup until
 * an issuer needs a document over the wire. The ordering is kept anyway, because the day a
 * `did:web` issuer arrives is the day it starts paying for itself.
 *
 * Two of the checks read a document **nobody has verified yet**. That is deliberate and it
 * is safe: they can only ever cause an early *refusal*, never an admission. Verification
 * still runs in full below, and it is the only thing that can let a presentation through.
 * A tampered document can therefore cause a false refusal — fail-closed, which is the
 * direction a refusal should fail in.
 *
 * The funnel holds the upstream credential. It reads it at start, never logs it, and never
 * puts it in a credential, a receipt or a response. That is what "the funnel is a boundary"
 * means, and the tests assert it rather than trusting it.
 */

import { randomUUID } from "node:crypto";
import { publicKeyFromDidKey } from "@synthetism/did";
import { hexToPem, verifyEd25519 } from "@synthetism/keys";
import { type RequirementSubject, createRequirement } from "@synthetism/query";
import {
  type AuthenticationSubject,
  type AuthorizationSubject,
  type ISigner,
  type ReceiptSubject,
  type VerifiableCredential,
  type VerifiablePresentation,
  createUnsigned,
  decodeCredential,
  issue,
} from "@synthetism/vc";
import { type Challenge, verifyPresentation } from "@synthetism/vp";
import { callSigningInput, digestOf } from "./call.js";
import type { MarketReceiptSubject } from "./receipt.js";
import type { Upstream } from "./upstream.js";

/** Why a request was refused. Distinguishable on purpose — a refusal is a product surface. */
export type Refusal =
  | "not-this-service"
  | "no-challenge"
  | "replayed"
  | "expired"
  | "out-of-scope"
  | "meter-empty"
  | "unverifiable"
  | "unknown-issuer"
  | "session-gone"
  | "bad-call";

/**
 * A refusal — a product surface, not an error string.
 *
 * `requirement` is attached when the refusal is *about what was offered*, so the caller has what
 * it needs to rebuild instead of asking again. That is what replaced the version echo: an old
 * requirement does not make a request fail, a **check** does, so the refusal carries the
 * requirement and the request does not have to carry a version it cannot use.
 */
export interface Refused {
  ok: false;
  refusal: Refusal;
  errors: string[];
  requirement?: VerifiableCredential<RequirementSubject>;
  receipt?: VerifiableCredential<MarketReceiptSubject>;
}

export type Outcome<T> = { ok: true; value: T } | Refused;

export interface Admission {
  /** The session id — and the Authentication VC's `id`, so one identifier does both jobs. */
  session: string;
  authentication: VerifiableCredential<AuthenticationSubject>;
  /** What is left in the pool. Admission costs nothing: nothing has been called yet. */
  remaining: number;
}

export interface Passage {
  data: unknown;
  receipt: VerifiableCredential<MarketReceiptSubject>;
  remaining: number;
}

/** What is left in a session's pool. Asked for, never carried on the credential. */
export interface Balance {
  session: string;
  pool: string;
  remaining: number;
}

/** What this funnel demands, before it will look at anything. */
export interface Requirement {
  name: string;
  version: string;
  /** The metered thing. One meter per pool. */
  pool: string;
  /** What the authorisation must cover. A subset is not enough. */
  scope: string[];
}

export interface FunnelOptions {
  /** The service's own identity, and the signer that speaks for it. */
  service: { did: string; signer: ISigner };
  /** The id the agent expects. A presentation for another funnel is worthless here. */
  aud: string;
  requirement: Requirement;
  /** Issuers this service accepts. The trust ladder, and the only policy in the file. */
  issuers: string[];
  /** Balance per pool. */
  meters: Record<string, number>;
  upstream: Upstream;
  /** The upstream's key — read at start, never returned. */
  upstreamKey: string;
  /** The channel width, in seconds. Ours to choose; never the presenter's. */
  expiresIn?: number;
  /**
   * How long a session lives, in seconds.
   *
   * Shorter than the authorization on purpose, and never equal to it — the lease's life is
   * not the authorization's life, and making them equal recreates the long-lived bearer
   * token this design exists to remove.
   */
  sessionSeconds?: number;
  now?: () => Date;
}

export interface Call {
  session: string;
  nonce: string;
  request: Record<string, unknown>;
  sig: string;
}

export interface Funnel {
  readonly aud: string;
  /** The VP Language, signed. Published before anything is presented. */
  requirement(): Promise<VerifiableCredential<RequirementSubject>>;
  challenge(aud: string): Outcome<Challenge>;
  /** A presentation in, a session out. */
  admit(vp: VerifiablePresentation): Promise<Outcome<Admission>>;
  /** One call: no token, a fresh signature, one nonce spent. */
  work(call: Call): Promise<Outcome<Passage>>;
  /**
   * What is left in this session's pool.
   *
   * A **read**, and it exists because the balance is not on any credential: what a pool holds is
   * an agreement between two parties that can change without either reissuing anything. It spends
   * a nonce like any other call and bills nothing, so ask as often as you like.
   */
  balance(call: Call): Promise<Outcome<Balance>>;
}

/** The session row. It *is* the session — key, scope, expiry and meter alike. */
interface Session {
  /** The key this session is pinned to. Fixed at admission, never renegotiated. */
  kid: string;
  holder: string;
  authorizationId: string;
  scope: string[];
  pool: string;
  expiresAt: number;
  /** Nonces spent on this session. The replay guard, and why a call is one-shot. */
  seen: Set<string>;
}

interface IssuedChallenge {
  aud: string;
  issuedAt: number;
  expiresIn: number;
  used: boolean;
}

const DEFAULT_EXPIRES_IN = 120;
const DEFAULT_SESSION_SECONDS = 600;

export function openFunnel(options: FunnelOptions): Funnel {
  const clock = options.now ?? ((): Date => new Date());
  const expiresIn = options.expiresIn ?? DEFAULT_EXPIRES_IN;
  const sessionSeconds = options.sessionSeconds ?? DEFAULT_SESSION_SECONDS;
  const challenges = new Map<string, IssuedChallenge>();
  const sessions = new Map<string, Session>();
  const meters: Record<string, number> = { ...options.meters };

  let requirement: VerifiableCredential<RequirementSubject> | undefined;

  /**
   * The requirement, built once.
   *
   * Hoisted out of the returned object because a refusal needs it: when the refusal is about
   * *what was offered*, the caller gets the requirement it should have built against.
   */
  async function ensureRequirement(): Promise<VerifiableCredential<RequirementSubject>> {
    if (requirement !== undefined) return requirement;

    // It is **data**, and it is signed by the service that will enforce it — so the caller is
    // told what is needed by the party that will check it, and a lookalike cannot talk an agent
    // into over-disclosure.
    //
    // The **envelope** is `createRequirement`'s job, and that includes the language address.
    // This service supplies what it demands and its own revision; it never names the address,
    // because the only version it has to hand is the wrong one.
    const unsigned = createRequirement({
      name: options.requirement.name,
      version: options.requirement.version,
      parameters: {
        pool: options.requirement.pool,
        scope: options.requirement.scope,
      },
      requirements: {
        authorization: {
          type: "AuthorizationCredential",
          required: true,
          match: {
            scope: options.requirement.scope,
            resource: options.requirement.pool,
          },
        },
      },
      issuer: { id: options.service.did },
    });

    requirement = (await issue(unsigned, options.service.signer)).credential;
    return requirement;
  }

  /** A refusal, receipted when there is somebody to make the receipt out to. */
  async function refuse(
    refusal: Refusal,
    errors: string[],
    holder?: string,
    authenticationId?: string,
  ): Promise<Refused> {
    const refused: Refused = {
      ok: false,
      refusal,
      errors,
      // Attached when the refusal is about *what was offered*, so the caller can rebuild without
      // asking again. An old requirement does not make a request fail — a check does — which is
      // why the refusal carries the requirement and the request carries no version.
      ...(refusal === "out-of-scope" ? { requirement: await ensureRequirement() } : {}),
    };

    // No receipt without a counterparty. Before the presentation nobody has said who they are,
    // and a receipt made out to an invented recipient is worse than no receipt at all.
    if (holder === undefined) return refused;

    // A refusal is an artifact, not a log line: it is signed, it says what did not happen, and it
    // is quotable by the party it refused. `breached` because that is the truth — it did not happen.
    return {
      ...refused,
      receipt: await mintReceipt({
        holder,
        artifactHash: digestOf({ refusal, errors }),
        verdict: "breached",
        pool: options.requirement.pool,
        ...(authenticationId === undefined ? {} : { authenticationId }),
      }),
    };
  }

  async function mintReceipt(args: {
    /** A DID. The receipt is made out to the party, and a bare string is not a party. */
    holder: string;
    artifactHash: string;
    verdict: ReceiptSubject["verdict"];
    pool: string;
    authenticationId?: string;
    units?: number;
  }): Promise<VerifiableCredential<MarketReceiptSubject>> {
    const { credential } = await issue(
      createUnsigned<MarketReceiptSubject>({
        subject: {
          holder: { id: args.holder },
          artifactHash: args.artifactHash,
          verdict: args.verdict,
          pool: args.pool,
          ...(args.authenticationId === undefined
            ? {}
            : { authenticationId: args.authenticationId }),
          ...(args.units === undefined ? {} : { units: args.units }),
        },
        type: "ReceiptCredential",
        issuer: { id: options.service.did },
      }),
      options.service.signer,
    );

    return credential;
  }

  /**
   * The shared front of every session call.
   *
   * The row, the clock, the nonce, the pinned key, the signature. `work` and `balance` differ
   * only in what happens *after* this, and putting it here is what stops the two from drifting
   * into two different ideas of what a session call is.
   */
  async function verifyCall(
    call: Call,
  ): Promise<{ ok: true; row: Session; digest: string } | Refused> {
    const row = sessions.get(call.session);

    if (row === undefined) {
      // No receipt: a session that is gone has no holder we can trust, and the id may be one we
      // never issued. A refusal addressed to an invented recipient is worse than none.
      return {
        ok: false,
        refusal: "session-gone",
        errors: ["no such session — it expired, or its row was deleted"],
      };
    }

    if (row.expiresAt <= epoch(clock())) {
      // Revocation is one operation: delete the row and the session is dead. This is the same
      // thing, arriving on its own.
      sessions.delete(call.session);
      return refuse("session-gone", ["the session expired"], row.holder, call.session);
    }

    if (row.seen.has(call.nonce)) {
      return refuse("replayed", ["that nonce is spent — sign a fresh one"], row.holder, call.session);
    }

    const pinned = hexToPem(row.kid, "ed25519");
    if (pinned === null) {
      return refuse("bad-call", ["the session's pinned key is not usable"], row.holder, call.session);
    }

    const digest = digestOf(call.request);
    const signed = callSigningInput({ session: call.session, nonce: call.nonce, digest });

    if (!verifyEd25519(signed, call.sig, pinned)) {
      // Against the key pinned in the session — never against a key the caller offers now, or
      // "verify the signature" becomes "verify *a* signature".
      return refuse(
        "bad-call",
        ["the signature does not verify against the key pinned in the session"],
        row.holder,
        call.session,
      );
    }

    row.seen.add(call.nonce);
    return { ok: true, row, digest };
  }

  function epoch(when: Date): number {
    return Math.floor(when.getTime() / 1000);
  }

  function firstAuthorization(
    vp: VerifiablePresentation,
  ): VerifiableCredential<AuthorizationSubject> | undefined {
    const carried = Array.isArray(vp?.verifiableCredential) ? vp.verifiableCredential : [];
    return carried.find(
      (credential): credential is VerifiableCredential<AuthorizationSubject> =>
        Array.isArray((credential as { type?: unknown }).type) &&
        ((credential as { type: string[] }).type.includes("AuthorizationCredential")),
    );
  }

  return {
    aud: options.aud,
    requirement: ensureRequirement,

    challenge(aud: string): Outcome<Challenge> {
      if (aud !== options.aud) {
        // No receipt: the caller has not identified itself as anybody, and a receipt needs an
        // addressee. This is the one refusal that is only an error.
        return { ok: false, refusal: "not-this-service", errors: [`aud is not ${options.aud}`] };
      }

      const nonce = randomUUID();
      challenges.set(nonce, {
        aud,
        issuedAt: epoch(clock()),
        expiresIn,
        used: false,
      });

      return { ok: true, value: { aud, nonce, expiresIn } };
    },

    async admit(vp: VerifiablePresentation): Promise<Outcome<Admission>> {
      const holder =
        typeof vp?.holder?.id === "string" && vp.holder.id !== "" ? vp.holder.id : undefined;

      // --- 1. the challenge -----------------------------------------------------
      const claims = decodeCredential(vp)?.payload;
      const nonce = typeof claims?.nonce === "string" ? claims.nonce : undefined;
      const issued = nonce === undefined ? undefined : challenges.get(nonce);

      if (issued === undefined) {
        return refuse("no-challenge", ["not a nonce this service issued"], holder);
      }
      if (issued.used) {
        return refuse("replayed", ["that nonce has already been presented"], holder);
      }
      if (typeof claims?.exp !== "number" || epoch(clock()) > claims.exp) {
        return refuse("expired", ["the window has passed"], holder);
      }

      // --- 2. scope -------------------------------------------------------------
      const carried = firstAuthorization(vp);
      if (carried === undefined) {
        return refuse(
          "unverifiable",
          ["the presentation carries no AuthorizationCredential"],
          holder,
        );
      }

      const granted = Array.isArray(carried.credentialSubject?.scope)
        ? carried.credentialSubject.scope
        : [];
      const missing = options.requirement.scope.filter((term) => !granted.includes(term));
      if (missing.length > 0) {
        return refuse(
          "out-of-scope",
          [`the authorization does not cover ${missing.join(", ")}`],
          holder,
        );
      }

      // --- 3. the meter, before any crypto -------------------------------------
      const remaining = meters[options.requirement.pool] ?? 0;
      if (remaining <= 0) {
        return refuse(
          "meter-empty",
          [`the pool ${options.requirement.pool} has nothing left`],
          holder,
        );
      }

      // --- 4. the signature chain -----------------------------------------------
      const verdict = verifyPresentation(vp, {
        challenge: {
          aud: options.aud,
          nonce: nonce as string,
          expiresIn: issued.expiresIn,
          issuedAt: issued.issuedAt,
        },
        now: clock(),
      });

      if (!verdict.verified) {
        return refuse("unverifiable", verdict.errors, holder);
      }

      // --- 5. the issuer, last, and the only check that is policy ---------------
      if (!options.issuers.includes(carried.issuer.id)) {
        return refuse(
          "unknown-issuer",
          [`${carried.issuer.id} is not an issuer this service accepts`],
          holder,
        );
      }

      // --- admitted -------------------------------------------------------------
      // The nonce is spent **here**, on admission rather than on receipt of the document.
      // A presentation that fails verification is not admitted, so it does not burn the
      // agent's nonce — and a replayed one that *is* valid is caught on the second sighting,
      // which is the only place the replay guard can catch it.
      issued.used = true;

      // The pinned key comes from the DID the presentation is bound to, so it is the key the
      // holder proved control of — not a key the caller offers later. `did:key` embeds it.
      let kid: string;
      try {
        kid = publicKeyFromDidKey(vp.holder.id);
      } catch {
        return refuse("unverifiable", ["the holder's DID embeds no usable key"], holder);
      }

      const session = randomUUID();
      const scope = [...granted];
      const expiresAt = epoch(clock()) + sessionSeconds;

      sessions.set(session, {
        kid,
        holder: vp.holder.id,
        authorizationId: carried.id,
        scope,
        pool: options.requirement.pool,
        expiresAt,
        seen: new Set(),
      });

      const { credential: authentication } = await issue(
        createUnsigned<AuthenticationSubject>({
          subject: { holder: { id: vp.holder.id }, authorizationId: carried.id, scope },
          type: "AuthenticationCredential",
          issuer: { id: options.service.did },
          id: session,
          validity: { until: new Date(expiresAt * 1000).toISOString() },
        }),
        options.service.signer,
      );

      return { ok: true, value: { session, authentication, remaining } };
    },

    async work(call: Call): Promise<Outcome<Passage>> {
      const verified = await verifyCall(call);
      if (!verified.ok) return verified;

      const { row, digest } = verified;
      const symbol = typeof call.request.symbol === "string" ? call.request.symbol : undefined;
      if (symbol === undefined) {
        return refuse("bad-call", ["the request names no symbol"], row.holder, call.session);
      }

      const remaining = meters[row.pool] ?? 0;
      if (remaining <= 0) {
        return refuse(
          "meter-empty",
          [`the pool ${row.pool} has nothing left`],
          row.holder,
          call.session,
        );
      }

      let data: unknown;
      try {
        // The only place the upstream key appears, and the only place it can. The agent sent a
        // signed request; it never sent a credential of ours, and it never sees ours.
        data = await options.upstream.quotes({ symbol }, options.upstreamKey);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        // Consume-last: a failed call is not billed. Under concurrency that oversells, which is
        // why `P4` replaces this with reserve → call → settle and an atomic `consume`.
        return refuse("bad-call", [message], row.holder, call.session);
      }

      meters[row.pool] = remaining - 1;

      const receipt = await mintReceipt({
        holder: row.holder,
        artifactHash: digest,
        verdict: "honoured",
        pool: row.pool,
        // The **artifact**, not the row: the session id *is* the Authentication VC's `id`, and
        // the row is deleted at expiry while the credential is not. A receipt has to outlive
        // its session, so it points at the thing that survives.
        authenticationId: call.session,
        units: 1,
      });

      return { ok: true, value: { data, receipt, remaining: remaining - 1 } };
    },

    async balance(call: Call): Promise<Outcome<Balance>> {
      const verified = await verifyCall(call);
      if (!verified.ok) return verified;

      const { row } = verified;

      // A read. No upstream call, no units, and no receipt — nothing happened to make one out
      // about, and a receipt for a question would be noise in the audit trail.
      return {
        ok: true,
        value: { session: call.session, pool: row.pool, remaining: meters[row.pool] ?? 0 },
      };
    },
  };
}
