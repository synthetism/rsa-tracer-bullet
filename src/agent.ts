/**
 * The agent — Alice's side. Ask, present, **check**, then call.
 *
 * The check is the half everyone forgets, and it is the whole reason the Authentication VC
 * exists. Two signatures, two directions: Alice proves control of the holder key with the
 * presentation, and the service proves control of the issuer key with this. Without the
 * second, Alice is talking to whoever answered — and a service cannot impersonate another
 * service, because it would have to hold that service's private key.
 *
 * The check is one comparison, and the pair is the one that cannot be confused:
 *
 *     authentication.issuer.id === authorization.issuer.id
 *
 * *The service that authenticated me is the service that authorised me.* Not the holder —
 * the holder is Alice, and comparing her to the service is comparing the wrong two parties.
 *
 * Nothing here holds a key. `ISigner` is all it ever gets, and all it can ask for.
 */

import { randomUUID } from "node:crypto";
import {
  type AuthorizationSubject,
  type ISigner,
  type ReceiptSubject,
  type VerifiableCredential,
  verify,
} from "@synthetism/vc";
import {
  type Challenge,
  type RequirementSubject,
  createUnsignedPresentation,
  present,
} from "@synthetism/vp";
import { callSigningInput, digestOf } from "./call.js";
import type { Admission, Balance, Outcome, Passage, Refusal, Refused } from "./funnel.js";
import type { MarketReceiptSubject } from "./receipt.js";

export interface AgentOptions {
  party: { did: string; alias: string };
  signer: ISigner;
  /** What Alice holds. She presents it; she does not ask for it again. */
  authorization: VerifiableCredential<AuthorizationSubject>;
  service: { url: string; aud: string };
  now?: () => Date;
}

export interface Agent {
  readonly did: string;
  readonly requirement: VerifiableCredential<RequirementSubject> | undefined;
  /** Ask what the service requires, and believe it only because the service signed it. */
  learn(): Promise<Outcome<VerifiableCredential<RequirementSubject>>>;
  /** Present, and check what comes back. */
  admit(): Promise<Outcome<Admission>>;
  /** One call: no token, a fresh nonce, a signature from the pinned key. */
  call(request: Record<string, unknown>): Promise<Outcome<Passage>>;
  /**
   * What is left in the session's pool.
   *
   * Exists because the balance is deliberately on no credential: what a pool holds is an agreement
   * between two parties, and a number that moves should not live inside a signed document. Ask
   * before you spend, and ask as often as you like — it bills nothing.
   */
  balance(): Promise<Outcome<Balance>>;
}

export function openAgent(options: AgentOptions): Agent {
  const clock = options.now ?? ((): Date => new Date());

  let requirement: VerifiableCredential<RequirementSubject> | undefined;
  let session: string | undefined;

  async function post(
    path: string,
    body: unknown,
  ): Promise<Outcome<Record<string, unknown>>> {
    const response = await fetch(`${options.service.url}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

    const parsed = (await response.json()) as Record<string, unknown>;

    if (response.ok) {
      return { ok: true, value: parsed };
    }

    return {
      ok: false,
      refusal: (parsed.refusal ?? "unverifiable") as Refusal,
      errors: Array.isArray(parsed.errors) ? (parsed.errors as string[]) : [String(parsed.error)],
      ...(parsed.receipt === undefined
        ? {}
        : { receipt: parsed.receipt as VerifiableCredential<MarketReceiptSubject> }),
      ...(parsed.requirement === undefined
        ? {}
        : {
            requirement: parsed.requirement as VerifiableCredential<RequirementSubject>,
          }),
    };
  }

  /** The refusal for every method that needs a session and has none. */
  function noSession(): Refused {
    return { ok: false, refusal: "session-gone", errors: ["no session — call `admit()` first"] };
  }

  /**
   * The signed envelope of one session call.
   *
   * A fresh nonce every time, and the signature is over the request itself — so nothing here is
   * reusable, and a captured request is worth nothing. `work` and `balance` share it because they
   * are the same envelope; only the request differs.
   */
  async function signedCall(
    request: Record<string, unknown>,
  ): Promise<{ session: string; nonce: string; request: Record<string, unknown>; sig: string } | undefined> {
    if (session === undefined) return undefined;

    const nonce = randomUUID();
    const digest = digestOf(request);
    const sig = await options.signer.sign(callSigningInput({ session, nonce, digest }));

    return { session, nonce, request, sig };
  }

  return {
    did: options.party.did,
    get requirement() {
      return requirement;
    },

    async learn() {
      const response = await fetch(`${options.service.url}/requirement`);
      if (!response.ok) {
        return {
          ok: false,
          refusal: "unverifiable" as Refusal,
          errors: [`the service published no requirement (${response.status})`],
        };
      }

      const published = (await response.json()) as VerifiableCredential<RequirementSubject>;

      // Signed, so it is worth believing — and checked against the service we bought from,
      // with the same comparison the handshake uses. A lookalike cannot talk Alice into
      // over-disclosure, because it cannot sign as the service that issued her authorisation.
      if (!verify(published).verified) {
        return {
          ok: false,
          refusal: "unverifiable" as Refusal,
          errors: ["the requirement does not verify"],
        };
      }
      if (published.issuer.id !== options.authorization.issuer.id) {
        return {
          ok: false,
          refusal: "unknown-issuer" as Refusal,
          errors: ["the requirement came from someone other than the service that authorised us"],
        };
      }

      requirement = published;
      return { ok: true, value: published };
    },

    async admit(): Promise<Outcome<Admission>> {
      const asked = await post("/challenge", { aud: options.service.aud });
      if (!asked.ok) return asked;

      const challenge = asked.value as unknown as Challenge;

      const unsigned = createUnsignedPresentation({
        holder: { id: options.party.did, name: options.party.alias },
        credentials: [options.authorization],
      });

      const { presentation } = await present(unsigned, options.signer, challenge, {
        now: clock(),
      });

      const admitted = await post("/admit", { vp: presentation });
      if (!admitted.ok) return admitted;

      const admission = admitted.value as unknown as Admission;

      // --- the half everyone forgets -------------------------------------------
      const verdict = verify(admission.authentication);
      if (!verdict.verified) {
        return {
          ok: false,
          refusal: "unverifiable",
          errors: ["the Authentication VC does not verify", ...verdict.errors],
        };
      }

      if (admission.authentication.issuer.id !== options.authorization.issuer.id) {
        return {
          ok: false,
          refusal: "unknown-issuer",
          errors: ["the service that answered is not the service that authorised us"],
        };
      }

      session = admission.session;
      return { ok: true, value: admission };
    },

    async call(request: Record<string, unknown>): Promise<Outcome<Passage>> {
      const signed = await signedCall(request);
      if (signed === undefined) return noSession();

      const worked = await post("/work", signed);
      if (!worked.ok) return worked;

      return { ok: true, value: worked.value as unknown as Passage };
    },

    async balance(): Promise<Outcome<Balance>> {
      const signed = await signedCall({ op: "balance" });
      if (signed === undefined) return noSession();

      const read = await post("/balance", signed);
      if (!read.ok) return read;

      return { ok: true, value: read.value as unknown as Balance };
    },
  };
}
