/**
 * The per-call convention — the bytes one call signs.
 *
 * `FLOW.md` §5: *every call, no token.*
 *
 * ```
 * sig = sign( session ‖ nonce ‖ request digest )
 * ```
 *
 * This is a **service convention, not a format,** and `FLOW.md`'s "still open" says exactly
 * that: it belongs in the requirement as data, so a second service can state a different
 * one without a new credential format. Until it does, it lives here — in one place, so the
 * two sides cannot drift apart without both of them failing.
 *
 * The label in front is not decoration. A signature over `session ‖ nonce ‖ digest` alone
 * is a signature an attacker can solicit in another context and replay here. Prefixing the
 * domain makes that signature worthless anywhere else, for one line of cost.
 *
 * The nonce is in here for the same reason the challenge has one: **signing the session id
 * alone would be a replayable token.** The whole point of the design is that a captured
 * request is worth nothing.
 */

import { createHash } from "node:crypto";
import { canonicalize } from "@synthetism/credential";

/** What a call signature is about. Changing it invalidates every outstanding session. */
export const CALL_LABEL = "synthetism:rsa:call:v1";

/**
 * The digest of a request.
 *
 * Canonical, so both sides hash the same bytes whatever order the object was built in —
 * and so the hash is the receipt's `artifactHash`, which is the same value in the same
 * place for every implementation.
 */
export function digestOf(request: unknown): string {
  return createHash("sha256").update(canonicalize(request)).digest("hex");
}

/** The exact string a caller signs for one call. */
export function callSigningInput(call: {
  session: string;
  nonce: string;
  digest: string;
}): string {
  return [CALL_LABEL, call.session, call.nonce, call.digest].join("\n");
}
