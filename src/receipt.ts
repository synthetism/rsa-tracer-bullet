/**
 * The receipt **this** service issues.
 *
 * `ReceiptSubject` is the base every receipt shares — three fields, true anywhere. This is the
 * extension: what the market service adds, because it is the only party that can know it.
 *
 * Naming it after the **service** rather than a party is deliberate. A receipt is a service's
 * artifact; `${service}ReceiptSubject` is the pattern, and any other service writes its own.
 */

import type { ReceiptSubject } from "@synthetism/vc";

export interface MarketReceiptSubject extends ReceiptSubject {
  /**
   * The authentication this was made under — **when there was one**.
   *
   * Written as the *artifact* and not the row, even though the same string names both: the
   * session id **is** the Authentication VC's `id`. The row is deleted when the session expires;
   * the credential is not. A receipt outlives its session, so it has to point at the thing that
   * survives — a receipt citing a deleted row is a dangling reference dressed as an audit trail.
   *
   * Optional, and that is the honest shape rather than a hedge. A refusal before admission has no
   * authentication to cite, and a purchase receipt (Stage 4) has none either.
   */
  authenticationId?: string;

  /** The metered pool this drew on, by its resource id. */
  pool: string;

  /**
   * What this call cost. **Service policy, not the format's.**
   *
   * A pool may bill per call, per token, per second, or not at all — and the reason the balance
   * is not on the authorization is the same reason this is optional here: what a unit is worth is
   * an agreement between two parties, and a credential is a poor place for a moving number.
   */
  units?: number;
}
