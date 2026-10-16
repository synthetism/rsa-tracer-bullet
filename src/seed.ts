/**
 * Two parties, seeded and fixed.
 *
 * The keys are **derived from labels**, not generated. That is what makes the DIDs stable
 * across runs, which in turn is what lets the Authorisation VC be issued **once** and
 * reused — the tests do not re-authorise anything, they find the same two DID:keys and the
 * same credential every time.
 *
 * A derived key is not a secret, and it is not pretending to be one. It is a fixture: the
 * material is reproducible from a string in this file, so committing the *seed* commits
 * nothing and the vaults stay gitignored. A real party generates its key through
 * `IKeyStore.create` and never knows the material at all.
 *
 * Each party gets its **own root** — its own key folder, its own vault, its own records.
 * That is not tidiness: Alice has to be able to run as a stand-alone process holding
 * nothing of Bob's, and the only way to be sure of that is for Bob's things to be in a
 * different directory.
 */

import { createHash } from "node:crypto";
import { join } from "node:path";
import type { KeyInfo } from "@privatekey/core";
import { didKeyFromPublicKey } from "@synthetism/did";
import {
  type AuthorizationSubject,
  type VerifiableCredential,
  createUnsigned,
  issue,
  verify,
} from "@synthetism/vc";
import { openVault, openWallet } from "./stores.js";

/** One party: a label, its key, and the DID the key projects to. */
export interface Party {
  alias: string;
  /** The party's own container — `<root>/<alias>`. */
  root: string;
  did: string;
  kid: string;
}

export interface Seeded {
  root: string;
  alice: Party;
  bob: Party;
  /** What Bob issued to Alice, and what Alice holds. */
  authorization: VerifiableCredential<AuthorizationSubject>;
  /** Its `id` — the value that ends up in the Authentication VC's `authorizationId`. */
  authorizationId: string;
  /** The metered thing. One meter per pool; two would be the only place a chain enters. */
  pool: string;
  /** What the authorisation permits. The funnel demands a subset of it. */
  scope: string[];
}

export const POOL = "https://api.example.com/market";
export const AUTHORIZED_SCOPE = ["read"];

/** A key from a label. Deterministic, reproducible, and a fixture rather than a secret. */
export function keyFromLabel(label: string): string {
  return createHash("sha256").update(`synthetism:rsa:v1:${label}`).digest("hex");
}

/** The register key. The vault owns the filename; the app owns the handle. */
export function authorizationRecord(id: string): string {
  return `authorization:${id}`;
}

/** Make the party's key if it is not there, and report the public projection either way. */
async function ensureParty(root: string, alias: string): Promise<Party> {
  const wallet = openWallet(root);
  const held: KeyInfo | undefined = (await wallet.store.list()).find(
    (key) => key.alias === alias,
  );

  const info =
    held ?? (await wallet.store.import({ privateKeyHex: keyFromLabel(alias), type: "Ed25519", alias }));

  return { alias, root, did: didKeyFromPublicKey(info.publicKeyHex), kid: info.kid };
}

/** Bob issues to Alice's DID. Bob never has — and never needs — a key for it. */
async function authorize(bob: Party, alice: Party): Promise<VerifiableCredential<AuthorizationSubject>> {
  const signer = await openWallet(bob.root).store.signer(bob.kid);

  const unsigned = createUnsigned<AuthorizationSubject>({
    subject: { holder: { id: alice.did }, scope: [...AUTHORIZED_SCOPE], resource: POOL },
    type: "AuthorizationCredential",
    issuer: { id: bob.did, name: bob.alias },
  });

  const { credential } = await issue(unsigned, signer);

  const verdict = verify(credential);
  if (!verdict.verified) {
    throw new Error(`the seeded authorization does not verify: ${verdict.errors.join("; ")}`);
  }

  return credential;
}

/** Alice's vault, if she is already holding an authorisation. */
async function findHeld(alice: Party): Promise<VerifiableCredential<AuthorizationSubject> | undefined> {
  const vault = await openVault(alice.root);
  const listed = await vault.list();
  if (!listed.isSuccess) return undefined;

  const entry = listed.value.find((record) => record.metadata?.type === "authorization");
  if (entry === undefined) return undefined;

  const found = await vault.get<VerifiableCredential<AuthorizationSubject>>(entry.id);
  return found.isSuccess && found.value !== undefined ? found.value : undefined;
}

async function record(
  party: Party,
  credential: VerifiableCredential<AuthorizationSubject>,
  metadata: Record<string, string>,
): Promise<void> {
  const vault = await openVault(party.root);
  const saved = await vault.save(authorizationRecord(credential.id), credential, {
    type: "authorization",
    ...metadata,
  });

  if (!saved.isSuccess) {
    throw new Error(`could not record the authorization for ${party.alias}`);
  }
}

/**
 * Seed the two parties, and the one authorisation between them.
 *
 * **Idempotent.** Keys that exist are left alone, and an authorisation Alice already holds
 * is returned rather than reissued — a second call gives you the same two DIDs and the same
 * credential, which is what "don't repeat authorisation" requires. Run it once into `.rsa/`
 * and the by-hand loop can be run as many times as you like.
 *
 * The register is written on **both** sides: Bob keeps what he sold (the issuer's register),
 * and Alice keeps what she bought (her vault). `SPEC.md` §6 says the vault is the register,
 * and this is where that becomes two directories rather than a remark.
 */
export async function seed(root: string): Promise<Seeded> {
  const alice = await ensureParty(join(root, "alice"), "alice");
  const bob = await ensureParty(join(root, "bob"), "bob");

  const existing = await findHeld(alice);
  const authorization = existing ?? (await authorize(bob, alice));

  if (existing === undefined) {
    await record(alice, authorization, { role: "held" });
    await record(bob, authorization, { role: "register", holder: alice.did });
  }

  return {
    root,
    alice,
    bob,
    authorization,
    authorizationId: authorization.id,
    pool: POOL,
    scope: [...AUTHORIZED_SCOPE],
  };
}
