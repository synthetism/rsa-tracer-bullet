/**
 * The stores this harness composes.
 *
 * Two of them, and the split is the whole point: a **keystore** holds private keys and
 * only ever hands out signers, and a **vault** holds public records. A composition root
 * belongs to the app that composes it, so this is the harness's own — `cli/src/wallet.ts`
 * and `cli/src/vault.ts` are the CLI's, and they reach the same decisions for the same
 * reasons.
 *
 * When a third app needs one, that is the moment to extract it. Not before: a
 * composition root shared by two apps is a composition root neither of them owns.
 */

import { join, resolve } from "node:path";
import { NodeFileSystem } from "@hsfs/adapter-node";
import { Vault, describeError } from "@hsfs/vault";
import type { IKeyStore } from "@privatekey/core";
import { fileStore } from "@privatekey/keystore-file";

export interface Wallet {
  readonly store: IKeyStore;
  /** The absolute folder the keys are in. */
  readonly keyDir: string;
}

/**
 * `0700` on the folder, `0600` on the key.
 *
 * The folder's mode is declared by whoever chose the filesystem — that is here — because
 * `0600` on a key protects the key while `0700` on the folder protects the *list* of them.
 * Without it the folder is `0755`: unreadable contents, a published inventory.
 */
export function openWallet(root: string): Wallet {
  const keyDir = resolve(root, "keys");
  return {
    store: fileStore({ fs: new NodeFileSystem({ root: keyDir, dirMode: 0o700 }) }),
    keyDir,
  };
}

export async function openVault(root: string, name = "records"): Promise<Vault> {
  const opened = await Vault.open({
    fs: new NodeFileSystem({ root: join(root, "vault"), dirMode: 0o700 }),
    name,
  });

  if (!opened.isSuccess) {
    throw new Error(`could not open the vault at ${root}: ${describeError(opened.error)}`);
  }

  return opened.value;
}
