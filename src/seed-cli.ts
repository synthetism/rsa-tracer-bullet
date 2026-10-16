#!/usr/bin/env node
/**
 * Seed the two parties and the one authorisation between them.
 *
 * Idempotent: run it as often as you like. The keys are derived from labels and the
 * authorisation is reused if Alice already holds one, so a second run prints the same two
 * DIDs and the same credential. **That is the point** — the loop below it can be run
 * repeatedly without re-authorising anything.
 */

import { resolve } from "node:path";
import { seed } from "./seed.js";

const root = resolve(process.argv[2] ?? ".rsa");
const seeded = await seed(root);

process.stdout.write(`✓ seeded ${root}\n`);
process.stdout.write(`   alice          ${seeded.alice.did}\n`);
process.stdout.write(`             keys ${seeded.alice.root}/keys    (0700, and 0600 inside)\n`);
process.stdout.write(`   bob            ${seeded.bob.did}\n`);
process.stdout.write(`             keys ${seeded.bob.root}/keys\n`);
process.stdout.write(`   authorization  ${seeded.authorizationId}\n`);
process.stdout.write(`   pool           ${seeded.pool}\n`);
process.stdout.write(`   scope          ${seeded.scope.join(", ")}\n`);
process.stdout.write("\n  run it again: same two DIDs, same credential, nothing reissued\n");
