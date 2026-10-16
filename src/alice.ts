#!/usr/bin/env node
/**
 * Alice, the agent — stand-alone, and holding nothing of Bob's.
 *
 * Her whole world is her own root: her key folder, her vault, and the one authorization
 * somebody issued her. She has no account, no password, no token, and she never signs up.
 * This process *is* the wedge: an agent admitted by a service that has never met it.
 */

import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { SERVICE_AUD, aliceAgent } from "./compose.js";
import type { Outcome } from "./funnel.js";
import { seed } from "./seed.js";

const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    root: { type: "string", default: ".rsa" },
    url: { type: "string", default: "http://127.0.0.1:8080" },
    aud: { type: "string", default: SERVICE_AUD },
    symbol: { type: "string", default: "ACME" },
  },
});

function fail(outcome: { refusal: string; errors: string[] }): never {
  process.stderr.write(`✗ refused: ${outcome.refusal}\n`);
  for (const problem of outcome.errors) {
    process.stderr.write(`  ${problem}\n`);
  }
  process.exit(1);
}

function unwrap<T>(outcome: Outcome<T>): T {
  return outcome.ok ? outcome.value : fail(outcome);
}

const seeded = await seed(resolve(values.root as string));
const agent = await aliceAgent(seeded, values.url as string);

process.stdout.write(`alice  ${agent.did}\n`);
process.stdout.write(`  → asking ${values.url} what it requires\n`);

const published = unwrap(await agent.learn());
const requirement = published.credentialSubject.requirement;
process.stdout.write(
  `  ✓ ${requirement.name} v${requirement.version}, signed by the service — ${published.issuer.id}\n`,
);

process.stdout.write("  → presenting the authorization\n");
const admission = unwrap(await agent.admit());
process.stdout.write(`  ✓ session           ${admission.session}\n`);
process.stdout.write(`  ✓ authentication    ${admission.authentication.id}\n`);
process.stdout.write("  ✓ its issuer is the service that authorised us — the handshake holds\n");

process.stdout.write("  → asking the pool what is left\n");
const before = unwrap(await agent.balance());
process.stdout.write(`  ✓ balance           ${before.remaining} call(s) in ${before.pool}\n`);

process.stdout.write(`  → calling /work for ${values.symbol}\n`);
const passage = unwrap(await agent.call({ symbol: values.symbol }));

process.stdout.write(`  ✓ data              ${JSON.stringify(passage.data)}\n`);
process.stdout.write(`  ✓ receipt           ${passage.receipt.id}\n`);
process.stdout.write(`                      verdict ${passage.receipt.credentialSubject.verdict}\n`);
process.stdout.write(`  ${passage.remaining} call(s) left in the pool\n`);
