#!/usr/bin/env node
/**
 * Bob, the service. Run this in one terminal and `alice` in another.
 *
 * It fronts an upstream API that has never heard of credentials, and it is the only place
 * the upstream's key exists.
 */

import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { SERVICE_AUD, bobService } from "./compose.js";
import { seed } from "./seed.js";
import { startService } from "./service.js";

const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    root: { type: "string", default: ".rsa" },
    port: { type: "string", default: "8080" },
    meters: { type: "string", default: "3" },
    "upstream-key": { type: "string", default: process.env.UPSTREAM_KEY ?? "dev-upstream-key" },
  },
});

const root = resolve(values.root as string);
const seeded = await seed(root);
const funnel = await bobService(seeded, {
  meters: Number(values.meters),
  upstreamKey: values["upstream-key"] as string,
});

const running = await startService(funnel, { port: Number(values.port) });

process.stdout.write(`✓ ${SERVICE_AUD} serving on ${running.url}\n`);
process.stdout.write(`   bob            ${seeded.bob.did}\n`);
process.stdout.write(`   authorisation  ${seeded.authorizationId}\n`);
process.stdout.write(`   pool           ${seeded.pool}   ${values.meters} calls\n`);
process.stdout.write("\n  the upstream key is in this process and nowhere else\n");
