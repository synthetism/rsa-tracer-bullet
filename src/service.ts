/**
 * The service on the wire — a real endpoint, because the point is that an *API* is unchanged.
 *
 * This is a thin translation and nothing else: routes in, `Outcome` out, and a status code
 * that means what the refusal means. No policy lives here, and no crypto.
 *
 * `402 Payment Required` for an empty meter is not a joke. The refusal is a price, the code
 * has been in HTTP since 1996 waiting for a use, and a client that can tell "buy more" apart
 * from "you are not who you say" without parsing prose is a client that can act on it.
 */

import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { VerifiablePresentation } from "@synthetism/vc";
import type { Call, Funnel, Refusal } from "./funnel.js";

export interface ServiceOptions {
  /** `0` picks a free port — which is what the tests want. */
  port?: number;
  host?: string;
}

export interface Running {
  url: string;
  close(): Promise<void>;
}

const STATUS: Record<Refusal, number> = {
  "not-this-service": 400,
  unverifiable: 401,
  "bad-call": 401,
  "out-of-scope": 403,
  "unknown-issuer": 403,
  "meter-empty": 402,
  "no-challenge": 409,
  replayed: 409,
  expired: 409,
  "session-gone": 409,
};

export async function startService(
  funnel: Funnel,
  options: ServiceOptions = {},
): Promise<Running> {
  const server = createServer((request, response) => {
    void handle(request, response).catch((error: unknown) => {
      send(response, 500, { error: error instanceof Error ? error.message : "unknown" });
    });
  });

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const path = new URL(request.url ?? "/", "http://localhost").pathname;

    // The requirement goes out on its own, before anything is presented — so a caller can
    // learn what is needed without disclosing anything to find out.
    if (request.method === "GET" && path === "/requirement") {
      send(response, 200, await funnel.requirement());
      return;
    }

    if (request.method !== "POST") {
      send(response, 405, { error: "method" });
      return;
    }

    const body = await readJson(request);

    if (path === "/challenge") {
      const aud = typeof body.aud === "string" ? body.aud : "";
      const outcome = funnel.challenge(aud);
      send(response, outcome.ok ? 200 : STATUS[outcome.refusal], outcome.ok ? outcome.value : outcome);
      return;
    }

    if (path === "/admit") {
      const outcome = await funnel.admit(body.vp as VerifiablePresentation);
      send(response, outcome.ok ? 200 : STATUS[outcome.refusal], outcome.ok ? outcome.value : outcome);
      return;
    }

    if (path === "/work" || path === "/balance") {
      const call = asCall(body);
      const outcome = path === "/work" ? await funnel.work(call) : await funnel.balance(call);
      send(response, outcome.ok ? 200 : STATUS[outcome.refusal], outcome.ok ? outcome.value : outcome);
      return;
    }

    send(response, 404, { error: "no such endpoint" });
  }

  await new Promise<void>((listening) => {
    server.listen(options.port ?? 0, options.host ?? "127.0.0.1", listening);
  });

  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : 0;

  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((closed) => {
        server.close(() => {
          closed();
        });
      }),
  };
}

/** Every session call is the same envelope. `work` and `balance` differ only in the request. */
function asCall(body: Record<string, unknown>): Call {
  return {
    session: String(body.session ?? ""),
    nonce: String(body.nonce ?? ""),
    request: (body.request ?? {}) as Record<string, unknown>,
    sig: String(body.sig ?? ""),
  };
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(chunk as Buffer);
  }

  const text = Buffer.concat(chunks).toString("utf8");
  if (text.trim() === "") return {};

  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function send(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}
