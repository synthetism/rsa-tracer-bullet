/**
 * The upstream — a market API that has never heard of credentials.
 *
 * This is the point of RSA, in one file. The API takes an API key, exactly as it does
 * today, and it knows nothing about agents, DIDs, presentations or sessions. **It is not
 * changed.** The funnel stands in front of it and turns a verifiable presentation into a
 * request this function accepts.
 *
 * The key is the service's, held by the funnel and read at start. It never travels: not
 * into a credential, not into a receipt, not into a response, not into a log. That is
 * what "the funnel is a boundary" means, and the tests assert it rather than trusting it.
 */

export interface Quote {
  symbol: string;
  bid: number;
  ask: number;
  at: string;
}

/** The exchange, as the funnel sees it. Wrong or missing key, no data. */
export interface Upstream {
  readonly name: string;
  quotes(request: { symbol: string }, apiKey: string): Promise<Quote[]>;
}

const BOOK: Record<string, Quote[]> = {
  ACME: [
    { symbol: "ACME", bid: 101.25, ask: 101.4, at: "2026-10-16T09:00:00.000Z" },
    { symbol: "ACME", bid: 101.1, ask: 101.3, at: "2026-10-16T09:01:00.000Z" },
  ],
  GLOBEX: [{ symbol: "GLOBEX", bid: 42.5, ask: 42.7, at: "2026-10-16T09:00:00.000Z" }],
};

export function openUpstream(): Upstream {
  return {
    name: "market.example",

    async quotes(request, apiKey) {
      if (apiKey.trim() === "") {
        throw new Error("upstream: no key");
      }

      const quotes = BOOK[request.symbol.toUpperCase()];
      if (quotes === undefined) {
        throw new Error(`upstream: unknown symbol ${JSON.stringify(request.symbol)}`);
      }

      return quotes;
    },
  };
}
