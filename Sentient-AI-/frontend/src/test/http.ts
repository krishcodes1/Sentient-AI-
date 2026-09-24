/**
 * Shared fetch and location doubles for the api-layer suites: jsonResponse, nonJsonResponse,
 * mockFetch and stubLocation.
 *
 * Why it exists: Several suites need the same 401-redirect scaffolding, and a second copy that
 * forgot to stub `replace` would stop exercising the redirect while still passing.
 */

import { vi } from "vitest";

/**
 * Shared fetch/location doubles for the api-layer suites.
 *
 * Both the SSE suite and the approval suite need the same 401-redirect
 * scaffolding. A drifting second copy of `stubLocation` is the failure mode
 * this file exists to prevent: if one copy forgets to stub `replace`, that
 * suite stops exercising the redirect entirely and still passes.
 */

/** A minimal Response double whose `json()` resolves to `body`. */
export function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: `status ${status}`,
    json: async () => body,
  } as unknown as Response;
}

/**
 * A failure Response whose body is not JSON at all — what a reverse proxy
 * returns when it, rather than FastAPI, generates the error page.
 */
export function nonJsonResponse(status: number): Response {
  return {
    ok: false,
    status,
    statusText: `status ${status}`,
    json: async () => {
      throw new SyntaxError("Unexpected token < in JSON at position 0");
    },
  } as unknown as Response;
}

export type FetchImpl = (
  input: string,
  init?: RequestInit,
) => Response | Promise<Response>;

export function mockFetch(impl: FetchImpl) {
  const fn = vi.fn(impl);
  vi.stubGlobal("fetch", fn);
  return fn;
}

/**
 * jsdom's real `location` refuses redefinition of `replace`/`reload`, so swap
 * the whole global (vitest maps `window` onto `globalThis`).
 */
export function stubLocation(pathname = "/") {
  const replace = vi.fn();
  const reload = vi.fn();
  vi.stubGlobal("location", {
    pathname,
    href: `http://localhost:3000${pathname}`,
    origin: "http://localhost:3000",
    replace,
    reload,
    assign: vi.fn(),
  });
  return { replace, reload };
}
