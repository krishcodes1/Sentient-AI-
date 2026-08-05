import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { jsonResponse } from "@/test/http";

/**
 * Proactive token renewal.
 *
 * The failure this guards against is subtle: renewing too eagerly turns
 * every request into two, and renewing on a token that is already dead
 * logs the user out sooner than doing nothing would. Both are covered
 * below alongside the happy path.
 */

/** Build a JWT-shaped string whose payload decodes to the given claims. */
function tokenExpiringIn(seconds: number): string {
  const claims = { sub: "u1", exp: Math.floor(Date.now() / 1000) + seconds };
  const payload = btoa(JSON.stringify(claims))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `header.${payload}.signature`;
}

let api: typeof import("./api");
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(async () => {
  vi.resetModules();
  localStorage.clear();
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  api = await import("./api");
});

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe("ensureFreshToken", () => {
  it("does nothing when there is no token", async () => {
    await api.ensureFreshToken();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("leaves a token with plenty of life alone", async () => {
    localStorage.setItem("auth_token", tokenExpiringIn(60 * 60));

    await api.ensureFreshToken();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("renews a token inside the expiry window", async () => {
    const old = tokenExpiringIn(60);
    localStorage.setItem("auth_token", old);
    const renewed = tokenExpiringIn(3600);
    fetchMock.mockResolvedValue(jsonResponse(200, { access_token: renewed }));

    await api.ensureFreshToken();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/auth/refresh");
    expect(init.method).toBe("POST");
    expect(init.headers.Authorization).toBe(`Bearer ${old}`);
    expect(localStorage.getItem("auth_token")).toBe(renewed);
  });

  it("does not try to renew an already-expired token", async () => {
    // There is nothing to extend, and the 401 path owns the logout.
    localStorage.setItem("auth_token", tokenExpiringIn(-30));

    await api.ensureFreshToken();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shares one request across concurrent callers", async () => {
    localStorage.setItem("auth_token", tokenExpiringIn(60));
    const renewed = tokenExpiringIn(3600);
    let release: (v: Response) => void = () => {};
    fetchMock.mockReturnValue(
      new Promise<Response>((resolve) => {
        release = resolve;
      })
    );

    const calls = [
      api.ensureFreshToken(),
      api.ensureFreshToken(),
      api.ensureFreshToken(),
    ];
    release(jsonResponse(200, { access_token: renewed }));
    await Promise.all(calls);

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keeps the existing token when renewal is refused", async () => {
    // Past the absolute session cap, say. The current token is still valid
    // until its own expiry — discarding it here would log the user out
    // earlier than doing nothing.
    const current = tokenExpiringIn(60);
    localStorage.setItem("auth_token", current);
    fetchMock.mockResolvedValue(jsonResponse(401, { detail: "session expired" }));

    await api.ensureFreshToken();

    expect(localStorage.getItem("auth_token")).toBe(current);
  });

  it("survives a network failure", async () => {
    const current = tokenExpiringIn(60);
    localStorage.setItem("auth_token", current);
    fetchMock.mockRejectedValue(new Error("offline"));

    await expect(api.ensureFreshToken()).resolves.toBeUndefined();
    expect(localStorage.getItem("auth_token")).toBe(current);
  });

  it("ignores a malformed token instead of throwing", async () => {
    localStorage.setItem("auth_token", "not-a-jwt");

    await expect(api.ensureFreshToken()).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
