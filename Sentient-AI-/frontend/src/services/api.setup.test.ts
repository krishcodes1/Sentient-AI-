import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { jsonResponse, mockFetch } from "@/test/http";
import {
  completeSetup,
  createOwner,
  getSetupStatus,
  saveProvider,
  testProvider,
} from "./api";

/**
 * The setup calls run before, and just after, anyone has a session. The
 * owner step must leave the browser signed in exactly as login() does, and
 * the status check must work for a visitor with no (or a stale) token.
 */

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe("setup api", () => {
  it("createOwner stores the returned token so the wizard continues signed in", async () => {
    const fetchFn = mockFetch(() =>
      jsonResponse(200, { access_token: "owner-token", token_type: "bearer", user: { id: "u1" } }),
    );

    await createOwner({ email: "krish@example.com", password: "correct-horse-9", name: "Krish" });

    expect(localStorage.getItem("auth_token")).toBe("owner-token");
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("/api/setup/owner");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({
      email: "krish@example.com",
      password: "correct-horse-9",
      name: "Krish",
    });
  });

  it("createOwner leaves no token behind when the server refuses", async () => {
    mockFetch(() => jsonResponse(409, { detail: "An owner account already exists." }));

    await expect(
      createOwner({ email: "a@b.co", password: "correct-horse-9", name: "A" }),
    ).rejects.toThrow("An owner account already exists.");
    expect(localStorage.getItem("auth_token")).toBeNull();
  });

  it("getSetupStatus sends no Authorization header, even with a leftover token", async () => {
    localStorage.setItem("auth_token", "stale-token-from-a-wiped-install");
    const fetchFn = mockFetch(() =>
      jsonResponse(200, {
        needs_setup: true,
        has_owner: false,
        provider_configured: false,
        setup_completed: false,
      }),
    );

    const status = await getSetupStatus();

    expect(status.needs_setup).toBe(true);
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("/api/setup/status");
    expect(JSON.stringify(init ?? {})).not.toContain("Authorization");
  });

  it("omits api_key when none is given and sends the choice to the right endpoints", async () => {
    const fetchFn = mockFetch(() => jsonResponse(200, { ok: true, reply: "OK" }));

    await testProvider({ provider: "gemini", model: "gemini-2.5-flash" });
    await saveProvider({ provider: "gemini", model: "gemini-2.5-flash", api_key: "k" });
    await completeSetup({ allow_registration: false });

    const calls = fetchFn.mock.calls.map(([url, init]) => [url, init?.method, JSON.parse(String(init?.body))]);
    expect(calls).toEqual([
      ["/api/setup/provider/test", "POST", { provider: "gemini", model: "gemini-2.5-flash" }],
      ["/api/setup/provider", "PUT", { provider: "gemini", model: "gemini-2.5-flash", api_key: "k" }],
      ["/api/setup/complete", "POST", { allow_registration: false }],
    ]);
  });
});
