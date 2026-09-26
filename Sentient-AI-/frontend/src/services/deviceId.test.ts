/**
 * Tests for the device id and the X-Crawler-Device header: they prove the id is made once, kept in
 * localStorage and reused, that a stored value the server would refuse is replaced, that a page
 * whose storage throws keeps one id in memory, that an id is made without crypto.randomUUID, and
 * that every request to /api carries it — request(), the streamed turn, the token refresh,
 * sign-out, the export and the setup status check.
 *
 * Why it exists: An app allowed for a week from the web applies only to requests from the browser
 * that allowed it. A request without the header, or a browser whose id changes from one request to
 * the next, would quietly get a card for every act again: the problem the weekly button exists to
 * end.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, mockFetch, stubLocation } from "@/test/http";

// What the server accepts as a device id (spec 2026-09-25-weekly-app-approvals §3.4).
const SERVER_RULE = /^[A-Za-z0-9_-]{16,100}$/;

let device: typeof import("./deviceId");
let api: typeof import("./api");

beforeEach(async () => {
  // Fresh modules for every test: the id a page keeps in memory must not carry over.
  vi.resetModules();
  localStorage.clear();
  device = await import("./deviceId");
  api = await import("./api");
});

function denied(): never {
  throw new DOMException("denied", "SecurityError");
}

describe("deviceId", () => {
  it("makes an id on first use, keeps it in localStorage and hands out the same one after", () => {
    expect(localStorage.getItem("crawler.device")).toBeNull();

    const id = device.deviceId();

    expect(id).toMatch(SERVER_RULE);
    expect(localStorage.getItem("crawler.device")).toBe(id);
    expect(device.deviceId()).toBe(id);
  });

  it("reuses the id an earlier visit stored", () => {
    localStorage.setItem("crawler.device", "0b6f2c1e-8d7a-4c55-9f3e-2a1b0c9d8e7f");

    expect(device.deviceId()).toBe("0b6f2c1e-8d7a-4c55-9f3e-2a1b0c9d8e7f");
  });

  it("replaces a stored value the server would refuse", () => {
    for (const refused of ["", "too-short", "has spaces in it, sadly", "x".repeat(101)]) {
      localStorage.setItem("crawler.device", refused);

      const id = device.deviceId();

      expect(id).toMatch(SERVER_RULE);
      expect(localStorage.getItem("crawler.device")).toBe(id);
    }
  });

  it("puts the same id back when storage is cleared while the page is open", () => {
    const id = device.deviceId();
    localStorage.clear();

    expect(device.deviceId()).toBe(id);
    expect(localStorage.getItem("crawler.device")).toBe(id);
  });

  it("keeps one id in memory for the page's life when localStorage throws", () => {
    // A private window with site data blocked throws on read and write alike.
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(denied);
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(denied);

    const id = device.deviceId();

    expect(id).toMatch(SERVER_RULE);
    expect(device.deviceId()).toBe(id);
    expect(device.deviceHeader()).toEqual({ "X-Crawler-Device": id });
  });

  it("keeps one id when storage can be read but not written", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });

    const id = device.deviceId();

    expect(id).toMatch(SERVER_RULE);
    expect(device.deviceId()).toBe(id);
  });

  it("makes an id without crypto.randomUUID, as over plain http at a LAN address", () => {
    const real = globalThis.crypto;
    vi.stubGlobal("crypto", { getRandomValues: real.getRandomValues.bind(real) });

    const id = device.deviceId();

    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(id).toMatch(SERVER_RULE);
  });
});

/** Build a JWT-shaped string whose payload decodes to the given expiry. */
function tokenExpiringIn(seconds: number): string {
  const claims = { sub: "u1", exp: Math.floor(Date.now() / 1000) + seconds };
  const payload = btoa(JSON.stringify(claims))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `header.${payload}.signature`;
}

/** A Response double whose body streams one `done` frame. */
function finishedStream(): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('event: done\ndata: {"content":"ok"}\n\n'));
      controller.close();
    },
  });
  return { ok: true, status: 200, statusText: "OK", body } as unknown as Response;
}

/** The X-Crawler-Device header of one recorded fetch call. */
function sentDevice([, init]: [string, RequestInit?]): string | undefined {
  return (init?.headers as Record<string, string> | undefined)?.["X-Crawler-Device"];
}

describe("X-Crawler-Device on every request to /api", () => {
  beforeEach(() => {
    stubLocation("/chat");
  });

  it("goes on request(), with the stored id and the same one each time", async () => {
    const fetchMock = mockFetch(async () => jsonResponse(200, []));

    await api.getPendingApprovals();
    await api.getConversations();

    const id = localStorage.getItem("crawler.device");
    expect(id).toMatch(SERVER_RULE);
    expect(fetchMock.mock.calls.map(sentDevice)).toEqual([id, id]);
  });

  it("goes on the streamed turn", async () => {
    const fetchMock = mockFetch(async () => finishedStream());

    await api.streamMessage("c1", "What am I doing on the 15th?", {});

    expect(fetchMock.mock.calls[0][0]).toBe("/api/agent/conversations/c1/messages/stream");
    expect(sentDevice(fetchMock.mock.calls[0])).toBe(device.deviceId());
  });

  it("goes on the token refresh", async () => {
    localStorage.setItem("auth_token", tokenExpiringIn(60));
    const fetchMock = mockFetch(async () => jsonResponse(200, { access_token: tokenExpiringIn(3600) }));

    await api.ensureFreshToken();

    expect(fetchMock.mock.calls[0][0]).toBe("/api/auth/refresh");
    expect(sentDevice(fetchMock.mock.calls[0])).toBe(device.deviceId());
  });

  it("goes on the setup status check, the export and sign-out", async () => {
    localStorage.setItem("auth_token", "tok");
    const fetchMock = mockFetch(async (url) =>
      url.endsWith("/setup/status")
        ? jsonResponse(200, { needs_setup: false, has_owner: true })
        : jsonResponse(500, {}),
    );
    const id = device.deviceId();

    await api.getSetupStatus();
    await expect(api.exportAccount()).rejects.toThrow("Export failed");
    api.logout();

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/setup/status",
      "/api/auth/export",
      "/api/auth/logout",
    ]);
    expect(fetchMock.mock.calls.map(sentDevice)).toEqual([id, id, id]);
  });
});
