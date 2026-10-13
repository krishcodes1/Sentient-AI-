/**
 * Tests for the X-Crawler-Timezone header: every request() call and the streamed chat turn carry
 * the browser's IANA zone, and a browser whose Intl cannot name one sends no header at all rather
 * than a guess.
 *
 * Why it exists: the server saves this zone on the account (after checking it is a real zone), and
 * scheduled tasks and the assistant's clock use it; a missing header on the chat path would leave a
 * Docker install, whose clock is UTC, asking the user for their zone again.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jsonResponse, mockFetch, stubLocation } from "@/test/http";

let api: typeof import("./api");

beforeEach(async () => {
  vi.resetModules();
  localStorage.clear();
  stubLocation("/chat");
  api = await import("./api");
});

afterEach(() => {
  vi.restoreAllMocks();
});

function sentZone([, init]: [string, RequestInit?]): string | undefined {
  return (init?.headers as Record<string, string> | undefined)?.["X-Crawler-Timezone"];
}

function finishedStream(): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('event: done\ndata: {"content":"ok"}\n\n'));
      controller.close();
    },
  });
  return { ok: true, status: 200, statusText: "OK", body } as unknown as Response;
}

describe("X-Crawler-Timezone", () => {
  it("goes on request() and the streamed turn with the browser's zone", async () => {
    vi.spyOn(Intl.DateTimeFormat.prototype, "resolvedOptions").mockReturnValue({
      timeZone: "America/Chicago",
    } as Intl.ResolvedDateTimeFormatOptions);
    const fetchMock = mockFetch(async (url) =>
      url.endsWith("/stream") ? finishedStream() : jsonResponse(200, []),
    );

    await api.getConversations();
    await api.streamMessage("c1", "hello", {});

    expect(fetchMock.mock.calls.map(sentZone)).toEqual(["America/Chicago", "America/Chicago"]);
  });

  it("is left out when the browser cannot name a zone", async () => {
    vi.spyOn(Intl.DateTimeFormat.prototype, "resolvedOptions").mockImplementation(() => {
      throw new Error("no Intl");
    });
    const fetchMock = mockFetch(async () => jsonResponse(200, []));

    await api.getConversations();

    expect(sentZone(fetchMock.mock.calls[0])).toBeUndefined();
  });
});
