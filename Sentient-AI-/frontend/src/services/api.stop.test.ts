/**
 * Tests for stopping a running task: stopAgent posts to the stop endpoint with the bearer token,
 * and a stopped turn's stream (a `stopped` frame, then the "Stopped." reply, `done` and `saved`)
 * reads as a normal, complete reply.
 *
 * Why it exists: Guards against the Stop button reaching nothing on the server, or a stopped
 * turn surfacing as an error or an interrupted stream.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { stopAgent, streamMessage } from "@/services/api";
import { jsonResponse, mockFetch, stubLocation } from "@/test/http";

const STOPPED = "Stopped. I didn't finish: 1 step was skipped. 1 step ran before the stop.";

/** A Response double whose body streams the given raw chunks. */
function sseResponse(chunks: string[]): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
  return { ok: true, status: 200, statusText: "OK", body } as unknown as Response;
}

describe("stopAgent", () => {
  beforeEach(() => {
    stubLocation("/chat");
    localStorage.clear();
  });

  it("posts to the stop endpoint as the signed-in user", async () => {
    localStorage.setItem("auth_token", "tok-stop");
    const fetchMock = mockFetch(() => jsonResponse(200, { ok: true }));

    await expect(stopAgent()).resolves.toEqual({ ok: true });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/stop");
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer tok-stop");
  });

  it("rejects when the server refuses, so the caller can fall back", async () => {
    mockFetch(() => jsonResponse(503, { detail: "Service unavailable" }));
    await expect(stopAgent()).rejects.toThrow("Service unavailable");
  });
});

describe("a stopped turn's stream", () => {
  beforeEach(() => {
    stubLocation("/chat");
    localStorage.clear();
  });

  it("reads as a complete reply: the stopped frame adds nothing, done and saved carry it", async () => {
    // Split into 7-byte chunks, as a slow connection would deliver it.
    const body =
      'event: tool_call\ndata: {"name":"web.fetch_page","host":"canvas.nyit.edu"}\n\n' +
      'event: tool_result\ndata: {"name":"web.fetch_page"}\n\n' +
      'event: stopped\ndata: {"policy":"user_stopped","steps_ran":1,"steps_skipped":1}\n\n' +
      `event: content_delta\ndata: {"text":"${STOPPED}"}\n\n` +
      `event: done\ndata: {"content":"${STOPPED}"}\n\n` +
      `event: saved\ndata: {"assistant_message":{"id":"m2","role":"assistant","content":"${STOPPED}"}}\n\n`;
    const chunks: string[] = [];
    for (let i = 0; i < body.length; i += 7) chunks.push(body.slice(i, i + 7));
    mockFetch(() => sseResponse(chunks));
    const handlers = {
      onToolCall: vi.fn(),
      onContentDelta: vi.fn(),
      onDone: vi.fn(),
      onSaved: vi.fn(),
      onBlocked: vi.fn(),
      onError: vi.fn(),
    };

    await expect(streamMessage("conv-1", "grades?", handlers)).resolves.toBeUndefined();

    expect(handlers.onToolCall).toHaveBeenCalledWith("web.fetch_page");
    expect(handlers.onContentDelta).toHaveBeenCalledWith(STOPPED);
    expect(handlers.onDone).toHaveBeenCalledWith({ content: STOPPED });
    expect(handlers.onSaved).toHaveBeenCalledWith(
      expect.objectContaining({ id: "m2", content: STOPPED }),
    );
    expect(handlers.onBlocked).not.toHaveBeenCalled();
    expect(handlers.onError).not.toHaveBeenCalled();
  });
});
