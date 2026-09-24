import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  deleteAccount,
  deleteConversation,
  getConversations,
  getUsageSummary,
  login,
  streamMessage,
  type StreamHandlers,
} from "@/services/api";
import { jsonResponse, mockFetch, stubLocation } from "@/test/http";

/**
 * Tests for the hand-rolled SSE reader in `streamMessage` and the shared
 * `request` error path. Both are pure protocol/plumbing logic that no other
 * layer re-checks, so a regression here silently truncates assistant replies
 * or strands the user on a 401 loop.
 */

/** Build a Response double whose body streams the given raw chunks. */
function sseResponse(chunks: string[]): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    body,
  } as unknown as Response;
}

function recordHandlers() {
  const handlers = {
    onUserMessage: vi.fn(),
    onContentDelta: vi.fn(),
    onToolCall: vi.fn(),
    onToolResult: vi.fn(),
    onPendingApproval: vi.fn(),
    onBlocked: vi.fn(),
    onDone: vi.fn(),
    onSaved: vi.fn(),
    onError: vi.fn(),
  };
  return handlers as typeof handlers & StreamHandlers;
}

const DONE_FRAME = 'event: done\ndata: {"content":"ok"}\n\n';

describe("streamMessage SSE parsing", () => {
  beforeEach(() => {
    stubLocation();
    localStorage.clear();
  });

  it("dispatches each event type to its handler", async () => {
    mockFetch(() =>
      sseResponse([
        'event: user_message\ndata: {"user_message":{"id":"m1","role":"user","content":"hi"}}\n\n',
        'event: content_delta\ndata: {"text":"Hel"}\n\n',
        'event: content_delta\ndata: {"text":"lo"}\n\n',
        'event: tool_call\ndata: {"name":"search_web"}\n\n',
        'event: tool_result\ndata: {"name":"search_web"}\n\n',
        'event: pending_approval\ndata: {"action_id":"a1","tool_name":"send_email"}\n\n',
        'event: blocked\ndata: {"tool_name":"delete_all","reason":"policy"}\n\n',
        'event: saved\ndata: {"assistant_message":{"id":"m2","role":"assistant","content":"Hello"}}\n\n',
        'event: done\ndata: {"content":"Hello","usage":{"total_tokens":7}}\n\n',
      ]),
    );
    const handlers = recordHandlers();

    await streamMessage("c1", "hi", handlers);

    expect(handlers.onUserMessage).toHaveBeenCalledWith(
      expect.objectContaining({ id: "m1", content: "hi" }),
    );
    expect(handlers.onContentDelta.mock.calls.map((c) => c[0])).toEqual(["Hel", "lo"]);
    expect(handlers.onToolCall).toHaveBeenCalledWith("search_web");
    expect(handlers.onToolResult).toHaveBeenCalledWith("search_web");
    expect(handlers.onPendingApproval).toHaveBeenCalledWith(
      expect.objectContaining({ action_id: "a1", tool_name: "send_email" }),
    );
    expect(handlers.onBlocked).toHaveBeenCalledWith(
      expect.objectContaining({ tool_name: "delete_all" }),
    );
    expect(handlers.onSaved).toHaveBeenCalledWith(
      expect.objectContaining({ id: "m2" }),
    );
    expect(handlers.onDone).toHaveBeenCalledWith(
      expect.objectContaining({ content: "Hello", usage: { total_tokens: 7 } }),
    );
    expect(handlers.onError).not.toHaveBeenCalled();
  });

  it("reassembles a payload spread over multiple data: lines", async () => {
    mockFetch(() =>
      sseResponse([
        'event: content_delta\ndata: {"text":\ndata: "multi-line"}\n\n',
        DONE_FRAME,
      ]),
    );
    const handlers = recordHandlers();

    await streamMessage("c1", "hi", handlers);

    expect(handlers.onContentDelta).toHaveBeenCalledWith("multi-line");
  });

  it("parses a frame that arrives split across chunk boundaries", async () => {
    // The split lands mid-event-name, mid-JSON, and between the two newlines
    // of the frame terminator — every place a naive per-chunk parser breaks.
    mockFetch(() =>
      sseResponse([
        "event: content_del",
        'ta\ndata: {"text":"chu',
        'nked"}\n',
        "\nevent: do",
        'ne\ndata: {"content":"chunked"}\n\n',
      ]),
    );
    const handlers = recordHandlers();

    await streamMessage("c1", "hi", handlers);

    expect(handlers.onContentDelta).toHaveBeenCalledExactlyOnceWith("chunked");
    expect(handlers.onDone).toHaveBeenCalledWith(
      expect.objectContaining({ content: "chunked" }),
    );
  });

  it("ignores ': ping' heartbeat comments without disturbing the stream", async () => {
    mockFetch(() =>
      sseResponse([
        ": ping\n\n",
        'event: content_delta\ndata: {"text":"alive"}\n\n',
        ": ping\n\n",
        DONE_FRAME,
      ]),
    );
    const handlers = recordHandlers();

    await streamMessage("c1", "hi", handlers);

    expect(handlers.onContentDelta).toHaveBeenCalledExactlyOnceWith("alive");
    expect(handlers.onDone).toHaveBeenCalledOnce();
    expect(handlers.onError).not.toHaveBeenCalled();
  });

  it("skips malformed and unknown frames instead of aborting the stream", async () => {
    mockFetch(() =>
      sseResponse([
        "event: content_delta\ndata: {not json}\n\n",
        'event: some_future_event\ndata: {"x":1}\n\n',
        'event: content_delta\ndata: {"text":"still here"}\n\n',
        DONE_FRAME,
      ]),
    );
    const handlers = recordHandlers();

    await streamMessage("c1", "hi", handlers);

    expect(handlers.onContentDelta).toHaveBeenCalledExactlyOnceWith("still here");
    expect(handlers.onDone).toHaveBeenCalledOnce();
  });

  it("flushes a trailing frame that is missing its blank-line terminator", async () => {
    mockFetch(() => sseResponse(['event: done\ndata: {"content":"tail"}']));
    const handlers = recordHandlers();

    await streamMessage("c1", "hi", handlers);

    expect(handlers.onDone).toHaveBeenCalledWith(
      expect.objectContaining({ content: "tail" }),
    );
  });

  it("rejects when the stream ends without a terminal event", async () => {
    // Regression guard: a proxy killing the connection mid-reply used to look
    // exactly like a completed turn, so the UI kept a truncated answer that
    // was never persisted server-side.
    mockFetch(() =>
      sseResponse(['event: content_delta\ndata: {"text":"half a sen"}\n\n']),
    );
    const handlers = recordHandlers();

    await expect(streamMessage("c1", "hi", handlers)).rejects.toThrow(
      /stream was interrupted/i,
    );
    expect(handlers.onContentDelta).toHaveBeenCalledWith("half a sen");
    expect(handlers.onDone).not.toHaveBeenCalled();
  });

  it("resolves without throwing once a done event arrives", async () => {
    mockFetch(() => sseResponse([DONE_FRAME]));

    await expect(streamMessage("c1", "hi", recordHandlers())).resolves.toBeUndefined();
  });

  it("treats a terminal error event as a complete stream", async () => {
    mockFetch(() =>
      sseResponse(['event: error\ndata: {"reason":"provider timeout"}\n\n']),
    );
    const handlers = recordHandlers();

    await expect(streamMessage("c1", "hi", handlers)).resolves.toBeUndefined();
    expect(handlers.onError).toHaveBeenCalledWith("provider timeout");
  });

  it("passes a not-set-up error's code and setup url through, with the pointer", async () => {
    mockFetch(() =>
      sseResponse([
        'event: error\ndata: {"reason":"No AI provider is configured yet.","code":"provider_not_configured","setup_url":"/setup"}\n\n',
      ]),
    );
    const handlers = recordHandlers();

    await streamMessage("c1", "hi", handlers);
    expect(handlers.onError).toHaveBeenCalledWith(
      "No AI provider is configured yet. Open /setup to finish setup.",
      { code: "provider_not_configured", setup_url: "/setup" },
    );
  });

  it("points an unavailable personal provider at Settings, not setup", async () => {
    mockFetch(() =>
      sseResponse([
        'event: error\ndata: {"reason":"The \'openai\' provider selected in your Settings is not configured on this server.","code":"user_provider_unavailable","settings_url":"/settings"}\n\n',
      ]),
    );
    const handlers = recordHandlers();

    await streamMessage("c1", "hi", handlers);
    expect(handlers.onError).toHaveBeenCalledWith(
      "The 'openai' provider selected in your Settings is not configured on this server. Change it in Settings.",
      { code: "user_provider_unavailable", settings_url: "/settings" },
    );
  });

  it("sends the bearer token and message body to the stream endpoint", async () => {
    localStorage.setItem("auth_token", "tok-123");
    const fetchMock = mockFetch(() => sseResponse([DONE_FRAME]));

    await streamMessage("conv-9", "hello there", recordHandlers());

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/conversations/conv-9/messages/stream");
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer tok-123");
    expect(JSON.parse(String(init?.body))).toEqual({ content: "hello there" });
  });

  it("sends attachments as an images array beside the content", async () => {
    const fetchMock = mockFetch(() => sseResponse([DONE_FRAME]));
    const png = "data:image/png;base64,iVBORw0KGgo=";

    await streamMessage("c1", "what is this", recordHandlers(), undefined, [png]);

    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      content: "what is this",
      images: [png],
    });
  });

  it("omits `images` entirely when nothing is attached", async () => {
    const fetchMock = mockFetch(() => sseResponse([DONE_FRAME]));

    // A server without image support must see byte-for-byte the request it
    // always saw, so only a turn that really carries an image can be
    // rejected by one.
    await streamMessage("c1", "plain text", recordHandlers(), undefined, []);

    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body));
    expect(body).toEqual({ content: "plain text" });
    expect("images" in body).toBe(false);
  });

  it("passes an abort signal through so Stop can cancel the turn", async () => {
    const fetchMock = mockFetch(() => sseResponse([DONE_FRAME]));
    const controller = new AbortController();

    await streamMessage("c1", "hi", recordHandlers(), controller.signal);

    expect(fetchMock.mock.calls[0][1]?.signal).toBe(controller.signal);
  });

  it("clears the token and redirects to /login on a 401", async () => {
    const { replace } = stubLocation("/chat");
    localStorage.setItem("auth_token", "expired");
    mockFetch(() => jsonResponse(401, { detail: "Not authenticated" }));

    await expect(streamMessage("c1", "hi", recordHandlers())).rejects.toThrow(
      "Not authenticated",
    );
    expect(localStorage.getItem("auth_token")).toBeNull();
    expect(replace).toHaveBeenCalledWith("/login");
  });

  it("surfaces a non-401 stream failure without redirecting", async () => {
    const { replace } = stubLocation("/chat");
    localStorage.setItem("auth_token", "tok");
    mockFetch(() => jsonResponse(500, { detail: "provider exploded" }));

    await expect(streamMessage("c1", "hi", recordHandlers())).rejects.toThrow(
      "provider exploded",
    );
    expect(replace).not.toHaveBeenCalled();
    expect(localStorage.getItem("auth_token")).toBe("tok");
  });
});

describe("request error handling", () => {
  beforeEach(() => {
    stubLocation();
    localStorage.clear();
  });

  it("renders FastAPI validation arrays as a readable sentence", async () => {
    // A 422 body is a list of objects; joining it naively renders
    // "[object Object]" in the UI.
    mockFetch(() =>
      jsonResponse(422, {
        detail: [
          { loc: ["body", "email"], msg: "value is not a valid email address" },
          { loc: ["body", "password"], msg: "too short" },
        ],
      }),
    );

    await expect(login({ email: "nope", password: "x" })).rejects.toThrow(
      "email: value is not a valid email address; password: too short",
    );
  });

  it("keeps a failed login on the login page instead of redirecting", async () => {
    const { replace } = stubLocation("/login");
    mockFetch(() => jsonResponse(401, { detail: "Incorrect email or password" }));

    await expect(
      login({ email: "a@b.com", password: "wrong" }),
    ).rejects.toThrow("Incorrect email or password");
    expect(replace).not.toHaveBeenCalled();
  });

  it("redirects to /login when an authenticated request 401s", async () => {
    const { replace } = stubLocation("/chat");
    localStorage.setItem("auth_token", "expired");
    mockFetch(() => jsonResponse(401, { detail: "Token expired" }));

    await expect(getConversations()).rejects.toThrow("Token expired");
    expect(localStorage.getItem("auth_token")).toBeNull();
    expect(replace).toHaveBeenCalledWith("/login");
  });

  it("asks for usage in the browser's timezone", async () => {
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    const fetchMock = mockFetch(() => jsonResponse(200, { windows: {} }));

    await getUsageSummary();

    const url = new URL(fetchMock.mock.calls[0][0], "http://localhost");
    expect(url.pathname).toMatch(/\/usage\/summary$/);
    expect(url.searchParams.get("tz")).toBe(zone);
  });

  it("falls back to the server's UTC day when it rejects the zone", async () => {
    const fetchMock = mockFetch((input) =>
      input.includes("tz=")
        ? jsonResponse(422, { detail: "Unknown timezone" })
        : jsonResponse(200, { windows: {} }),
    );

    await expect(getUsageSummary()).resolves.toEqual({ windows: {} });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1][0]).not.toContain("tz=");
  });

  it("does not try to parse a body on 204 responses", async () => {
    mockFetch(
      () =>
        ({
          ok: true,
          status: 204,
          statusText: "No Content",
          json: async () => {
            throw new Error("204 has no body to parse");
          },
        }) as unknown as Response,
    );

    await expect(deleteConversation("c1")).resolves.toBeUndefined();
  });
});

describe("deleteAccount", () => {
  beforeEach(() => {
    stubLocation();
    localStorage.clear();
  });

  it("sends the current password, since the backend requires it for this irreversible action", async () => {
    const fetchFn = mockFetch(() => jsonResponse(204, {}));

    await expect(deleteAccount({ current_password: "correct-horse-9" })).resolves.toBeUndefined();

    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("/api/auth/account");
    expect(init?.method).toBe("DELETE");
    expect(JSON.parse(String(init?.body))).toEqual({ current_password: "correct-horse-9" });
  });

  it("surfaces the backend's 409 message verbatim when the last owner tries to leave", async () => {
    mockFetch(() =>
      jsonResponse(409, { detail: "Transfer ownership before deleting the last owner account" }),
    );

    await expect(deleteAccount({ current_password: "correct-horse-9" })).rejects.toThrow(
      "Transfer ownership before deleting the last owner account",
    );
  });
});
