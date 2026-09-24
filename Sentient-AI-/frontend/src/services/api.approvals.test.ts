/**
 * Tests for the approval endpoints, error-detail normalisation and conversation CRUD: they prove
 * decisions post the right verb, action_id and approved flag, and FastAPI error bodies become
 * readable sentences.
 *
 * Why it exists: Guards against a "Deny" click executing the action, or an approval card reading
 * "[object Object]".
 */

import { beforeEach, describe, expect, it } from "vitest";
import {
  createConversation,
  decideApproval,
  deleteConversation,
  getConversation,
  getConversations,
  getPendingApprovals,
  updateConversation,
} from "@/services/api";
import {
  jsonResponse,
  mockFetch,
  nonJsonResponse,
  stubLocation,
} from "@/test/http";

/**
 * The approval endpoints are the consent boundary: whatever this module puts
 * on the wire is what the backend executes. A swapped verb, a dropped
 * `action_id`, or an inverted `approved` flag would turn a "Deny" click into
 * a real-world action, and nothing downstream would catch it.
 *
 * The error-message tests cover `errorDetailToMessage`, which is the only
 * thing standing between FastAPI's 422 body (a list of objects) and an
 * approval card that reads "[object Object]".
 */

describe("approval decisions", () => {
  beforeEach(() => {
    stubLocation("/chat");
    localStorage.clear();
  });

  it("posts an approval to the action's own endpoint", async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse(200, {
        action_id: "act-1",
        approved: true,
        result: { sent: true },
      }),
    );

    await expect(decideApproval("act-1", true)).resolves.toEqual({
      action_id: "act-1",
      approved: true,
      result: { sent: true },
    });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/approvals/act-1");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ approved: true });
  });

  it("sends approved:false for a denial rather than omitting the flag", async () => {
    // An omitted or truthy flag here executes the action the user refused.
    const fetchMock = mockFetch(() =>
      jsonResponse(200, { action_id: "act-2", approved: false, result: null }),
    );

    await decideApproval("act-2", false);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/approvals/act-2");
    expect(JSON.parse(String(init?.body))).toEqual({ approved: false });
  });

  it("authenticates the decision with the stored bearer token", async () => {
    localStorage.setItem("auth_token", "tok-approve");
    const fetchMock = mockFetch(() =>
      jsonResponse(200, { action_id: "act-3", approved: true }),
    );

    await decideApproval("act-3", true);

    const headers = fetchMock.mock.calls[0][1]?.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer tok-approve");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("reads the pending queue with a plain GET", async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse(200, [
        {
          action_id: "a1",
          tool_name: "gmail.send",
          arguments: { to: "x@y.z" },
          reason: "needs consent",
        },
      ]),
    );

    await expect(getPendingApprovals()).resolves.toHaveLength(1);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/approvals");
    expect(init?.method).toBeUndefined();
  });

  it("clears the session and redirects when a decision comes back 401", async () => {
    const { replace } = stubLocation("/chat");
    localStorage.setItem("auth_token", "expired");
    mockFetch(() => jsonResponse(401, { detail: "Token expired" }));

    await expect(decideApproval("act-4", true)).rejects.toThrow("Token expired");
    expect(localStorage.getItem("auth_token")).toBeNull();
    expect(replace).toHaveBeenCalledWith("/login");
  });

  it("surfaces an expired approval's 404 without logging the user out", async () => {
    // Approvals have a server-side TTL, so a late click legitimately 404s.
    // Treating that like an auth failure would dump the user on /login.
    const { replace } = stubLocation("/chat");
    localStorage.setItem("auth_token", "still-valid");
    mockFetch(() =>
      jsonResponse(404, { detail: "Approval request not found or expired" }),
    );

    await expect(decideApproval("act-old", true)).rejects.toThrow(
      "Approval request not found or expired",
    );
    expect(replace).not.toHaveBeenCalled();
    expect(localStorage.getItem("auth_token")).toBe("still-valid");
  });
});

describe("error detail normalization", () => {
  beforeEach(() => {
    stubLocation("/chat");
    localStorage.clear();
  });

  it("uses a plain string detail verbatim", async () => {
    mockFetch(() => jsonResponse(409, { detail: "Approval already decided" }));

    await expect(decideApproval("act-1", true)).rejects.toThrow(
      "Approval already decided",
    );
  });

  it("flattens FastAPI's 422 list-of-dicts into field: message pairs", async () => {
    // `loc` always leads with the request part ("body"/"query"); only that
    // first segment is dropped, so nested fields keep their dotted path.
    mockFetch(() =>
      jsonResponse(422, {
        detail: [
          { loc: ["body", "approved"], msg: "field required" },
          {
            loc: ["body", "settings", "rate_limit"],
            msg: "ensure this value is <= 100",
          },
        ],
      }),
    );

    await expect(decideApproval("act-1", true)).rejects.toThrow(
      "approved: field required; settings.rate_limit: ensure this value is <= 100",
    );
  });

  it("handles list details that are not FastAPI validation dicts", async () => {
    mockFetch(() => jsonResponse(400, { detail: [{ msg: "no location here" }] }));
    await expect(decideApproval("act-1", true)).rejects.toThrow(
      "no location here",
    );

    mockFetch(() => jsonResponse(400, { detail: ["first problem", "second"] }));
    await expect(decideApproval("act-1", true)).rejects.toThrow(
      "first problem; second",
    );
  });

  it("serializes a non-array object detail instead of rendering [object Object]", async () => {
    mockFetch(() =>
      jsonResponse(429, {
        detail: { code: "rate_limited", retry_after: 30 },
      }),
    );

    await expect(decideApproval("act-1", true)).rejects.toThrow(
      '{"code":"rate_limited","retry_after":30}',
    );
  });

  it("uses the message field of a 503 not-configured detail and appends the setup url", async () => {
    mockFetch(() =>
      jsonResponse(503, {
        detail: {
          message: "No AI provider is configured.",
          code: "provider_not_configured",
          setup_url: "/setup",
        },
      }),
    );

    await expect(decideApproval("act-1", true)).rejects.toThrow(
      "No AI provider is configured. Open /setup to finish setup.",
    );
  });

  it("points a 409 unavailable-personal-provider detail at Settings", async () => {
    mockFetch(() =>
      jsonResponse(409, {
        detail: {
          message: "The 'openai' provider selected in your Settings is not configured on this server.",
          code: "user_provider_unavailable",
          settings_url: "/settings",
        },
      }),
    );

    await expect(decideApproval("act-1", true)).rejects.toMatchObject({
      message:
        "The 'openai' provider selected in your Settings is not configured on this server. Change it in Settings.",
      status: 409,
    });
  });

  it("uses the message field verbatim when the detail object has no fix url", async () => {
    mockFetch(() =>
      jsonResponse(503, {
        detail: { message: "No AI provider is configured.", code: "provider_not_configured" },
      }),
    );

    await expect(decideApproval("act-1", true)).rejects.toMatchObject({
      message: "No AI provider is configured.",
    });
  });

  it("falls back to the status line when the body carries no usable detail", async () => {
    mockFetch(() => jsonResponse(500, {}));
    await expect(decideApproval("act-1", true)).rejects.toThrow(
      "Request failed: status 500",
    );

    mockFetch(() => jsonResponse(500, { detail: "   " }));
    await expect(decideApproval("act-1", true)).rejects.toThrow(
      "Request failed: status 500",
    );
  });

  it("falls back to the status line when the detail list has nothing usable", async () => {
    // An array whose items all filter out used to fall past the array
    // branch into the generic object branch and get JSON.stringify'd — an
    // array IS a truthy object — so `{"detail": []}` surfaced as the
    // literal "[]", the exact unreadable message this code exists to
    // prevent.
    for (const detail of [[], [""], [null]]) {
      mockFetch(() => jsonResponse(400, { detail }));
      await expect(decideApproval("act-1", true)).rejects.toThrow(
        "Request failed: status 400",
      );
    }
  });

  it("falls back when the error body is not JSON at all", async () => {
    // A proxy's HTML 502 page makes `response.json()` throw; the caller still
    // needs a readable Error rather than an unhandled parse failure.
    mockFetch(() => nonJsonResponse(502));

    await expect(decideApproval("act-1", true)).rejects.toThrow(
      "Request failed: status 502",
    );
  });

  it("carries the HTTP status on the thrown error", async () => {
    mockFetch(() => jsonResponse(403, { detail: "Forbidden" }));

    await expect(decideApproval("act-1", true)).rejects.toMatchObject({
      name: "ApiError",
      status: 403,
    });
  });
});

describe("conversation CRUD", () => {
  beforeEach(() => {
    stubLocation("/chat");
    localStorage.clear();
  });

  it("omits the query string entirely when no paging is requested", async () => {
    const fetchMock = mockFetch(() => jsonResponse(200, []));

    await getConversations();

    expect(fetchMock.mock.calls[0][0]).toBe("/api/agent/conversations");
  });

  it("keeps a zero offset and zero limit in the query string", async () => {
    // A truthiness check instead of `!= null` would silently drop offset=0
    // and re-request the same page forever.
    const fetchMock = mockFetch(() => jsonResponse(200, []));

    await getConversations({ limit: 50, offset: 0 });

    expect(fetchMock.mock.calls[0][0]).toBe(
      "/api/agent/conversations?limit=50&offset=0",
    );
  });

  it("creates a conversation with the default title", async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse(201, { id: "c1", title: "New Conversation" }),
    );

    await expect(createConversation()).resolves.toMatchObject({ id: "c1" });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/conversations");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ title: "New Conversation" });
  });

  it("creates a conversation with an explicit title", async () => {
    const fetchMock = mockFetch(() => jsonResponse(201, { id: "c2" }));

    await createConversation("Quarterly review");

    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      title: "Quarterly review",
    });
  });

  it("loads a single conversation with its messages", async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse(200, { id: "c3", title: "t", messages: [{ id: "m1" }] }),
    );

    await expect(getConversation("c3")).resolves.toMatchObject({
      messages: [{ id: "m1" }],
    });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/agent/conversations/c3");
  });

  it("renames a conversation with PATCH and sends only the title", async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse(200, { id: "c4", title: "Renamed" }),
    );

    await updateConversation("c4", { title: "Renamed" });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/conversations/c4");
    expect(init?.method).toBe("PATCH");
    expect(JSON.parse(String(init?.body))).toEqual({ title: "Renamed" });
  });

  it("deletes a conversation with DELETE and no body", async () => {
    const fetchMock = mockFetch(() => jsonResponse(200, null));

    await deleteConversation("c5");

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/conversations/c5");
    expect(init?.method).toBe("DELETE");
    expect(init?.body).toBeUndefined();
  });
});
