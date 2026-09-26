/**
 * Tests for the weekly app approval calls: decideApproval sends `remember: "week"` only when the
 * weekly button asks for it and hands back `weekly`, the list and Revoke hit /agent/app-approvals
 * with the right verbs, a Revoke of an approval that is gone surfaces the server's 404 without
 * signing anyone out, and a streamed pending_approval keeps its `weekly_app`.
 *
 * Why it exists: The decision body is the consent boundary. A `remember` sent with a plain Approve
 * would let Crawler act in an app for a week that the owner approved once, and a dropped
 * `weekly_app` would hide the button on the very card it belongs to.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  decideApproval,
  listAppApprovals,
  revokeAppApproval,
  streamMessage,
} from "@/services/api";
import { jsonResponse, mockFetch, stubLocation } from "@/test/http";
import type { AppApproval, PendingApproval } from "@/types";

const UNTIL = "2026-10-02T15:14:00Z";

/** A Response double whose body streams the given SSE frames. */
function sseResponse(frames: string[]): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const frame of frames) controller.enqueue(encoder.encode(frame));
      controller.close();
    },
  });
  return { ok: true, status: 200, statusText: "OK", body } as unknown as Response;
}

describe("weekly app approvals api", () => {
  beforeEach(() => {
    stubLocation("/chat");
    localStorage.clear();
  });

  it("sends remember: week for the weekly button and hands back until when the app is allowed", async () => {
    const fetchMock = mockFetch(() =>
      jsonResponse(200, {
        action_id: "act-7",
        approved: true,
        result: { ok: true },
        weekly: { app: "Calendar", expires_at: UNTIL },
      }),
    );

    await expect(decideApproval("act-7", true, "week")).resolves.toMatchObject({
      weekly: { app: "Calendar", expires_at: UNTIL },
    });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/approvals/act-7");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ approved: true, remember: "week" });
  });

  it("sends no remember at all with a plain Approve or Deny", async () => {
    const fetchMock = mockFetch(() => jsonResponse(200, { action_id: "act-8", approved: true, weekly: null }));

    await decideApproval("act-8", true);
    await decideApproval("act-9", false);

    const bodies = fetchMock.mock.calls.map(([, init]) => JSON.parse(String(init?.body)));
    expect(bodies).toEqual([{ approved: true }, { approved: false }]);
    expect(bodies.some((body) => "remember" in body)).toBe(false);
  });

  it("reads the allowed apps with a plain GET", async () => {
    const rows: AppApproval[] = [
      {
        id: "w1",
        app: "Calendar",
        channel: "web",
        this_device: true,
        granted_at: "2026-09-25T15:14:00Z",
        expires_at: UNTIL,
        last_used_at: null,
      },
      {
        id: "w2",
        app: "Reminders",
        channel: "telegram",
        this_device: false,
        granted_at: "2026-09-24T09:00:00Z",
        expires_at: "2026-10-01T09:00:00Z",
        last_used_at: "2026-09-25T10:30:00Z",
      },
    ];
    const fetchMock = mockFetch(() => jsonResponse(200, rows));

    await expect(listAppApprovals()).resolves.toEqual(rows);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/app-approvals");
    expect(init?.method).toBeUndefined();
  });

  it("revokes one with DELETE and no body, reading nothing from the 204", async () => {
    const fetchMock = mockFetch(
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

    await expect(revokeAppApproval("w1")).resolves.toBeUndefined();

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/agent/app-approvals/w1");
    expect(init?.method).toBe("DELETE");
    expect(init?.body).toBeUndefined();
  });

  it("surfaces the 404 for an approval that is gone without signing the user out", async () => {
    const { replace } = stubLocation("/settings");
    localStorage.setItem("auth_token", "still-valid");
    mockFetch(() => jsonResponse(404, { detail: "App approval not found" }));

    await expect(revokeAppApproval("w-old")).rejects.toMatchObject({
      name: "ApiError",
      status: 404,
      message: "App approval not found",
    });
    expect(replace).not.toHaveBeenCalled();
    expect(localStorage.getItem("auth_token")).toBe("still-valid");
  });

  it("keeps weekly_app on a streamed pending_approval", async () => {
    const card: PendingApproval = {
      action_id: "a7",
      tool_name: "desktop.act",
      arguments: { action: "click", ref: "e12" },
      reason: 'Click "Month" in Calendar',
      expires_at: "2099-01-01T00:00:00Z",
      weekly_app: "Calendar",
    };
    mockFetch(() =>
      sseResponse([
        `event: pending_approval\ndata: ${JSON.stringify(card)}\n\n`,
        'event: done\ndata: {"content":""}\n\n',
      ]),
    );
    const onPendingApproval = vi.fn();

    await streamMessage("c1", "What am I doing on the 15th?", { onPendingApproval });

    expect(onPendingApproval).toHaveBeenCalledWith(card);
  });
});
