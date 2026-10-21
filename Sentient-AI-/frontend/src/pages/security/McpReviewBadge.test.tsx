/**
 * Tests for McpReviewBadge (the chip on an MCP connector's card): they prove it shows how many of
 * that server's tools wait for review with a link to Security ▸ MCP reviews, asks only about its
 * own connector, and renders nothing when nothing waits, when holding is switched off, on a 404
 * from an older server, or on any other failure.
 *
 * Why it exists: the chip is the owner's pointer from the Connectors page to a held tool. A chip
 * that shows a count while holding is off would claim tools are held when they are offered as they
 * are, and one that showed an error would add noise to a card whose connection works.
 */

import { act, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import type { McpReviewList } from "@/types";

vi.mock("@/services/api", () => {
  class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
      this.name = "ApiError";
    }
  }
  return { ApiError, getMcpReviews: vi.fn() };
});

import McpReviewBadge from "@/pages/security/McpReviewBadge";
import { ApiError, getMcpReviews } from "@/services/api";

function reviews(needsReview: number, pinningEnabled = true): McpReviewList {
  return {
    pinning_enabled: pinningEnabled,
    servers: [
      {
        connector_id: "c1",
        display_name: "Notes Server",
        is_active: true,
        needs_review_count: needsReview,
        tools: [],
      },
    ],
  };
}

function renderBadge() {
  return render(
    <MemoryRouter>
      <McpReviewBadge connectorId="c1" />
    </MemoryRouter>,
  );
}

/** Let the badge's one request settle, then report what it rendered. */
async function settled() {
  await waitFor(() => expect(getMcpReviews).toHaveBeenCalledTimes(1));
  await act(async () => {});
}

describe("McpReviewBadge", () => {
  it("shows a warning chip with the count and a link to the MCP reviews tab", async () => {
    vi.mocked(getMcpReviews).mockResolvedValue(reviews(2));
    renderBadge();

    expect(await screen.findByText("2 tools need your review")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Review" })).toHaveAttribute("href", "/security?tab=mcp");
    expect(vi.mocked(getMcpReviews).mock.calls).toEqual([["c1"]]);
  });

  it("says tool, not tools, when one tool waits", async () => {
    vi.mocked(getMcpReviews).mockResolvedValue(reviews(1));
    renderBadge();

    expect(await screen.findByText("1 tool needs your review")).toBeInTheDocument();
  });

  it("renders nothing when no tool waits, when the switch is off, or on a 404", async () => {
    vi.mocked(getMcpReviews).mockResolvedValueOnce(reviews(0));
    const nothingWaits = renderBadge();
    await settled();
    expect(nothingWaits.container).toBeEmptyDOMElement();
    nothingWaits.unmount();

    vi.mocked(getMcpReviews).mockClear();
    vi.mocked(getMcpReviews).mockResolvedValueOnce(reviews(3, false));
    const switchedOff = renderBadge();
    await settled();
    expect(switchedOff.container).toBeEmptyDOMElement();
    switchedOff.unmount();

    vi.mocked(getMcpReviews).mockClear();
    vi.mocked(getMcpReviews).mockRejectedValueOnce(new ApiError("Not Found", 404));
    const olderServer = renderBadge();
    await settled();
    expect(olderServer.container).toBeEmptyDOMElement();
  });

  it("renders nothing, and no error, when the reviews cannot be loaded", async () => {
    vi.mocked(getMcpReviews).mockRejectedValue(new Error("Request failed: Bad Gateway"));
    const { container } = renderBadge();
    await settled();

    expect(container).toBeEmptyDOMElement();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
