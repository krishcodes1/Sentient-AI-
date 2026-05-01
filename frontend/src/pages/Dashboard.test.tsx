import { describe, expect, it, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import Dashboard from "./Dashboard";
import { renderWithProviders } from "@/test/utils";
import { MOCK_TOKEN } from "@/test/handlers";

describe("Dashboard page", () => {
  beforeEach(() => {
    localStorage.setItem("sai.access_token", MOCK_TOKEN);
  });

  it("shows skeleton then renders metric values from the API", async () => {
    renderWithProviders(<Dashboard />, { initialEntries: ["/overview"] });

    // Header always rendered.
    expect(
      screen.getByRole("heading", { name: /gateway & workspace/i }),
    ).toBeInTheDocument();

    // After queries resolve, we should see the 24-hour metric counts from
    // the audit-stats handler (last_24h_count = 142, blocked_24h = 7).
    await waitFor(() => {
      expect(screen.getByText("142")).toBeInTheDocument();
      expect(screen.getByText("7")).toBeInTheDocument();
    });
  });

  it("renders the integrations section and channel name", async () => {
    renderWithProviders(<Dashboard />, { initialEntries: ["/overview"] });

    await waitFor(() => {
      expect(screen.getByText(/Primary Telegram/i)).toBeInTheDocument();
    });
  });
});
