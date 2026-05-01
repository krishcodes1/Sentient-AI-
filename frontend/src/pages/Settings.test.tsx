import { describe, expect, it, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Settings from "./Settings";
import { renderWithProviders } from "@/test/utils";
import { MOCK_TOKEN } from "@/test/handlers";

describe("Settings page", () => {
  beforeEach(() => {
    localStorage.setItem("sai.access_token", MOCK_TOKEN);
  });

  it("loads the user profile and prefills the form", async () => {
    renderWithProviders(<Settings />, { initialEntries: ["/settings"] });

    await waitFor(() => {
      expect(screen.getByLabelText(/^email$/i)).toHaveValue("test@sentient.ai");
    });
    expect(screen.getByLabelText(/^name$/i)).toHaveValue("Test User");
  });

  it("does NOT render the legacy Reset All Channels button", async () => {
    renderWithProviders(<Settings />, { initialEntries: ["/settings"] });
    await waitFor(() => {
      expect(screen.getByLabelText(/^name$/i)).toBeInTheDocument();
    });
    expect(
      screen.queryByRole("button", { name: /reset all channels/i }),
    ).toBeNull();
  });

  it("provides a Logout all sessions button", async () => {
    renderWithProviders(<Settings />, { initialEntries: ["/settings"] });
    await waitFor(() => {
      expect(
        screen.getByRole("button", { name: /logout all sessions/i }),
      ).toBeInTheDocument();
    });
  });

  it("marks the selected provider with aria-pressed=true", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Settings />, { initialEntries: ["/settings"] });
    await waitFor(() => {
      expect(screen.getByRole("radio", { name: /^anthropic$/i })).toHaveAttribute(
        "aria-pressed",
        "true",
      );
    });
    await user.click(screen.getByRole("radio", { name: /^openai$/i }));
    expect(screen.getByRole("radio", { name: /^openai$/i })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });
});
