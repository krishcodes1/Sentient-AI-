import { describe, expect, it, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Channels from "./Channels";
import { renderWithProviders } from "@/test/utils";
import { MOCK_TOKEN } from "@/test/handlers";

describe("Channels page", () => {
  beforeEach(() => {
    localStorage.setItem("auth_token", MOCK_TOKEN);
  });

  it("renders the connected channel from the API", async () => {
    renderWithProviders(<Channels />, { initialEntries: ["/channels"] });

    await waitFor(() => {
      expect(screen.getByText("Primary Telegram")).toBeInTheDocument();
    });
  });

  it("opens the add-channel modal with role=dialog", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Channels />, { initialEntries: ["/channels"] });

    await waitFor(() => {
      expect(screen.getByText("Primary Telegram")).toBeInTheDocument();
    });

    // Telegram is already configured, so the modal opens via Discord card.
    const discordButton = screen.getByRole("button", { name: /discord/i });
    await user.click(discordButton);

    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAttribute("aria-labelledby");
  });

  it("validates a malformed Telegram-style token (regex hint)", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Channels />, { initialEntries: ["/channels"] });

    await waitFor(() => {
      expect(screen.getByText("Primary Telegram")).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: /discord/i }));
    const dialog = await screen.findByRole("dialog");
    const tokenInput = dialog.querySelector('input[type="password"]');
    expect(tokenInput).not.toBeNull();
    if (tokenInput) {
      await user.type(tokenInput as HTMLInputElement, "short");
      const connect = screen.getByRole("button", { name: /connect channel/i });
      await user.click(connect);
      // The discord regex requires 40+ chars; expect error message.
      expect(await screen.findByText(/40\+ characters/i)).toBeInTheDocument();
    }
  });
});
