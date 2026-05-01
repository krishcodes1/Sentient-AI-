import { describe, expect, it, beforeEach } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Chat from "./Chat";
import { renderWithProviders } from "@/test/utils";
import { MOCK_TOKEN } from "@/test/handlers";

describe("Chat page", () => {
  beforeEach(() => {
    localStorage.setItem("auth_token", MOCK_TOKEN);
  });

  it("loads the conversation list", async () => {
    renderWithProviders(<Chat />, { initialEntries: ["/chat"] });
    await waitFor(() => {
      expect(screen.getByText("Sample conversation")).toBeInTheDocument();
    });
  });

  it("opens a conversation and renders its messages", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Chat />, { initialEntries: ["/chat"] });
    const convoButton = await screen.findByText("Sample conversation");
    await user.click(convoButton);

    await waitFor(() => {
      expect(screen.getByText("Hi there")).toBeInTheDocument();
      expect(screen.getByText(/hello! how can i help/i)).toBeInTheDocument();
    });
  });

  it("optimistically appends the user message after send", async () => {
    const user = userEvent.setup();
    renderWithProviders(<Chat />, { initialEntries: ["/chat"] });

    const convoButton = await screen.findByText("Sample conversation");
    await user.click(convoButton);

    await waitFor(() => {
      expect(screen.getByText("Hi there")).toBeInTheDocument();
    });

    const input = screen.getByLabelText(/^message$/i);
    await user.type(input, "Tell me a joke{Enter}");

    await waitFor(() => {
      expect(screen.getByText("Tell me a joke")).toBeInTheDocument();
    });
  });
});
