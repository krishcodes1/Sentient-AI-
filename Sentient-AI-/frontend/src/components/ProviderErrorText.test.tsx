/**
 * Tests for ProviderErrorText: they prove a Settings pointer becomes a /settings link, an
 * install-level pointer also points at Settings, and any other text renders unchanged.
 *
 * Why it exists: Guards against inventing a link when the text lacks the pointer, or sending a
 * user to /setup once setup is already finished.
 */

import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import ProviderErrorText from "@/components/ProviderErrorText";

function renderText(text: string, info?: Parameters<typeof ProviderErrorText>[0]["info"]) {
  return render(
    <MemoryRouter>
      <p data-testid="bubble">
        <ProviderErrorText text={text} info={info} />
      </p>
    </MemoryRouter>,
  );
}

describe("ProviderErrorText", () => {
  it("links the Settings pointer of a user_provider_unavailable failure", () => {
    renderText(
      "The 'openai' provider selected in your Settings is not configured on this server. Change it in Settings.",
      { code: "user_provider_unavailable", settings_url: "/settings" },
    );

    expect(screen.getByRole("link", { name: "Settings" })).toHaveAttribute("href", "/settings");
    expect(screen.getByTestId("bubble")).toHaveTextContent(
      "The 'openai' provider selected in your Settings is not configured on this server. Change it in Settings.",
    );
  });

  it("points an install-level failure at Settings too, since /setup is finished by the time chat is open", () => {
    renderText("No AI provider is configured yet. Open /setup to finish setup.", {
      code: "provider_not_configured",
      setup_url: "/setup",
    });

    expect(screen.getByRole("link", { name: "Settings" })).toHaveAttribute("href", "/settings");
    expect(screen.getByTestId("bubble")).toHaveTextContent(
      "No AI provider is configured yet. Set it up in Settings.",
    );
    expect(screen.getByTestId("bubble")).not.toHaveTextContent("/setup");
  });

  it("leaves any other failure as plain text", () => {
    renderText("anthropic provider error (HTTP 529): overloaded");

    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByTestId("bubble")).toHaveTextContent("anthropic provider error (HTTP 529): overloaded");
  });

  it("does not invent a link when the text lacks the pointer the info promises", () => {
    renderText("Something else went wrong.", { settings_url: "/settings" });

    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByTestId("bubble")).toHaveTextContent("Something else went wrong.");
  });
});
