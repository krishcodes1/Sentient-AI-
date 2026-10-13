/**
 * Tests for the AI provider form's "Get a <Provider> API key" link: the right key page per
 * provider, opened safely in a new tab, and none where no key is asked for (Ollama, a key from
 * the server's .env) or the provider is unknown.
 *
 * Why it exists: the link sends people straight to the console page where the key is created,
 * so a wrong or missing URL would leave them hunting for it. The API module is mocked at the
 * "@/services/api" boundary; no network.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SetupProvider, SetupProviders } from "@/types";

vi.mock("@/services/api", () => ({
  clearStoredSecrets: vi.fn(),
  getSetupProviders: vi.fn(),
  saveProvider: vi.fn(),
  testProvider: vi.fn(),
}));

import ProviderForm from "@/components/ProviderForm";
import { getSetupProviders } from "@/services/api";

const KEY_PAGES: [string, string, string][] = [
  ["anthropic", "Get an Anthropic API key", "https://platform.claude.com/settings/keys"],
  ["openai", "Get an OpenAI API key", "https://platform.openai.com/api-keys"],
  ["gemini", "Get a Gemini API key", "https://aistudio.google.com/apikey"],
  ["grok", "Get a Grok API key", "https://console.x.ai/team/default/api-keys"],
  ["deepseek", "Get a DeepSeek API key", "https://platform.deepseek.com/api_keys"],
  ["groq", "Get a Groq API key", "https://console.groq.com/keys"],
  ["mistral", "Get a Mistral API key", "https://console.mistral.ai/api-keys"],
];

function provider(name: string, overrides: Partial<SetupProvider> = {}): SetupProvider {
  return { name, key_from_env: false, key_stored: false, models: [`${name}-model`], ...overrides };
}

function serve(list: SetupProvider[], current = ""): void {
  const data: SetupProviders = { providers: list, current: { provider: current, model: "" } };
  vi.mocked(getSetupProviders).mockResolvedValue(data);
}

beforeEach(() => {
  vi.mocked(getSetupProviders).mockReset();
});

describe("ProviderForm API key link", () => {
  it.each(KEY_PAGES)("links the %s key page", async (name, text, url) => {
    serve([provider(name)], name);
    render(<ProviderForm compact />);
    // ExternalAnchor tells screen readers the link opens a new tab.
    const link = await screen.findByRole("link", { name: `${text} (opens in a new tab)` });
    expect(link).toHaveAttribute("href", url);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link.getAttribute("rel")).toContain("noopener");
    expect(link.getAttribute("rel")).toContain("noreferrer");
  });

  it("switches the link with the chosen provider and shows none for Ollama", async () => {
    serve([provider("anthropic"), provider("openai"), provider("ollama")], "anthropic");
    const user = userEvent.setup();
    render(<ProviderForm compact />);
    expect(await screen.findByRole("link", { name: "Get an Anthropic API key (opens in a new tab)" })).toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: "openai" }));
    expect(screen.getByRole("link", { name: "Get an OpenAI API key (opens in a new tab)" })).toHaveAttribute(
      "href",
      "https://platform.openai.com/api-keys",
    );

    await user.click(screen.getByRole("radio", { name: "ollama" }));
    expect(screen.queryByRole("link", { name: /API key/ })).not.toBeInTheDocument();
  });

  it("shows no link when the key comes from the server's .env or the provider is unknown", async () => {
    serve([provider("gemini", { key_from_env: true }), provider("someday")], "gemini");
    const user = userEvent.setup();
    render(<ProviderForm compact />);
    expect(await screen.findByText("Provided by server configuration")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /API key/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: "someday" }));
    expect(screen.getByLabelText("API key")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /API key/ })).not.toBeInTheDocument();
  });
});
