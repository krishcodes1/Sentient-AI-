/**
 * Tests for ServiceKeysTab (Security ▸ Service keys, owner only): they prove every outside service
 * is listed with whether its key is saved, stored or provided by the server's .env and that no key
 * is ever rendered; that Test checks a typed key (or, with none, the configured one) without
 * saving it; that Save stores a key once, clears the field and marks the row saved; that the
 * server's 400, 409, 422 and 429 sentences are shown on the row without the typed key; that Remove
 * asks first and removes only its own row; that the link-check line under the Google rows says
 * which service is used, lookups against the limit, the last problem, and when checks are off or
 * blocked; and that unreadable keys, a load failure and a 403 are each said plainly.
 *
 * Why it exists: this tab is the only place an owner adds the keys that let Crawler send links,
 * email addresses or file fingerprints to an outside service. A key echoed back into the page, a
 * key stored without its test, a removal that hit the wrong service, or a refusal the owner never
 * saw would each break the promise that nothing leaves without the owner's own working key.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type {
  LinkReputationStatus,
  SecurityServiceKey,
  SecurityServiceKeys,
  SecurityServiceName,
} from "@/types";

vi.mock("@/services/api", () => {
  class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
      this.name = "ApiError";
    }
  }
  return {
    ApiError,
    getSecurityKeys: vi.fn(),
    testSecurityKey: vi.fn(),
    saveSecurityKey: vi.fn(),
    removeSecurityKey: vi.fn(),
    getLinkReputationStatus: vi.fn(),
  };
});

import ServiceKeysTab from "@/pages/security/ServiceKeysTab";
import {
  ApiError,
  getLinkReputationStatus,
  getSecurityKeys,
  removeSecurityKey,
  saveSecurityKey,
  testSecurityKey,
} from "@/services/api";

// Built by concatenation so no secret scanner ever sees a literal key (backend test precedent).
const FAKE_GOOGLE_KEY = "AIza" + "FAKEfake".repeat(4) + "000";
const GOOGLE_KEY_SHAPE = /AIza[0-9A-Za-z_-]{35}/;

const STORED_PLACEHOLDER = "A key is saved — paste a new one to replace it";
const ENV_SENTENCE = "Provided by server configuration (.env); remove it there to manage it here.";
const BLOCKED_REASON = "Add a Google Safe Browsing or Web Risk key in Security → Service keys.";

const ROWS: Record<SecurityServiceName, SecurityServiceKey> = {
  safe_browsing: {
    name: "safe_browsing",
    label: "Google Safe Browsing",
    used_for:
      "Checking links in mail alerts, scam checks, outgoing messages and pages the browser opens.",
    note: "Free for non-commercial use. If you use Crawler for a business, use Google Web Risk instead.",
    console_url: "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com",
    key_hint: "Starts with AIza, 39 characters",
    key_from_env: false,
    key_stored: false,
  },
  web_risk: {
    name: "web_risk",
    label: "Google Web Risk",
    used_for: "The same link checks, under Google's commercial terms.",
    note: "Billed by Google past its free tier. When both Google keys are saved, Web Risk is used.",
    console_url: "https://console.cloud.google.com/apis/library/webrisk.googleapis.com",
    key_hint: "Starts with AIza, 39 characters",
    key_from_env: false,
    key_stored: false,
  },
  hibp: {
    name: "hibp",
    label: "Have I Been Pwned",
    used_for: "Watching the owners' email addresses for new data breaches (Breach monitor).",
    note: "Have I Been Pwned charges a monthly subscription for an API key. The password check works without one.",
    console_url: "https://haveibeenpwned.com/API/Key",
    key_hint: "32 characters, 0-9 and a-f",
    key_from_env: false,
    key_stored: false,
  },
  virustotal: {
    name: "virustotal",
    label: "VirusTotal",
    used_for: "Checking the fingerprint of files people send Crawler and of email attachments.",
    note: "Free public API: 4 lookups a minute, 500 a day, non-commercial use only.",
    console_url: "https://www.virustotal.com/gui/my-apikey",
    key_hint: "64 hex characters",
    key_from_env: false,
    key_stored: false,
  },
};

function keyList(
  changes: Partial<Record<SecurityServiceName, Partial<SecurityServiceKey>>> = {},
  secretsUnreadable = false,
): SecurityServiceKeys {
  const order: SecurityServiceName[] = ["safe_browsing", "web_risk", "hibp", "virustotal"];
  return {
    services: order.map((name) => ({ ...ROWS[name], ...changes[name] })),
    secrets_unreadable: secretsUnreadable,
  };
}

function linkStatus(changes: Partial<LinkReputationStatus> = {}): LinkReputationStatus {
  return {
    capability: "blocked",
    reason: BLOCKED_REASON,
    service: null,
    both_keys: false,
    lookups_last_minute: 0,
    lookups_per_minute: 60,
    lookups_last_day: 0,
    lookups_per_day: 2000,
    counting_since: "2026-10-14T08:00:00Z",
    cache_entries: 0,
    dangerous_found_last_day: 0,
    not_checked_last_day: 0,
    cooling_down_until: null,
    last_problem: null,
    ...changes,
  };
}

/** The local short time the tab prints for an ISO moment. */
function shortTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

/** Render the tab with the given key list and status answers; resolves once the rows show. */
async function mount({
  keys = keyList(),
  status = linkStatus() as LinkReputationStatus | Error,
}: { keys?: SecurityServiceKeys; status?: LinkReputationStatus | Error } = {}) {
  vi.mocked(getSecurityKeys).mockResolvedValue(keys);
  if (status instanceof Error) vi.mocked(getLinkReputationStatus).mockRejectedValue(status);
  else vi.mocked(getLinkReputationStatus).mockResolvedValue(status);
  render(<ServiceKeysTab />);
  await screen.findByRole("region", { name: "Google Safe Browsing" });
}

function row(label: string): HTMLElement {
  return screen.getByRole("region", { name: label });
}

function keyField(label: string): HTMLInputElement {
  return within(row(label)).getByLabelText(`${label} API key`) as HTMLInputElement;
}

function button(label: string, action: "Test" | "Save" | "Remove"): HTMLElement {
  return within(row(label)).getByRole("button", { name: `${action} the ${label} key` });
}

function badge(label: string, text: string): HTMLElement {
  return within(row(label)).getByText(text, { selector: "span" });
}

describe("ServiceKeysTab", () => {
  it("lists every service with whether a key is saved and never renders a key", async () => {
    vi.mocked(getSecurityKeys).mockResolvedValue(
      keyList({ safe_browsing: { key_stored: true }, hibp: { key_from_env: true } }),
    );
    vi.mocked(getLinkReputationStatus).mockResolvedValue(linkStatus());
    render(<ServiceKeysTab />);

    expect(screen.getByRole("heading", { name: "Service keys" })).toBeInTheDocument();
    expect(screen.getByText("Loading service keys…")).toBeInTheDocument();
    await screen.findByRole("region", { name: "Google Safe Browsing" });
    expect(
      screen.getByText(
        "Crawler sends nothing to these services until you add your own key here. Keys are stored " +
          "encrypted and are never shown again.",
      ),
    ).toBeInTheDocument();

    expect(screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual([
      "Google Safe Browsing",
      "Google Web Risk",
      "Have I Been Pwned",
      "VirusTotal",
    ]);
    expect(badge("Google Safe Browsing", "Saved")).toBeInTheDocument();
    expect(badge("Google Web Risk", "Not set")).toBeInTheDocument();
    expect(badge("Have I Been Pwned", "From server configuration")).toBeInTheDocument();
    expect(badge("VirusTotal", "Not set")).toBeInTheDocument();
    expect(within(row("Google Safe Browsing")).getByText(ROWS.safe_browsing.note)).toBeInTheDocument();
    expect(row("Google Safe Browsing")).toHaveTextContent(`Used for: ${ROWS.safe_browsing.used_for}`);

    // Saved keys are never prefilled: the field only says one exists.
    expect(keyField("Google Safe Browsing")).toHaveAttribute("placeholder", STORED_PLACEHOLDER);
    expect(keyField("Google Web Risk")).toHaveAttribute("placeholder", "Starts with AIza, 39 characters");
    expect(keyField("VirusTotal")).toHaveAttribute("placeholder", "64 hex characters");
    const fields = Array.from(document.querySelectorAll("input"));
    expect(fields).toHaveLength(3);
    for (const field of fields) {
      expect(field).toHaveAttribute("type", "password");
      expect(field).toHaveAttribute("autocomplete", "off");
      expect(field).toHaveAttribute("spellcheck", "false");
      expect(field).toHaveValue("");
    }
    expect(document.body.textContent).not.toMatch(GOOGLE_KEY_SHAPE);

    const link = within(row("Google Safe Browsing")).getByRole("link", {
      name: "Get a key for Google Safe Browsing (opens in a new tab)",
    });
    expect(link).toHaveAttribute("href", ROWS.safe_browsing.console_url);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");

    // Only a saved key can be removed; Test needs a typed or configured key.
    expect(button("Google Safe Browsing", "Remove")).toBeEnabled();
    expect(within(row("Google Web Risk")).queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();
    expect(button("Google Safe Browsing", "Test")).toBeEnabled();
    expect(button("Google Web Risk", "Test")).toBeDisabled();
    expect(button("Google Web Risk", "Save")).toBeDisabled();
  });

  it("hides the key field and says so when the server's .env provides the key", async () => {
    await mount({ keys: keyList({ hibp: { key_from_env: true } }) });

    const hibp = row("Have I Been Pwned");
    expect(within(hibp).getByText(ENV_SENTENCE)).toBeInTheDocument();
    expect(within(hibp).queryByLabelText(/API key/)).not.toBeInTheDocument();
    expect(within(hibp).queryByRole("button", { name: /Save/ })).not.toBeInTheDocument();
    expect(within(hibp).queryByRole("link")).not.toBeInTheDocument();
    // The environment's key can still be tested, with nothing typed.
    vi.mocked(testSecurityKey).mockResolvedValue({ ok: true, detail: "Have I Been Pwned accepted the key." });
    fireEvent.click(button("Have I Been Pwned", "Test"));
    expect(await within(hibp).findByRole("status")).toHaveTextContent("Have I Been Pwned accepted the key.");
    expect(vi.mocked(testSecurityKey).mock.calls).toEqual([["hibp"]]);
  });

  it("tests a typed key without saving it and shows Google's answer", async () => {
    await mount();
    let answer: (value: { ok: boolean; detail?: string }) => void = () => undefined;
    vi.mocked(testSecurityKey).mockImplementation(
      () => new Promise((resolve) => (answer = resolve)),
    );

    fireEvent.change(keyField("Google Safe Browsing"), { target: { value: `  ${FAKE_GOOGLE_KEY} ` } });
    expect(button("Google Safe Browsing", "Test")).toBeEnabled();
    fireEvent.click(button("Google Safe Browsing", "Test"));

    // While Google is asked, the row cannot start a second request.
    expect(button("Google Safe Browsing", "Test")).toBeDisabled();
    expect(button("Google Safe Browsing", "Save")).toBeDisabled();
    answer({ ok: true, detail: "Google answered: the key works." });

    const sb = row("Google Safe Browsing");
    expect(await within(sb).findByRole("status")).toHaveTextContent("Google answered: the key works.");
    expect(vi.mocked(testSecurityKey).mock.calls).toEqual([["safe_browsing", FAKE_GOOGLE_KEY]]);
    expect(saveSecurityKey).not.toHaveBeenCalled();
    expect(badge("Google Safe Browsing", "Not set")).toBeInTheDocument();
    // Testing keeps what was typed so it can be saved next; the page text never holds it.
    expect(keyField("Google Safe Browsing")).toHaveValue(`  ${FAKE_GOOGLE_KEY} `);
    expect(document.body.textContent).not.toContain(FAKE_GOOGLE_KEY);
  });

  it("tests the saved key when the field is empty", async () => {
    await mount({ keys: keyList({ safe_browsing: { key_stored: true } }) });
    vi.mocked(testSecurityKey).mockResolvedValue({
      ok: false,
      error:
        "Google refused the key: the Safe Browsing API is not turned on for this key's project, or " +
        "the key is restricted to other APIs.",
    });

    fireEvent.click(button("Google Safe Browsing", "Test"));

    expect(await within(row("Google Safe Browsing")).findByRole("alert")).toHaveTextContent(
      "Google refused the key: the Safe Browsing API is not turned on",
    );
    // No key argument at all: the server tests the configured key.
    expect(vi.mocked(testSecurityKey).mock.calls).toEqual([["safe_browsing"]]);
    expect(saveSecurityKey).not.toHaveBeenCalled();
  });

  it("after a save, shows the service's own answer when the server sends it", async () => {
    await mount();
    vi.mocked(saveSecurityKey).mockResolvedValue({
      ok: true,
      service: { ...ROWS.safe_browsing, key_stored: true },
      detail: "Google answered: the key works.",
    });

    fireEvent.change(keyField("Google Safe Browsing"), { target: { value: FAKE_GOOGLE_KEY } });
    fireEvent.click(button("Google Safe Browsing", "Save"));

    expect(await within(row("Google Safe Browsing")).findByRole("status")).toHaveTextContent(
      "Saved. Google answered: the key works.",
    );
  });

  it("saves a key once, clears the field and shows the row as saved", async () => {
    await mount();
    vi.mocked(saveSecurityKey).mockResolvedValue({
      ok: true,
      service: { ...ROWS.safe_browsing, key_stored: true },
    });
    vi.mocked(getLinkReputationStatus).mockResolvedValue(
      linkStatus({ capability: "on", reason: "", service: "safe_browsing" }),
    );

    fireEvent.change(keyField("Google Safe Browsing"), { target: { value: ` ${FAKE_GOOGLE_KEY}  ` } });
    fireEvent.click(button("Google Safe Browsing", "Save"));

    const sb = row("Google Safe Browsing");
    expect(await within(sb).findByRole("status")).toHaveTextContent(
      "Saved. Google Safe Browsing accepted the key.",
    );
    expect(vi.mocked(saveSecurityKey).mock.calls).toEqual([["safe_browsing", FAKE_GOOGLE_KEY]]);
    expect(testSecurityKey).not.toHaveBeenCalled();
    expect(keyField("Google Safe Browsing")).toHaveValue("");
    expect(keyField("Google Safe Browsing")).toHaveAttribute("placeholder", STORED_PLACEHOLDER);
    expect(badge("Google Safe Browsing", "Saved")).toBeInTheDocument();
    expect(button("Google Safe Browsing", "Remove")).toBeEnabled();
    expect(button("Google Safe Browsing", "Save")).toBeDisabled();
    // Other rows are untouched.
    expect(badge("Google Web Risk", "Not set")).toBeInTheDocument();
    // The link-check line follows the new key.
    await waitFor(() => expect(getLinkReputationStatus).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByText(/Link checks: on · using Google Safe Browsing/),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(FAKE_GOOGLE_KEY);
  });

  it("shows the server's 409 when the environment manages the key", async () => {
    await mount();
    vi.mocked(saveSecurityKey).mockRejectedValue(
      new ApiError("Google Safe Browsing is set in the server's .env file; change it there.", 409),
    );

    fireEvent.change(keyField("Google Safe Browsing"), { target: { value: FAKE_GOOGLE_KEY } });
    fireEvent.click(button("Google Safe Browsing", "Save"));

    expect(await within(row("Google Safe Browsing")).findByRole("alert")).toHaveTextContent(
      "Google Safe Browsing is set in the server's .env file; change it there.",
    );
    expect(badge("Google Safe Browsing", "Not set")).toBeInTheDocument();
  });

  it("shows the server's 422 format message and keeps the typed key out of the page text", async () => {
    await mount();
    const typed = "AIza-not-a-real-key-" + "x".repeat(6);
    vi.mocked(testSecurityKey).mockRejectedValue(
      new ApiError(
        "That does not look like a Google API key (they start with AIza and are 39 characters long).",
        422,
      ),
    );

    fireEvent.change(keyField("Google Web Risk"), { target: { value: typed } });
    fireEvent.click(button("Google Web Risk", "Test"));

    expect(await within(row("Google Web Risk")).findByRole("alert")).toHaveTextContent(
      "That does not look like a Google API key (they start with AIza and are 39 characters long).",
    );
    expect(vi.mocked(testSecurityKey).mock.calls).toEqual([["web_risk", typed]]);
    expect(keyField("Google Web Risk")).toHaveAttribute("type", "password");
    expect(document.body.textContent).not.toContain(typed);
  });

  it("never shows the typed key even when a server sentence quotes it", async () => {
    await mount();
    vi.mocked(testSecurityKey).mockResolvedValue({
      ok: false,
      error: `Google said ${FAKE_GOOGLE_KEY} is not valid.`,
    });

    fireEvent.change(keyField("Google Safe Browsing"), { target: { value: FAKE_GOOGLE_KEY } });
    fireEvent.click(button("Google Safe Browsing", "Test"));

    expect(await within(row("Google Safe Browsing")).findByRole("alert")).toHaveTextContent(
      "Google said [hidden] is not valid.",
    );
    expect(document.body.textContent).not.toContain(FAKE_GOOGLE_KEY);
  });

  it("shows the retry message from a 429", async () => {
    await mount();
    vi.mocked(saveSecurityKey).mockRejectedValue(
      new ApiError("Too many attempts. Try again in 42 seconds.", 429),
    );

    fireEvent.change(keyField("VirusTotal"), { target: { value: "a".repeat(64) } });
    fireEvent.click(button("VirusTotal", "Save"));

    expect(await within(row("VirusTotal")).findByRole("alert")).toHaveTextContent(
      "Too many attempts. Try again in 42 seconds.",
    );
    // The row is usable again once the refusal is shown.
    expect(button("VirusTotal", "Save")).toBeEnabled();
  });

  it("shows a failed test's reason from a 400 on save and keeps the row unsaved", async () => {
    await mount();
    vi.mocked(saveSecurityKey).mockRejectedValue(
      new ApiError(
        "Google refused the key: the Safe Browsing API is not turned on for this key's project, " +
          "or the key is restricted to other APIs.",
        400,
      ),
    );

    fireEvent.change(keyField("Google Safe Browsing"), { target: { value: FAKE_GOOGLE_KEY } });
    fireEvent.click(button("Google Safe Browsing", "Save"));

    expect(await within(row("Google Safe Browsing")).findByRole("alert")).toHaveTextContent(
      "Google refused the key: the Safe Browsing API is not turned on for this key's project",
    );
    expect(badge("Google Safe Browsing", "Not set")).toBeInTheDocument();
    expect(within(row("Google Safe Browsing")).queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();
    expect(keyField("Google Safe Browsing")).toHaveAttribute("placeholder", "Starts with AIza, 39 characters");
    // Nothing changed on the server, so the link-check line is not reloaded.
    expect(getLinkReputationStatus).toHaveBeenCalledTimes(1);
  });

  it("asks before removing a key and removes only that service's key", async () => {
    await mount({
      keys: keyList({ safe_browsing: { key_stored: true }, virustotal: { key_stored: true } }),
    });
    vi.mocked(removeSecurityKey).mockResolvedValue(undefined);

    fireEvent.click(button("Google Safe Browsing", "Remove"));
    const dialog = screen.getByRole("dialog", { name: "Remove the Google Safe Browsing key?" });
    expect(dialog).toHaveTextContent(
      "Link checks with Google stop until you add a key again; links are still checked on this computer.",
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(removeSecurityKey).not.toHaveBeenCalled();

    fireEvent.click(button("Google Safe Browsing", "Remove"));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Remove" }));

    expect(await within(row("Google Safe Browsing")).findByRole("status")).toHaveTextContent("Removed.");
    expect(vi.mocked(removeSecurityKey).mock.calls).toEqual([["safe_browsing"]]);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(badge("Google Safe Browsing", "Not set")).toBeInTheDocument();
    expect(badge("VirusTotal", "Saved")).toBeInTheDocument();
    expect(button("VirusTotal", "Remove")).toBeInTheDocument();
    await waitFor(() => expect(getLinkReputationStatus).toHaveBeenCalledTimes(2));
  });

  it("says link checks continue with the other Google key when one of two is removed", async () => {
    await mount({ keys: keyList({ safe_browsing: { key_stored: true }, web_risk: { key_stored: true } }) });

    fireEvent.click(button("Google Web Risk", "Remove"));

    expect(screen.getByRole("dialog", { name: "Remove the Google Web Risk key?" })).toHaveTextContent(
      "Link checks with Google continue with Google Safe Browsing; links are still checked on this computer.",
    );
  });

  it("shows a failed removal on the row and keeps the key saved", async () => {
    await mount({ keys: keyList({ hibp: { key_stored: true } }) });
    vi.mocked(removeSecurityKey).mockRejectedValue(
      new ApiError(
        "Stored service keys cannot be decrypted with the current ENCRYPTION_KEY; restore the key or clear the stored secrets",
        409,
      ),
    );

    fireEvent.click(button("Have I Been Pwned", "Remove"));
    expect(screen.getByRole("dialog")).toHaveTextContent(
      "Breach monitoring with Have I Been Pwned stops until you add a key again",
    );
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Remove" }));

    expect(await within(row("Have I Been Pwned")).findByRole("alert")).toHaveTextContent(
      "Stored service keys cannot be decrypted",
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(badge("Have I Been Pwned", "Saved")).toBeInTheDocument();
  });

  it("shows the link-check line: service used, lookups against the limit and the last problem", async () => {
    const at = "2026-10-14T12:04:00Z";
    await mount({
      keys: keyList({ safe_browsing: { key_stored: true } }),
      status: linkStatus({
        capability: "on",
        reason: "",
        service: "safe_browsing",
        lookups_last_day: 42,
        lookups_per_day: 2000,
        dangerous_found_last_day: 1,
        last_problem: { kind: "key_rejected", at, http_status: 403 },
      }),
    });

    const line = await screen.findByRole("region", { name: "Link checks with Google" });
    expect(line).toHaveTextContent(
      "Link checks: on · using Google Safe Browsing · 42 of 2,000 lookups in the last 24 hours · " +
        `1 dangerous link found · last problem: Google refused the key (HTTP 403) at ${shortTime(at)}`,
    );
    expect(line).not.toHaveTextContent("Web Risk is used");
    // The line sits under the two Google rows, before the other services.
    expect(row("Google Web Risk").compareDocumentPosition(line) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(line.compareDocumentPosition(row("Have I Been Pwned")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // Nothing on it ever calls a link safe (the service's own name aside).
    expect((line.textContent ?? "").replace(/Safe Browsing/g, "")).not.toMatch(/\bsafe\b/i);
  });

  it("names the other problems in plain words", async () => {
    const at = "2026-10-14T09:30:00Z";
    await mount({
      status: linkStatus({
        capability: "on",
        reason: "",
        service: "safe_browsing",
        last_problem: { kind: "timeout", at, http_status: null },
      }),
    });
    expect(await screen.findByRole("region", { name: "Link checks with Google" })).toHaveTextContent(
      `0 dangerous links found · last problem: Google did not answer in time at ${shortTime(at)}`,
    );
  });

  it("says Web Risk is used when both Google keys are saved", async () => {
    await mount({
      keys: keyList({ safe_browsing: { key_stored: true }, web_risk: { key_stored: true } }),
      status: linkStatus({
        capability: "on",
        reason: "",
        service: "web_risk",
        both_keys: true,
        lookups_last_day: 3,
      }),
    });

    const line = await screen.findByRole("region", { name: "Link checks with Google" });
    expect(line).toHaveTextContent(
      "Link checks: on · using Google Web Risk · 3 of 2,000 lookups in the last 24 hours · " +
        "0 dangerous links found · last problem: none",
    );
    expect(line).toHaveTextContent("Both Google keys are saved; Web Risk is used.");
  });

  it("says when link checks are paused after Google asked to slow down", async () => {
    const until = "2026-10-14T12:14:00Z";
    await mount({
      status: linkStatus({
        capability: "on",
        reason: "",
        service: "safe_browsing",
        cooling_down_until: until,
        last_problem: { kind: "rate_limited", at: "2026-10-14T12:04:00Z", http_status: 429 },
      }),
    });

    expect(await screen.findByRole("region", { name: "Link checks with Google" })).toHaveTextContent(
      `Paused until ${shortTime(until)} after Google asked to slow down.`,
    );
  });

  it("says link checks are off when the owner switched them off", async () => {
    await mount({
      keys: keyList({ safe_browsing: { key_stored: true } }),
      status: linkStatus({ capability: "off", reason: "", service: "safe_browsing" }),
    });

    const line = await screen.findByRole("region", { name: "Link checks with Google" });
    expect(line).toHaveTextContent(
      "Link checks with Google are turned off in Settings → Permissions. Links are still checked on this computer.",
    );
    expect(line).not.toHaveTextContent("Link checks: on");
  });

  it("shows the blocked reason when no Google key is saved", async () => {
    await mount({ status: linkStatus() });

    const line = await screen.findByRole("region", { name: "Link checks with Google" });
    expect(line).toHaveTextContent(BLOCKED_REASON);
    expect(line).not.toHaveTextContent("Link checks: on");
  });

  it("hides the link-check line when its status cannot be loaded and keeps the keys usable", async () => {
    await mount({ status: new ApiError("Link checks are not ready.", 503) });
    vi.mocked(saveSecurityKey).mockResolvedValue({
      ok: true,
      service: { ...ROWS.web_risk, key_stored: true },
    });

    await waitFor(() => expect(getLinkReputationStatus).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole("region", { name: "Link checks with Google" })).not.toBeInTheDocument();
    expect(screen.queryByText("Link checks are not ready.")).not.toBeInTheDocument();

    fireEvent.change(keyField("Google Web Risk"), { target: { value: FAKE_GOOGLE_KEY } });
    fireEvent.click(button("Google Web Risk", "Save"));
    expect(await within(row("Google Web Risk")).findByRole("status")).toHaveTextContent(
      "Saved. Google Web Risk accepted the key.",
    );
  });

  it("warns when saved keys cannot be decrypted", async () => {
    await mount({ keys: keyList({}, true) });

    const alerts = screen.getAllByRole("alert");
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toHaveTextContent(
      "Saved service keys can't be read with this server's current ENCRYPTION_KEY. Restore the old " +
        "key, or clear stored secrets in Settings, then add the keys again.",
    );
    // The rows stay listed so an .env key can still be tested.
    expect(screen.getAllByRole("heading", { level: 3 })).toHaveLength(4);
  });

  it("reports a load failure with a retry", async () => {
    vi.mocked(getSecurityKeys)
      .mockRejectedValueOnce(new ApiError("Request failed: Internal Server Error", 500))
      .mockResolvedValueOnce(keyList());
    vi.mocked(getLinkReputationStatus).mockResolvedValue(linkStatus());
    render(<ServiceKeysTab />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Request failed: Internal Server Error");
    expect(screen.queryByRole("region", { name: "Google Safe Browsing" })).not.toBeInTheDocument();

    fireEvent.click(within(alert).getByRole("button", { name: "Retry" }));

    expect(await screen.findByRole("region", { name: "Google Safe Browsing" })).toBeInTheDocument();
    expect(getSecurityKeys).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says only the owner can manage keys when the server answers 403", async () => {
    vi.mocked(getSecurityKeys).mockRejectedValue(
      new ApiError("Only the owner of this install can change this.", 403),
    );
    vi.mocked(getLinkReputationStatus).mockRejectedValue(
      new ApiError("Only the owner of this install can change this.", 403),
    );
    render(<ServiceKeysTab />);

    expect(
      await screen.findByText("Only the owner of this install can manage service keys."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(document.querySelectorAll("input")).toHaveLength(0);
  });
});
