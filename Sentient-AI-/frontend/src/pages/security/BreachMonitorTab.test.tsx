/**
 * Tests for BreachMonitorTab (Security ▸ Breach monitor): they prove a standard user sees only the
 * password check and never asks for the owner's overview; that the owner sees each watched address
 * with its last check, why nothing is sent (no key, switch off) and a way to the Service keys tab;
 * that adding, checking, pausing and removing an address each call the backend once and update only
 * their own row, with the server's refusals shown as sent; that breaches are marked handled one by
 * one or all at once, a sensitive one is never named, and the list carries the Have I Been Pwned
 * attribution; and that the password check sends only a 5-character prefix, clears the field, and
 * says "not checked" on a failure instead of ever calling a password safe.
 *
 * Why it exists: this tab is where the owner learns their address is in a breach and where anyone
 * checks a password. A failed lookup shown as "no breaches", a password sent whole or left in the
 * field, a row removed without asking, or a sensitive breach named on screen would each mislead or
 * expose the person the tab is meant to protect.
 */

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { BreachAddress, BreachCheckResult, BreachFinding, BreachOverview } from "@/types";

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
    getBreachMonitor: vi.fn(),
    addBreachAddress: vi.fn(),
    setBreachAddressPaused: vi.fn(),
    removeBreachAddress: vi.fn(),
    checkBreachAddress: vi.fn(),
    acknowledgeBreachFinding: vi.fn(),
    acknowledgeAllBreachFindings: vi.fn(),
    getPwnedRange: vi.fn(),
  };
});

import BreachMonitorTab from "@/pages/security/BreachMonitorTab";
import {
  ApiError,
  acknowledgeAllBreachFindings,
  acknowledgeBreachFinding,
  addBreachAddress,
  checkBreachAddress,
  getBreachMonitor,
  getPwnedRange,
  removeBreachAddress,
  setBreachAddressPaused,
} from "@/services/api";

const MEMBER_NOTE = "Breach monitoring of email addresses is set up by the owner of this Crawler.";
const NO_KEY_NOTE =
  "Breach checks use your own Have I Been Pwned key, and none is saved yet. Nothing is sent until you add one.";
const OFF_NOTE = "Breach monitoring is turned off in Settings → Permissions. Nothing is sent.";
// SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
const PASSWORD_PREFIX = "5BAA6";
const PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
const RANGE_SOURCE = "Pwned Passwords by Have I Been Pwned (haveibeenpwned.com)";

function address(overrides: Partial<BreachAddress>): BreachAddress {
  return {
    id: "a1",
    address: "kash@example.com",
    hint: "k•••@example.com",
    source: "account",
    status: "active",
    readable: true,
    last_checked_at: "2026-10-10T09:00:00Z",
    next_check_at: "2026-10-17T09:00:00Z",
    baseline_at: "2026-09-01T09:00:00Z",
    breach_count: 5,
    new_count: 1,
    last_error_code: null,
    last_error: null,
    ...overrides,
  };
}

function finding(overrides: Partial<BreachFinding>): BreachFinding {
  return {
    id: "f1",
    address_id: "a1",
    name: "ExampleShop",
    title: "Example Shop",
    domain: "example-shop.com",
    breach_date: "2026-08-30",
    added_at: "2026-10-12T03:11:00Z",
    pwn_count: 1200000,
    data_classes: ["Email addresses", "Passwords", "Phone numbers"],
    verified: true,
    sensitive: false,
    fabricated: false,
    spam_list: false,
    baseline: false,
    first_seen_at: "2026-10-13T09:00:12Z",
    alerted_at: "2026-10-13T09:00:13Z",
    acknowledged_at: null,
    ...overrides,
  };
}

const ACCOUNT = address({});
const ALT = address({
  id: "a2",
  address: "me.alt@example.org",
  hint: "m•••@example.org",
  source: "added",
  last_checked_at: null,
  baseline_at: null,
  breach_count: 0,
  new_count: 0,
});
const OLD = address({
  id: "a3",
  address: "old@example.net",
  hint: "o•••@example.net",
  source: "added",
  breach_count: 0,
  new_count: 0,
});
const SHOP = finding({});
const ADOBE = finding({
  id: "f2",
  name: "Adobe",
  title: "Adobe",
  domain: "adobe.com",
  breach_date: "2013-10-04",
  data_classes: ["Email addresses", "Password hints", "Passwords", "Usernames"],
  baseline: true,
  first_seen_at: "2026-09-01T09:00:00Z",
  alerted_at: null,
  acknowledged_at: "2026-09-01T09:00:00Z",
});

function overview(overrides: Partial<BreachOverview> = {}): BreachOverview {
  return {
    state: "on",
    reason: "",
    switch_on: true,
    key_configured: true,
    check_every_days: 7,
    max_addresses: 10,
    account_note: null,
    addresses: [ACCOUNT, ALT],
    findings: [SHOP, ADOBE],
    attribution: { text: "Breach data: Have I Been Pwned", url: "https://haveibeenpwned.com" },
    ...overrides,
  };
}

async function watchedRows(): Promise<HTMLElement[]> {
  const list = await screen.findByRole("list", { name: "Watched addresses" });
  return within(list).getAllByRole("listitem");
}

async function breachRows(): Promise<HTMLElement[]> {
  const list = await screen.findByRole("list", { name: "Breaches found" });
  return within(list).getAllByRole("listitem");
}

function renderOwner(data: BreachOverview, onOpenKeys = vi.fn()) {
  vi.mocked(getBreachMonitor).mockResolvedValue(data);
  render(<BreachMonitorTab isOwner onOpenKeys={onOpenKeys} />);
  return onOpenKeys;
}

describe("BreachMonitorTab", () => {
  afterEach(() => {
    for (const fn of [
      getBreachMonitor,
      addBreachAddress,
      setBreachAddressPaused,
      removeBreachAddress,
      checkBreachAddress,
      acknowledgeBreachFinding,
      acknowledgeAllBreachFindings,
      getPwnedRange,
    ]) {
      vi.mocked(fn).mockReset();
    }
  });

  it("a non-owner sees only the password check and the breach overview is never requested", async () => {
    render(<BreachMonitorTab isOwner={false} onOpenKeys={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "Breach monitor" })).toBeInTheDocument();
    expect(screen.getByText(MEMBER_NOTE)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Check a password" })).toBeInTheDocument();
    expect(screen.getByLabelText("Password to check")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Watched addresses" })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Breaches" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Loading the breach monitor/)).not.toBeInTheDocument();
    await Promise.resolve();
    expect(getBreachMonitor).not.toHaveBeenCalled();
  });

  it("the owner sees each watched address with its last check and breach count, and the sign-in address has no Remove button", async () => {
    renderOwner(overview());

    expect(screen.getByText("Loading the breach monitor…")).toBeInTheDocument();
    const [account, alt] = await watchedRows();
    expect(
      screen.getByText("Crawler checks 2 addresses every week with your Have I Been Pwned key."),
    ).toBeInTheDocument();
    expect(account).toHaveTextContent("kash@example.com");
    expect(account).toHaveTextContent("Your sign-in address");
    expect(account).toHaveTextContent(/Last checked .+ · in 5 known breaches · 1 new/);
    expect(within(account).getByRole("button", { name: "Check now: kash@example.com" })).toBeInTheDocument();
    expect(within(account).getByRole("button", { name: "Pause checks of kash@example.com" })).toBeInTheDocument();
    expect(within(account).queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();

    expect(alt).toHaveTextContent("me.alt@example.org");
    expect(alt).toHaveTextContent("Not checked yet");
    expect(alt).not.toHaveTextContent("Your sign-in address");
    expect(within(alt).getByRole("button", { name: "Remove me.alt@example.org" })).toBeInTheDocument();
    expect(getBreachMonitor).toHaveBeenCalledTimes(1);
  });

  it("without a key the tab says nothing is sent until a Have I Been Pwned key is added and Open Service keys calls onOpenKeys", async () => {
    const onOpenKeys = renderOwner(
      overview({
        state: "blocked",
        reason: "Breach checks use your own Have I Been Pwned key, and none is saved yet. Add one in Security → Service keys.",
        key_configured: false,
      }),
    );

    expect(await screen.findByText(NO_KEY_NOTE)).toBeInTheDocument();
    // Nothing would be sent, so no row offers Check now; the list and the form stay usable.
    const rows = await watchedRows();
    expect(within(rows[0]).queryByRole("button", { name: /^Check now/ })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Add an address you own")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Open Service keys" }));
    expect(onOpenKeys).toHaveBeenCalledTimes(1);
  });

  it("when the switch is off the tab says breach monitoring is turned off in Settings and nothing is sent", async () => {
    renderOwner(overview({ state: "off", reason: "Breach monitoring is off.", switch_on: false }));

    expect(await screen.findByText(OFF_NOTE)).toBeInTheDocument();
    expect(screen.queryByText(NO_KEY_NOTE)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open Service keys" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Crawler checks \d+ address/)).not.toBeInTheDocument();
  });

  it("adding an address posts it once, shows the new row, clears the field and checks it at once", async () => {
    const created = address({
      id: "a9",
      address: "new@example.net",
      hint: "n•••@example.net",
      source: "added",
      last_checked_at: null,
      baseline_at: null,
      breach_count: 0,
      new_count: 0,
    });
    vi.mocked(addBreachAddress).mockResolvedValue(created);
    vi.mocked(checkBreachAddress).mockResolvedValue({
      outcome: "checked",
      address: { ...created, last_checked_at: "2026-10-14T10:00:00Z", baseline_at: "2026-10-14T10:00:00Z" },
      new_findings: [],
      note: "Have I Been Pwned lists this address in no breach it knows of.",
    });
    renderOwner(overview({ addresses: [ACCOUNT], findings: [] }));

    const field = await screen.findByLabelText("Add an address you own");
    fireEvent.change(field, { target: { value: " new@example.net " } });
    fireEvent.click(screen.getByRole("button", { name: "Watch this address" }));

    expect(await screen.findByText("new@example.net")).toBeInTheDocument();
    expect(vi.mocked(addBreachAddress).mock.calls).toEqual([["new@example.net"]]);
    expect(field).toHaveValue("");
    await waitFor(() => expect(vi.mocked(checkBreachAddress).mock.calls).toEqual([["a9"]]));
    expect(await screen.findByText("Have I Been Pwned lists this address in no breach it knows of.")).toBeInTheDocument();
    const rows = await watchedRows();
    expect(rows).toHaveLength(2);
    expect(rows[1]).toHaveTextContent(/Last checked .+ · in no known breaches/);
  });

  it("the server's refusal to add an address is shown beside the form as it was sent", async () => {
    vi.mocked(addBreachAddress).mockRejectedValue(
      new ApiError("That is your sign-in address; it is already watched.", 409),
    );
    renderOwner(overview());

    const field = await screen.findByLabelText("Add an address you own");
    fireEvent.change(field, { target: { value: "kash@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Watch this address" }));

    const form = screen.getByRole("form", { name: "Add an address to watch" });
    expect(await within(form).findByRole("alert")).toHaveTextContent(
      /^That is your sign-in address; it is already watched\.$/,
    );
    expect(field).toHaveValue("kash@example.com");
    expect(await watchedRows()).toHaveLength(2);
    expect(checkBreachAddress).not.toHaveBeenCalled();
  });

  it("Check now shows the new breaches from the answer, and a failed lookup says not checked rather than no breaches", async () => {
    const altFinding = finding({ id: "f9", address_id: "a2", title: "Other Shop", domain: "other-shop.com" });
    vi.mocked(checkBreachAddress).mockImplementation(async (id: string): Promise<BreachCheckResult> => {
      if (id === "a2") {
        return {
          outcome: "checked",
          address: { ...ALT, last_checked_at: "2026-10-14T10:00:00Z", breach_count: 1, new_count: 1 },
          new_findings: [altFinding],
          note: "Found in 1 new breach.",
        };
      }
      return {
        outcome: "not_checked",
        address: {
          ...ACCOUNT,
          last_error_code: "unavailable",
          last_error: "Have I Been Pwned could not be reached.",
          next_check_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        },
        new_findings: [],
        note: "Not checked: Have I Been Pwned could not be reached. Crawler tries again in 1 hour.",
      };
    });
    renderOwner(overview({ findings: [ADOBE] }));

    fireEvent.click(await screen.findByRole("button", { name: "Check now: me.alt@example.org" }));
    const [, alt] = await watchedRows();
    expect(await within(alt).findByRole("status")).toHaveTextContent(/^Found in 1 new breach\.$/);
    expect(alt).toHaveTextContent(/Last checked .+ · in 1 known breach · 1 new/);
    const breaches = await breachRows();
    expect(breaches[0]).toHaveTextContent("NEW");
    expect(breaches[0]).toHaveTextContent("Other Shop · other-shop.com");
    expect(breaches[0]).toHaveTextContent("me.alt@example.org · exposed: email addresses, passwords, phone numbers");

    fireEvent.click(screen.getByRole("button", { name: "Check now: kash@example.com" }));
    const [account] = await watchedRows();
    expect(await within(account).findByRole("alert")).toHaveTextContent(
      "Not checked: Have I Been Pwned could not be reached. Crawler tries again in 1 hour.",
    );
    expect(account).toHaveTextContent("Last check failed: Have I Been Pwned could not be reached.");
    expect(account).not.toHaveTextContent(/no (known )?breach/i);
    expect(vi.mocked(checkBreachAddress).mock.calls).toEqual([["a2"], ["a1"]]);
  });

  it("a 429 from Check now shows its wait message and leaves the row as it was", async () => {
    vi.mocked(checkBreachAddress).mockRejectedValue(
      new ApiError("Checked moments ago. Try again in 240 seconds.", 429),
    );
    renderOwner(overview());

    const [before] = await watchedRows();
    const detailsBefore = within(before).getByText(/Last checked/).textContent;
    fireEvent.click(within(before).getByRole("button", { name: "Check now: kash@example.com" }));

    const [account] = await watchedRows();
    expect(await within(account).findByRole("alert")).toHaveTextContent(
      /^Checked moments ago\. Try again in 240 seconds\.$/,
    );
    expect(within(account).getByText(/Last checked/).textContent).toBe(detailsBefore);
    expect(account).toHaveTextContent("in 5 known breaches · 1 new");
    expect(within(account).getByRole("button", { name: "Check now: kash@example.com" })).toBeEnabled();
    expect(await breachRows()).toHaveLength(2);
  });

  it("Remove asks first and removes only its own row", async () => {
    const oldFinding = finding({ id: "f7", address_id: "a3", title: "Old Forum", domain: "old-forum.net" });
    vi.mocked(removeBreachAddress).mockResolvedValue(undefined);
    renderOwner(overview({ addresses: [ACCOUNT, ALT, OLD], findings: [SHOP, oldFinding] }));

    fireEvent.click(await screen.findByRole("button", { name: "Remove me.alt@example.org" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("Stop watching me.alt@example.org?");
    expect(removeBreachAddress).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(vi.mocked(removeBreachAddress).mock.calls).toEqual([["a2"]]);
    const rows = await watchedRows();
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("kash@example.com");
    expect(rows[1]).toHaveTextContent("old@example.net");
    expect(screen.queryByText("me.alt@example.org")).not.toBeInTheDocument();
    expect(await breachRows()).toHaveLength(2);
  });

  it("a failed Remove keeps the row and shows the server's reason in the dialog", async () => {
    vi.mocked(removeBreachAddress).mockRejectedValue(new ApiError("No such address.", 404));
    renderOwner(overview());

    fireEvent.click(await screen.findByRole("button", { name: "Remove me.alt@example.org" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    expect(await within(dialog).findByText("No such address.")).toBeInTheDocument();
    expect(await watchedRows()).toHaveLength(2);
  });

  it("Mark as handled moves a finding out of the new list, and Mark all as handled acknowledges every one", async () => {
    const other = finding({ id: "f3", address_id: "a2", title: "Other Shop", domain: "other-shop.com" });
    vi.mocked(acknowledgeBreachFinding).mockImplementation(async (id: string) => ({
      ...(id === "f1" ? SHOP : other),
      acknowledged_at: "2026-10-14T10:00:00Z",
    }));
    vi.mocked(acknowledgeAllBreachFindings).mockResolvedValue({ acknowledged: 1 });
    renderOwner(overview({ findings: [SHOP, other, ADOBE] }));

    let rows = await breachRows();
    expect(rows.map((row) => row.textContent?.startsWith("NEW"))).toEqual([true, true, false]);
    expect(rows[2]).toHaveTextContent("Known before monitoring started");
    expect(rows[2]).toHaveTextContent("Handled");

    fireEvent.click(within(rows[0]).getByRole("button", { name: "Mark as handled: Example Shop (kash@example.com)" }));
    await waitFor(() =>
      expect(
        within(screen.getByRole("list", { name: "Breaches found" })).getAllByRole("listitem")[0],
      ).toHaveTextContent("Other Shop"),
    );
    rows = await breachRows();
    expect(rows.map((row) => row.textContent?.startsWith("NEW"))).toEqual([true, false, false]);
    expect(rows[1]).toHaveTextContent("Example Shop");
    expect(within(rows[1]).queryByRole("button", { name: /^Mark as handled/ })).not.toBeInTheDocument();
    expect(vi.mocked(acknowledgeBreachFinding).mock.calls).toEqual([["f1"]]);
    const [account] = await watchedRows();
    expect(account).not.toHaveTextContent("1 new");

    fireEvent.click(screen.getByRole("button", { name: "Mark all as handled" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Mark all as handled" })).not.toBeInTheDocument());
    expect(acknowledgeAllBreachFindings).toHaveBeenCalledTimes(1);
    rows = await breachRows();
    expect(rows.map((row) => row.textContent?.startsWith("NEW"))).toEqual([false, false, false]);
    expect(screen.queryByRole("button", { name: /^Mark as handled/ })).not.toBeInTheDocument();
  });

  it("a sensitive breach is shown without its title", async () => {
    const sensitive = finding({
      id: "f5",
      name: "SecretSite",
      title: "Secret Site",
      domain: "secret-site.example",
      sensitive: true,
    });
    renderOwner(overview({ findings: [sensitive] }));

    const [row] = await breachRows();
    expect(row).toHaveTextContent("A breach marked sensitive");
    expect(row).not.toHaveTextContent(/Secret ?Site/i);
    expect(row).not.toHaveTextContent("secret-site.example");
    expect(within(row).getByRole("button", { name: "Mark as handled: A breach marked sensitive (kash@example.com)" })).toBeInTheDocument();
  });

  it("the breach list carries the Have I Been Pwned attribution link opening in a new tab", async () => {
    renderOwner(overview());

    const link = await screen.findByRole("link", { name: /Breach data: Have I Been Pwned/ });
    expect(link).toHaveAttribute("href", "https://haveibeenpwned.com");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveAccessibleName(/opens in a new tab/);
  });

  it("an empty breach list says nothing was found so far, without the attribution link or Mark all as handled", async () => {
    renderOwner(overview({ findings: [] }));

    expect(await screen.findByText("No breaches are recorded for the addresses checked so far.")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Have I Been Pwned/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Mark all as handled" })).not.toBeInTheDocument();
  });

  it("the password check shows the breach count, clears the field, and the request holds only the five-character prefix", async () => {
    vi.mocked(getPwnedRange).mockImplementation(async (prefix: string) => ({
      prefix,
      suffixes: [
        ["0018A45C4D1DEF81644B54AB7F969B88D65", 1],
        [PASSWORD_SUFFIX, 52256],
      ],
      source: RANGE_SOURCE,
    }));
    render(<BreachMonitorTab isOwner={false} />);

    const field = screen.getByLabelText("Password to check");
    expect(field).toHaveAttribute("type", "password");
    expect(field).toHaveAttribute("autocomplete", "off");
    expect(field).toHaveAttribute("spellcheck", "false");
    expect(field).not.toHaveAttribute("name");
    fireEvent.change(field, { target: { value: "password" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      `This password has appeared in ${(52256).toLocaleString()} data breaches. Don't use it; change it wherever you use it.`,
    );
    expect(field).toHaveValue("");
    expect(vi.mocked(getPwnedRange).mock.calls).toEqual([[PASSWORD_PREFIX]]);
    expect(JSON.stringify(vi.mocked(getPwnedRange).mock.calls)).not.toContain("password");
    expect(screen.queryByDisplayValue("password")).not.toBeInTheDocument();
  });

  it("the password check says not checked when the service fails and never calls a password safe", async () => {
    vi.mocked(getPwnedRange)
      .mockRejectedValueOnce(new ApiError("Not checked: the Pwned Passwords service could not be reached.", 503))
      .mockImplementationOnce(async (prefix: string) => ({ prefix, suffixes: [], source: RANGE_SOURCE }));
    render(<BreachMonitorTab isOwner={false} />);

    const field = screen.getByLabelText("Password to check");
    fireEvent.change(field, { target: { value: "hunter2" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /^Not checked: the Pwned Passwords service could not be reached\. Try again later\.$/,
    );
    expect(field).toHaveValue("");
    expect(document.body.textContent).not.toMatch(/safe|not found|no breaches/i);

    fireEvent.change(field, { target: { value: "hunter2" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));
    expect(
      await screen.findByText(
        "Not found in Have I Been Pwned's list of leaked passwords. That doesn't make it strong: a long password used nowhere else is still best.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Not checked/)).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/safe/i);
  });

  it("the password check shows the server's own sentence under Not checked when breach checks are off or it is asked too often", async () => {
    vi.mocked(getPwnedRange).mockRejectedValue(
      new ApiError("The owner turned off breach checks in Settings → Permissions.", 403),
    );
    render(<BreachMonitorTab isOwner={false} />);

    fireEvent.change(screen.getByLabelText("Password to check"), { target: { value: "hunter2" } });
    fireEvent.click(screen.getByRole("button", { name: "Check" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /^Not checked: The owner turned off breach checks in Settings → Permissions\.$/,
    );
  });

  it("the password check sends nothing while the field is empty", async () => {
    render(<BreachMonitorTab isOwner={false} />);

    const button = screen.getByRole("button", { name: "Check" });
    expect(button).toBeDisabled();
    fireEvent.submit(screen.getByRole("form", { name: "Check a password" }));
    fireEvent.change(screen.getByLabelText("Password to check"), { target: { value: "x" } });
    expect(button).toBeEnabled();
    fireEvent.change(screen.getByLabelText("Password to check"), { target: { value: "" } });
    expect(button).toBeDisabled();
    await Promise.resolve();

    expect(getPwnedRange).not.toHaveBeenCalled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("a failed load shows the error with Try again, and Try again loads the monitor", async () => {
    vi.mocked(getBreachMonitor)
      .mockRejectedValueOnce(new ApiError("The server is still starting. Try again shortly.", 503))
      .mockResolvedValueOnce(overview());
    render(<BreachMonitorTab isOwner onOpenKeys={vi.fn()} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("The server is still starting. Try again shortly.");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await watchedRows()).toHaveLength(2);
    expect(getBreachMonitor).toHaveBeenCalledTimes(2);
  });

  it("Pause and Resume switch the row, and a paused address offers no Check now", async () => {
    vi.mocked(setBreachAddressPaused).mockImplementation(async (id: string, paused: boolean) => ({
      ...(id === "a1" ? ACCOUNT : ALT),
      status: paused ? "paused" : "active",
    }));
    renderOwner(overview());

    fireEvent.click(await screen.findByRole("button", { name: "Pause checks of kash@example.com" }));
    const resume = await screen.findByRole("button", { name: "Resume checks of kash@example.com" });
    let [account] = await watchedRows();
    expect(account).toHaveTextContent("Paused: Crawler does not check this address until you resume it.");
    expect(within(account).queryByRole("button", { name: /^Check now/ })).not.toBeInTheDocument();
    expect(screen.getByText("Crawler checks 1 address every week with your Have I Been Pwned key.")).toBeInTheDocument();

    fireEvent.click(resume);
    expect(await screen.findByRole("button", { name: "Check now: kash@example.com" })).toBeInTheDocument();
    [account] = await watchedRows();
    expect(account).not.toHaveTextContent("Paused");
    expect(vi.mocked(setBreachAddressPaused).mock.calls).toEqual([
      ["a1", true],
      ["a1", false],
    ]);
  });

  it("an address that can no longer be read shows only its sentence and Remove", async () => {
    const unreadable = address({
      id: "a4",
      address: null,
      hint: "",
      source: "added",
      status: "error",
      readable: false,
      last_error_code: "unreadable",
      last_error: "This address can no longer be read (the server's encryption key changed). Remove it and add it again.",
    });
    renderOwner(overview({ addresses: [ACCOUNT, unreadable], findings: [] }));

    const [, row] = await watchedRows();
    expect(row).toHaveTextContent(
      "This address can no longer be read (the server's encryption key changed). Remove it and add it again.",
    );
    expect(within(row).getAllByRole("button").map((b) => b.textContent)).toEqual(["Remove"]);
  });

  it("a failed check the server will retry says when, a stopped address says to press Check now, and the account note is shown", async () => {
    const retrying = address({
      id: "a5",
      address: "retry@example.com",
      source: "added",
      last_checked_at: null,
      last_error_code: "unavailable",
      last_error: "Have I Been Pwned could not be reached.",
      next_check_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
    });
    const stopped = address({
      id: "a6",
      address: "stopped@example.com",
      source: "added",
      status: "error",
      last_error_code: "timeout",
      last_error: "Have I Been Pwned did not answer in time.",
    });
    renderOwner(
      overview({
        addresses: [retrying, stopped],
        findings: [],
        account_note:
          "Your sign-in address (admin@localhost) is not a mailbox address Have I Been Pwned can look up. Add the addresses you use below.",
      }),
    );

    const [first, second] = await watchedRows();
    expect(first).toHaveTextContent(
      "Last check failed: Have I Been Pwned could not be reached. Crawler tries again in 2 hours.",
    );
    expect(first).not.toHaveTextContent("Not checked yet");
    expect(second).toHaveTextContent(
      "Checks stopped: Have I Been Pwned did not answer in time. Press Check now to try again.",
    );
    expect(
      screen.getByText(
        "Your sign-in address (admin@localhost) is not a mailbox address Have I Been Pwned can look up. Add the addresses you use below.",
      ),
    ).toBeInTheDocument();
  });

  it("while checks are off or have no key, a stopped or failed address promises neither Check now nor a retry", async () => {
    const retrying = address({
      id: "a5",
      address: "retry@example.com",
      source: "added",
      last_checked_at: null,
      last_error_code: "unavailable",
      last_error: "Have I Been Pwned could not be reached.",
      next_check_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
    });
    const stopped = address({
      id: "a6",
      address: "stopped@example.com",
      source: "added",
      status: "error",
      last_error_code: "timeout",
      last_error: "Have I Been Pwned did not answer in time.",
    });
    for (const state of ["off", "blocked"] as const) {
      renderOwner(overview({ state, key_configured: state === "off", addresses: [retrying, stopped], findings: [] }));
      const [first, second] = await watchedRows();
      expect(first).toHaveTextContent("Last check failed: Have I Been Pwned could not be reached.");
      expect(first).not.toHaveTextContent(/tries again/i);
      expect(second).toHaveTextContent("Checks stopped: Have I Been Pwned did not answer in time.");
      expect(second).not.toHaveTextContent(/Press Check now/);
      expect(screen.queryByRole("button", { name: /^Check now/ })).not.toBeInTheDocument();
      cleanup();
    }
  });

  it("a not_checked answer that somehow came back without a note names Have I Been Pwned, never the password service", async () => {
    vi.mocked(checkBreachAddress).mockResolvedValue({
      outcome: "not_checked",
      address: ACCOUNT,
      new_findings: [],
      note: "",
    });
    renderOwner(overview());

    fireEvent.click(await screen.findByRole("button", { name: "Check now: kash@example.com" }));
    const [account] = await watchedRows();
    const alert = await within(account).findByRole("alert");
    expect(alert).toHaveTextContent(/^Not checked: Have I Been Pwned could not be reached\.$/);
    expect(alert).not.toHaveTextContent(/Pwned Passwords/);
  });
});
