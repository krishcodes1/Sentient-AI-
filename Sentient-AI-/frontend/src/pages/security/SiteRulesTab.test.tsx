/**
 * Tests for SiteRulesTab (Security ▸ Site rules, owner only): they prove the owner's rules, the four
 * built-in sensitive-site lists and the recent hits are shown once loaded; that the switch being off
 * is said plainly without hiding anything; that a failed load can be retried; that adding, changing
 * and removing a rule sends exactly what the owner chose and shows the server's reason for a refusal
 * as written; that a row someone else already removed makes the list be read again; that a list's
 * kind can be changed and reset, and its sites trusted or blocked one by one; that "Check a site"
 * shows the server's own explanation; and that the rule limit, saving and empty states read right.
 *
 * Why it exists: these rules decide which sites Crawler's browser never opens and where every
 * action carries a "sensitive site" warning. A form that sent the wrong kind, a refusal the owner
 * never saw, a row removed without asking, or a select that kept showing a kind the server refused
 * would each leave Crawler following rules the owner did not choose.
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SiteCategory, SiteHit, SiteRule, SiteRulesView } from "@/types";

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
    getSiteRules: vi.fn(),
    createSiteRule: vi.fn(),
    updateSiteRule: vi.fn(),
    deleteSiteRule: vi.fn(),
    setSiteCategory: vi.fn(),
    checkSite: vi.fn(),
  };
});

import SiteRulesTab from "@/pages/security/SiteRulesTab";
import {
  ApiError,
  checkSite,
  createSiteRule,
  deleteSiteRule,
  getSiteRules,
  setSiteCategory,
  updateSiteRule,
} from "@/services/api";

const STAMP = "2026-10-14T12:00:00+00:00";

function rule(overrides: Partial<SiteRule>): SiteRule {
  return {
    id: "r1",
    pattern: "*.example-casino.com",
    host: "example-casino.com",
    include_subdomains: true,
    kind: "blocked",
    overrides_builtin: false,
    created_at: STAMP,
    updated_at: STAMP,
    ...overrides,
  };
}

function category(overrides: Partial<SiteCategory>): SiteCategory {
  return {
    key: "banks",
    label: "Banks and money accounts",
    kind: "always_ask",
    default_kind: "always_ask",
    site_count: 52,
    sites: ["chase.com", "bankofamerica.com"],
    ...overrides,
  };
}

const CASINO = rule({});
const DOCS = rule({
  id: "r2",
  pattern: "docs.mybank.example",
  host: "docs.mybank.example",
  include_subdomains: false,
  kind: "trusted",
});
const CATEGORIES: SiteCategory[] = [
  category({}),
  category({
    key: "brokers",
    label: "Brokers and investing",
    kind: "blocked",
    site_count: 33,
    sites: ["fidelity.com"],
  }),
  category({ key: "crypto", label: "Crypto exchanges and wallets", site_count: 26, sites: ["coinbase.com"] }),
  category({ key: "government", label: "Tax and government services", site_count: 30, sites: ["irs.gov"] }),
];

function minutesAgo(minutes: number): string {
  return new Date(Date.now() - minutes * 60_000).toISOString();
}

function hits(): SiteHit[] {
  return [
    { host: "chase.com", kind: "always_ask", where: "read", count: 3, last_at: minutesAgo(2) },
    { host: "example-casino.com", kind: "blocked", where: "navigation", count: 1, last_at: minutesAgo(10) },
  ];
}

function view(overrides: Partial<SiteRulesView> = {}): SiteRulesView {
  return {
    enabled: true,
    rules: [CASINO, DOCS],
    categories: CATEGORIES,
    recent: hits(),
    max_rules: 500,
    ...overrides,
  };
}

const OFF_NOTE =
  "Site rules are off (Settings → Permissions → “Site rules for Crawler's browser”), so nothing on this tab applies right now.";

/** A promise the test settles by hand, to look at the tab while a request is in flight. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (err: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

async function renderLoaded(data: SiteRulesView = view()) {
  vi.mocked(getSiteRules).mockResolvedValue(data);
  render(<SiteRulesTab />);
  await screen.findByRole("region", { name: "Your rules" });
}

const region = (name: string) => screen.getByRole("region", { name });
const rowOf = (control: HTMLElement) => control.closest("li") as HTMLElement;

describe("SiteRulesTab", () => {
  beforeEach(() => {
    vi.mocked(getSiteRules).mockReset();
    vi.mocked(getSiteRules).mockResolvedValue(view());
    vi.mocked(createSiteRule).mockReset();
    vi.mocked(updateSiteRule).mockReset();
    vi.mocked(deleteSiteRule).mockReset();
    vi.mocked(setSiteCategory).mockReset();
    vi.mocked(checkSite).mockReset();
  });

  it("renders the owner's rules, the four categories with site counts, and the recent hits after loading", async () => {
    render(<SiteRulesTab />);

    expect(screen.getByRole("region", { name: "Site rules" })).toBeInTheDocument();
    expect(screen.getByText("Loading site rules…")).toBeInTheDocument();

    const rules = await screen.findByRole("region", { name: "Your rules" });
    expect(within(rules).getByText("2 of 500")).toBeInTheDocument();
    expect(within(rules).getByText("example-casino.com and subdomains")).toBeInTheDocument();
    expect(within(rules).getByText("docs.mybank.example")).toBeInTheDocument();
    expect(screen.getByLabelText("Rule for example-casino.com and subdomains")).toHaveValue("blocked");
    expect(screen.getByLabelText("Rule for docs.mybank.example")).toHaveValue("trusted");

    const builtin = region("Built-in sensitive sites");
    for (const [label, count] of [
      ["Banks and money accounts", "52 sites"],
      ["Brokers and investing", "33 sites"],
      ["Crypto exchanges and wallets", "26 sites"],
      ["Tax and government services", "30 sites"],
    ]) {
      const row = rowOf(within(builtin).getByText(label));
      expect(within(row).getByText(count)).toBeInTheDocument();
    }
    expect(screen.getByLabelText("Rule for Banks and money accounts")).toHaveValue("always_ask");
    expect(screen.getByLabelText("Rule for Brokers and investing")).toHaveValue("blocked");

    const recent = region("Recently stopped or flagged");
    expect(within(recent).getAllByRole("listitem").map((row) => row.textContent)).toEqual([
      "chase.comAlways ask · read · 3 times · 2 min ago",
      "example-casino.comBlocked · navigation · 1 time · 10 min ago",
    ]);
    expect(screen.queryByText(OFF_NOTE)).not.toBeInTheDocument();
  });

  it("shows the off banner when the switch is off and still lists the rules", async () => {
    await renderLoaded(view({ enabled: false }));

    expect(screen.getByRole("status")).toHaveTextContent(OFF_NOTE);
    expect(screen.getByText("example-casino.com and subdomains")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add rule" })).toBeEnabled();
  });

  it("a failed load shows the server's reason and Retry loads again", async () => {
    vi.mocked(getSiteRules)
      .mockRejectedValueOnce(new ApiError("Only the owner of this install can change this.", 403))
      .mockResolvedValueOnce(view());
    render(<SiteRulesTab />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Only the owner of this install can change this.");
    expect(screen.queryByRole("region", { name: "Your rules" })).not.toBeInTheDocument();

    fireEvent.click(within(alert).getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("example-casino.com and subdomains")).toBeInTheDocument();
    expect(getSiteRules).toHaveBeenCalledTimes(2);
  });

  it("Add posts the typed site, the include-subdomains box and the chosen kind, then shows the new row", async () => {
    vi.mocked(createSiteRule).mockResolvedValue(
      rule({
        id: "r3",
        pattern: "shop.example.com",
        host: "shop.example.com",
        include_subdomains: false,
        kind: "always_ask",
      }),
    );
    await renderLoaded();

    const site = screen.getByLabelText("Site");
    expect(screen.getByLabelText("Include subdomains (www., login., …)")).toBeChecked();
    expect(screen.getByLabelText("Rule")).toHaveValue("blocked");
    fireEvent.change(site, { target: { value: "  https://Shop.Example.com/cart  " } });
    fireEvent.click(screen.getByLabelText("Include subdomains (www., login., …)"));
    fireEvent.change(screen.getByLabelText("Rule"), { target: { value: "always_ask" } });
    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));

    expect(await screen.findByText("shop.example.com")).toBeInTheDocument();
    expect(vi.mocked(createSiteRule).mock.calls).toEqual([
      [{ site: "https://Shop.Example.com/cart", include_subdomains: false, kind: "always_ask" }],
    ]);
    expect(screen.getByLabelText("Rule for shop.example.com")).toHaveValue("always_ask");
    expect(within(region("Your rules")).getByText("3 of 500")).toBeInTheDocument();
    expect(site).toHaveValue("");
  });

  it("a 422 from the server is shown next to the form as written and the typed site is kept", async () => {
    const reason = "*.com would cover a whole top-level domain. Pick a site, like example.com.";
    vi.mocked(createSiteRule).mockRejectedValue(new ApiError(reason, 422));
    await renderLoaded();

    fireEvent.change(screen.getByLabelText("Site"), { target: { value: "*.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));

    const form = screen.getByRole("form", { name: "Add a site rule" });
    expect(await within(form).findByRole("alert")).toHaveTextContent(reason);
    expect(screen.getByLabelText("Site")).toHaveValue("*.com");
    expect(within(region("Your rules")).getAllByRole("listitem")).toHaveLength(2);
  });

  it("a 409 duplicate message is shown as written", async () => {
    const reason = "There is already a rule for example-casino.com. Change that one instead.";
    vi.mocked(createSiteRule).mockRejectedValue(new ApiError(reason, 409));
    await renderLoaded();

    fireEvent.change(screen.getByLabelText("Site"), { target: { value: "www.example-casino.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));

    const form = screen.getByRole("form", { name: "Add a site rule" });
    expect(await within(form).findByRole("alert")).toHaveTextContent(reason);
  });

  it("an empty site is refused before asking the server", async () => {
    await renderLoaded();

    fireEvent.change(screen.getByLabelText("Site"), { target: { value: "   " } });
    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));

    const form = screen.getByRole("form", { name: "Add a site rule" });
    expect(await within(form).findByRole("alert")).toHaveTextContent("Type a site, like example.com.");
    expect(createSiteRule).not.toHaveBeenCalled();
  });

  it("changing a row's kind patches only that row; a failed patch puts the old kind back and shows why", async () => {
    const lookalike =
      "This address uses look-alike characters (xn--pple-43d.com, which reads as apple.com), so it cannot be marked Trusted. You can block it.";
    vi.mocked(updateSiteRule)
      .mockResolvedValueOnce({ ...DOCS, kind: "always_ask" })
      .mockRejectedValueOnce(new ApiError(lookalike, 422));
    await renderLoaded();

    const docs = screen.getByLabelText("Rule for docs.mybank.example");
    fireEvent.change(docs, { target: { value: "always_ask" } });
    await waitFor(() => expect(docs).toBeEnabled());
    expect(docs).toHaveValue("always_ask");
    expect(screen.getByLabelText("Rule for example-casino.com and subdomains")).toHaveValue("blocked");

    const casino = screen.getByLabelText("Rule for example-casino.com and subdomains");
    fireEvent.change(casino, { target: { value: "trusted" } });
    expect(await within(rowOf(casino)).findByRole("alert")).toHaveTextContent(lookalike);
    expect(casino).toHaveValue("blocked");
    expect(docs).toHaveValue("always_ask");
    expect(vi.mocked(updateSiteRule).mock.calls).toEqual([
      ["r2", "always_ask"],
      ["r1", "trusted"],
    ]);
  });

  it("Remove asks first; confirming deletes only that row; cancelling keeps it", async () => {
    vi.mocked(deleteSiteRule).mockResolvedValue(undefined);
    await renderLoaded();

    const remove = screen.getByRole("button", { name: "Remove the rule for example-casino.com and subdomains" });
    fireEvent.click(remove);
    let dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("Remove this site rule?");
    expect(dialog).toHaveTextContent("Crawler stops treating example-casino.com and subdomains as Blocked.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(deleteSiteRule).not.toHaveBeenCalled();
    expect(screen.getByText("example-casino.com and subdomains")).toBeInTheDocument();

    fireEvent.click(remove);
    dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(vi.mocked(deleteSiteRule).mock.calls).toEqual([["r1"]]);
    expect(screen.queryByText("example-casino.com and subdomains")).not.toBeInTheDocument();
    expect(within(region("Your rules")).getAllByRole("listitem")).toHaveLength(1);
    expect(screen.getByText("docs.mybank.example")).toBeInTheDocument();
  });

  it("a failed remove keeps the row and shows the server's reason in the dialog", async () => {
    vi.mocked(deleteSiteRule).mockRejectedValue(new ApiError("The rule could not be removed right now.", 500));
    await renderLoaded();

    fireEvent.click(screen.getByRole("button", { name: "Remove the rule for docs.mybank.example" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    expect(await within(dialog).findByText("The rule could not be removed right now.")).toBeInTheDocument();
    expect(within(region("Your rules")).getAllByRole("listitem")).toHaveLength(2);
  });

  it("a 404 when changing a rule re-reads the list and says why", async () => {
    vi.mocked(getSiteRules)
      .mockResolvedValueOnce(view())
      .mockResolvedValueOnce(view({ rules: [DOCS] }));
    vi.mocked(updateSiteRule).mockRejectedValue(new ApiError("No such site rule.", 404));
    render(<SiteRulesTab />);
    await screen.findByRole("region", { name: "Your rules" });

    fireEvent.change(screen.getByLabelText("Rule for example-casino.com and subdomains"), {
      target: { value: "trusted" },
    });

    await waitFor(() =>
      expect(screen.queryByText("example-casino.com and subdomains")).not.toBeInTheDocument(),
    );
    expect(getSiteRules).toHaveBeenCalledTimes(2);
    expect(within(region("Your rules")).getByRole("alert")).toHaveTextContent("No such site rule.");
    expect(within(region("Your rules")).getByText("1 of 500")).toBeInTheDocument();
  });

  it("a 404 when removing closes the dialog and re-reads the list", async () => {
    vi.mocked(getSiteRules)
      .mockResolvedValueOnce(view())
      .mockResolvedValueOnce(view({ rules: [DOCS] }));
    vi.mocked(deleteSiteRule).mockRejectedValue(new ApiError("No such site rule.", 404));
    render(<SiteRulesTab />);
    await screen.findByRole("region", { name: "Your rules" });

    fireEvent.click(screen.getByRole("button", { name: "Remove the rule for example-casino.com and subdomains" }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Remove" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await waitFor(() =>
      expect(screen.queryByText("example-casino.com and subdomains")).not.toBeInTheDocument(),
    );
    expect(getSiteRules).toHaveBeenCalledTimes(2);
  });

  it("changing a category's kind puts it; Reset to Always ask appears only when the category is overridden", async () => {
    vi.mocked(setSiteCategory)
      .mockResolvedValueOnce({ ...CATEGORIES[0], kind: "blocked" })
      .mockResolvedValueOnce({ ...CATEGORIES[1], kind: "always_ask" });
    await renderLoaded();

    const banks = screen.getByLabelText("Rule for Banks and money accounts");
    const brokers = screen.getByLabelText("Rule for Brokers and investing");
    expect(within(banks).getByRole("option", { name: "Always ask (default)" })).toBeInTheDocument();
    expect(within(rowOf(banks)).queryByRole("button", { name: "Reset to Always ask" })).not.toBeInTheDocument();
    expect(within(rowOf(brokers)).getByRole("button", { name: "Reset to Always ask" })).toBeInTheDocument();

    fireEvent.change(banks, { target: { value: "blocked" } });
    expect(await within(rowOf(banks)).findByRole("button", { name: "Reset to Always ask" })).toBeInTheDocument();
    expect(banks).toHaveValue("blocked");

    fireEvent.click(within(rowOf(brokers)).getByRole("button", { name: "Reset to Always ask" }));
    await waitFor(() =>
      expect(within(rowOf(brokers)).queryByRole("button", { name: "Reset to Always ask" })).not.toBeInTheDocument(),
    );
    expect(brokers).toHaveValue("always_ask");
    expect(vi.mocked(setSiteCategory).mock.calls).toEqual([
      ["banks", "blocked"],
      ["brokers", "always_ask"],
    ]);
  });

  it("a failed category change puts the old kind back and shows why", async () => {
    vi.mocked(setSiteCategory).mockRejectedValue(new ApiError("That is not a kind a list can have.", 422));
    await renderLoaded();

    const crypto = screen.getByLabelText("Rule for Crypto exchanges and wallets");
    fireEvent.change(crypto, { target: { value: "trusted" } });

    expect(await within(rowOf(crypto)).findByRole("alert")).toHaveTextContent("That is not a kind a list can have.");
    expect(crypto).toHaveValue("always_ask");
  });

  it("Show sites expands a category's list and its Block / Trust buttons add an owner rule", async () => {
    const chaseRule = rule({ id: "r9", pattern: "*.chase.com", host: "chase.com", overrides_builtin: true });
    vi.mocked(getSiteRules)
      .mockResolvedValueOnce(view())
      .mockResolvedValueOnce(view({ rules: [CASINO, DOCS, chaseRule] }))
      .mockResolvedValue(view({ rules: [CASINO, DOCS, chaseRule] }));
    vi.mocked(createSiteRule).mockResolvedValue(chaseRule);
    render(<SiteRulesTab />);
    await screen.findByRole("region", { name: "Your rules" });

    const show = screen.getByRole("button", { name: "Show sites in Banks and money accounts" });
    expect(show).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("list", { name: "Banks and money accounts sites" })).not.toBeInTheDocument();
    fireEvent.click(show);

    expect(screen.getByRole("button", { name: "Hide sites in Banks and money accounts" })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
    const sites = screen.getByRole("list", { name: "Banks and money accounts sites" });
    expect(within(sites).getAllByRole("listitem").map((row) => row.firstChild?.textContent)).toEqual([
      "chase.com",
      "bankofamerica.com",
    ]);

    fireEvent.click(within(sites).getByRole("button", { name: "Block chase.com" }));
    expect(await screen.findByText("chase.com and subdomains")).toBeInTheDocument();
    expect(screen.getByText("Replaces the built-in sensitive-site list here")).toBeInTheDocument();
    expect(getSiteRules).toHaveBeenCalledTimes(2);

    fireEvent.click(within(sites).getByRole("button", { name: "Trust bankofamerica.com" }));
    await waitFor(() => expect(getSiteRules).toHaveBeenCalledTimes(3));
    expect(vi.mocked(createSiteRule).mock.calls).toEqual([
      [{ site: "chase.com", include_subdomains: true, kind: "blocked" }],
      [{ site: "bankofamerica.com", include_subdomains: true, kind: "trusted" }],
    ]);
  });

  it("a refused quick Block shows the server's reason under that list", async () => {
    const reason = "There is already a rule for chase.com. Change that one instead.";
    vi.mocked(createSiteRule).mockRejectedValue(new ApiError(reason, 409));
    await renderLoaded();

    fireEvent.click(screen.getByRole("button", { name: "Show sites in Banks and money accounts" }));
    const banksRow = rowOf(screen.getByLabelText("Rule for Banks and money accounts"));
    fireEvent.click(within(banksRow).getByRole("button", { name: "Block chase.com" }));

    expect(await within(banksRow).findByRole("alert")).toHaveTextContent(reason);
    expect(getSiteRules).toHaveBeenCalledTimes(1);
  });

  it("Check a site shows the server's explanation; an empty box does not call the API", async () => {
    const explanation =
      "secure.chase.com is on the built-in Banks and money accounts list, so Crawler asks before every action there and notes when it reads there.";
    vi.mocked(checkSite).mockResolvedValue({
      host: "secure.chase.com",
      kind: "always_ask",
      source: "builtin",
      category: "banks",
      rule_id: null,
      pattern: "*.chase.com",
      protected: false,
      enabled: true,
      explanation,
    });
    await renderLoaded();

    const check = region("Check a site");
    fireEvent.click(within(check).getByRole("button", { name: "Check" }));
    expect(await within(check).findByRole("alert")).toHaveTextContent("Type a site, like example.com.");
    expect(checkSite).not.toHaveBeenCalled();

    fireEvent.change(within(check).getByLabelText("Site to check"), { target: { value: " secure.chase.com " } });
    fireEvent.click(within(check).getByRole("button", { name: "Check" }));

    expect(await within(check).findByRole("status")).toHaveTextContent(explanation);
    expect(within(check).queryByRole("alert")).not.toBeInTheDocument();
    expect(vi.mocked(checkSite).mock.calls).toEqual([["secure.chase.com"]]);
  });

  it("a failed check shows the server's reason", async () => {
    vi.mocked(checkSite).mockRejectedValue(
      new ApiError("Only web sites (http or https) can have a rule.", 422),
    );
    await renderLoaded();

    const check = region("Check a site");
    fireEvent.change(within(check).getByLabelText("Site to check"), { target: { value: "ftp://files.example" } });
    fireEvent.click(within(check).getByRole("button", { name: "Check" }));

    expect(await within(check).findByRole("alert")).toHaveTextContent(
      "Only web sites (http or https) can have a rule.",
    );
  });

  it("the Add form is disabled with the limit sentence when the rule limit is reached", async () => {
    await renderLoaded(view({ max_rules: 2 }));

    const add = region("Add a rule");
    expect(within(add).getByText("You have 2 site rules, the most Crawler keeps. Remove some first.")).toBeInTheDocument();
    expect(within(add).getByLabelText("Site")).toBeDisabled();
    expect(within(add).getByRole("button", { name: "Add rule" })).toBeDisabled();

    fireEvent.click(within(add).getByRole("button", { name: "Add rule" }));
    expect(createSiteRule).not.toHaveBeenCalled();
    expect(within(region("Your rules")).getByText("2 of 2")).toBeInTheDocument();
  });

  it("controls of the row being saved are disabled until the server answers", async () => {
    const answer = deferred<SiteRule>();
    vi.mocked(updateSiteRule).mockReturnValue(answer.promise);
    await renderLoaded();

    const casino = screen.getByLabelText("Rule for example-casino.com and subdomains");
    const casinoRemove = screen.getByRole("button", { name: "Remove the rule for example-casino.com and subdomains" });
    fireEvent.change(casino, { target: { value: "always_ask" } });

    expect(casino).toBeDisabled();
    expect(casinoRemove).toBeDisabled();
    expect(casino).toHaveValue("always_ask");
    expect(screen.getByLabelText("Rule for docs.mybank.example")).toBeEnabled();
    expect(screen.getByRole("button", { name: "Remove the rule for docs.mybank.example" })).toBeEnabled();

    answer.resolve({ ...CASINO, kind: "always_ask" });
    await waitFor(() => expect(casino).toBeEnabled());
    expect(casinoRemove).toBeEnabled();
    expect(casino).toHaveValue("always_ask");
  });

  it("the Add form is disabled while its rule is being saved", async () => {
    const answer = deferred<SiteRule>();
    vi.mocked(createSiteRule).mockReturnValue(answer.promise);
    await renderLoaded();

    fireEvent.change(screen.getByLabelText("Site"), { target: { value: "example.net" } });
    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));

    expect(screen.getByRole("button", { name: "Add rule" })).toBeDisabled();
    expect(screen.getByLabelText("Site")).toBeDisabled();
    answer.resolve(rule({ id: "r4", pattern: "*.example.net", host: "example.net" }));
    expect(await screen.findByText("example.net and subdomains")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add rule" })).toBeEnabled();
  });

  it("empty states read \"No rules yet…\" and \"Nothing since Crawler last started.\"", async () => {
    await renderLoaded(view({ rules: [], recent: [] }));

    expect(
      within(region("Your rules")).getByText("No rules yet. The built-in sensitive sites below still apply."),
    ).toBeInTheDocument();
    expect(within(region("Your rules")).getByText("0 of 500")).toBeInTheDocument();
    expect(
      within(region("Recently stopped or flagged")).getByText("Nothing since Crawler last started."),
    ).toBeInTheDocument();
  });
});
