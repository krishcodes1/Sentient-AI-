/**
 * Tests for ToolRulesTab (Security ▸ Tool rules, owner only): they prove the four built-in rules are
 * listed with their switches and the owner's rules with their summaries, that the switch being off
 * and an unreadable rule store are said plainly, that a rule is sent with arrays for list checks and
 * numbers for number checks, that the server's reason for refusing one is shown unchanged, that
 * turning a built-in rule off or removing a rule asks first while turning one on does not, that the
 * debounced preview says which tools a pattern covers (and warns about reads) without ever blocking
 * Save, that a failed load can be retried, and that a rule never gets a sixth condition.
 *
 * Why it exists: tool rules decide which calls wait for the owner's approval. A form that sent the
 * wrong shape, a refusal the owner never saw, a protection switched off without asking, or a preview
 * that kept a valid rule from being saved would each leave Crawler less careful than the owner chose.
 */

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  BuiltinToolRule,
  ToolRule,
  ToolRuleCatalog,
  ToolRuleOperator,
  ToolRulePreview,
  ToolRulesView,
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
    listToolRules: vi.fn(),
    createToolRule: vi.fn(),
    deleteToolRule: vi.fn(),
    setBuiltinToolRule: vi.fn(),
    previewToolRule: vi.fn(),
    getToolRuleCatalog: vi.fn(),
  };
});

import ToolRulesTab from "@/pages/security/ToolRulesTab";
import {
  ApiError,
  createToolRule,
  deleteToolRule,
  getToolRuleCatalog,
  listToolRules,
  previewToolRule,
  setBuiltinToolRule,
} from "@/services/api";

const OPERATORS: ToolRuleOperator[] = [
  { op: "equals", label: "is", value: "text" },
  { op: "not_equals", label: "is not", value: "text" },
  { op: "contains", label: "contains", value: "text" },
  { op: "regex", label: "matches pattern", value: "pattern" },
  { op: "in_list", label: "is one of", value: "list" },
  { op: "domain_in", label: "has an address or link at", value: "list" },
  { op: "domain_not_in", label: "has an address or link outside", value: "list" },
  { op: "number_gt", label: "is more than", value: "number" },
  { op: "number_lt", label: "is less than", value: "number" },
];

const BUILTINS: BuiltinToolRule[] = [
  {
    key: "untrusted_recipient",
    name: "Address seen only in content Crawler read",
    description:
      "Ask before a send, share or invite to an email address that appeared in an email, web page or file " +
      "Crawler read, or in its own earlier replies, but not in your messages.",
    enabled: true,
    changed_at: null,
  },
  {
    key: "many_recipients",
    name: "More than 10 recipients",
    description: "Ask before one action addresses more than 10 people.",
    enabled: true,
    changed_at: null,
  },
  {
    key: "outside_share",
    name: "Sharing outside your organisation",
    description:
      "Ask before forwarding, sharing a file or inviting someone whose address is not at your organisation's domains.",
    enabled: true,
    changed_at: null,
  },
  {
    key: "untrusted_link",
    name: "Link seen only in content Crawler read",
    description:
      "Ask before a change that includes a link to a site that appeared only in content Crawler read, not in your messages.",
    enabled: false,
    changed_at: "2026-10-14T12:05:00+00:00",
  },
];

const STRIPE: ToolRule = {
  id: "r1",
  name: "Large Stripe refunds",
  tool: "mcp.stripe.*",
  conditions: [{ arg: "amount", op: "number_gt", value: 500 }],
  summary: 'Ask before any mcp.stripe.* call when "amount" is more than 500.',
  created_at: "2026-10-14T12:00:00+00:00",
  created_by: "owner@myco.com",
};

const OUTLOOK: ToolRule = {
  id: "r2",
  name: "Outside guests on Outlook events",
  tool: "microsoft.create_event",
  conditions: [{ arg: "attendees", op: "domain_not_in", value: ["myco.com", "myco.org"] }],
  summary: 'Ask before microsoft.create_event when "attendees" has an address or link outside myco.com, myco.org.',
  created_at: "2026-10-14T12:01:00+00:00",
  created_by: "owner@myco.com",
};

function rulesView(overrides: Partial<ToolRulesView> = {}): ToolRulesView {
  return {
    enabled: true,
    store_ok: true,
    builtins: BUILTINS,
    rules: [STRIPE, OUTLOOK],
    org_domains: ["myco.com"],
    operators: OPERATORS,
    limits: {
      max_rules: 50,
      max_conditions: 5,
      max_list_items: 50,
      max_value_chars: 200,
      max_regex_chars: 100,
      regex_text_cap: 4000,
    },
    ...overrides,
  };
}

const CATALOG: ToolRuleCatalog = {
  tools: [
    { tool: "google_workspace.create_draft", category: "write", args: ["to", "subject", "body"] },
    { tool: "google_workspace.search_email", category: "read", args: ["query"] },
    { tool: "google_workspace.send_email", category: "write", args: ["to", "subject", "body"] },
    { tool: "microsoft.create_event", category: "write", args: ["attendees", "subject", "start"] },
  ],
  mcp_hint: "mcp.<server>.<tool>",
};

function preview(overrides: Partial<ToolRulePreview> = {}): ToolRulePreview {
  return {
    valid: true,
    error: null,
    summary: "Ask before every google_workspace.send_email call.",
    matches: [{ tool: "google_workspace.send_email", category: "write" }],
    reads: 0,
    writes: 1,
    mcp: false,
    truncated: false,
    ...overrides,
  };
}

const PATTERN_REASON =
  "A pattern may use at most one open-ended repeat (*, + or {2,}); give the others a limit such as {1,20}.";

/** Render the tab and wait until the rules are on screen. */
async function renderLoaded(view: ToolRulesView = rulesView()) {
  vi.mocked(listToolRules).mockResolvedValue(view);
  render(<ToolRulesTab />);
  await screen.findByRole("heading", { name: "Built-in rules" });
}

/** Move the faked clock and let the answers it releases render. */
async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

function builtinSwitch(name: string) {
  return screen.getByRole("switch", { name });
}

function ownerRuleRows() {
  return within(screen.getByRole("region", { name: /^Your rules/ })).queryAllByRole("listitem");
}

describe("ToolRulesTab", () => {
  beforeEach(() => {
    vi.mocked(listToolRules).mockResolvedValue(rulesView());
    vi.mocked(getToolRuleCatalog).mockResolvedValue(CATALOG);
    vi.mocked(previewToolRule).mockResolvedValue(preview());
  });

  afterEach(() => {
    // Unmount first: the catalog request starts in a passive effect after the
    // load renders, which React may flush only at unmount; resetting the mocks
    // before that hands the effect an undefined answer (seen under load).
    cleanup();
    vi.useRealTimers();
    vi.mocked(listToolRules).mockReset();
    vi.mocked(createToolRule).mockReset();
    vi.mocked(deleteToolRule).mockReset();
    vi.mocked(setBuiltinToolRule).mockReset();
    vi.mocked(previewToolRule).mockReset();
    vi.mocked(getToolRuleCatalog).mockReset();
  });

  it("lists the four built-in rules with their on state and the owner's rules with their summaries", async () => {
    render(<ToolRulesTab />);

    expect(screen.getByRole("region", { name: "Tool rules" })).toBeInTheDocument();
    expect(screen.getByText("Loading tool rules…")).toBeInTheDocument();
    await screen.findByRole("heading", { name: "Built-in rules" });

    const builtins = within(screen.getByRole("region", { name: "Built-in rules" }));
    expect(builtins.getAllByRole("listitem").map((row) => row.querySelector("p")?.textContent)).toEqual([
      "Address seen only in content Crawler read",
      "More than 10 recipients",
      "Sharing outside your organisation",
      "Link seen only in content Crawler read",
    ]);
    expect(screen.getAllByRole("switch")).toHaveLength(4);
    expect(builtinSwitch("Address seen only in content Crawler read")).toHaveAttribute("aria-checked", "true");
    expect(builtinSwitch("More than 10 recipients")).toHaveAttribute("aria-checked", "true");
    expect(builtinSwitch("Sharing outside your organisation")).toHaveAttribute("aria-checked", "true");
    expect(builtinSwitch("Link seen only in content Crawler read")).toHaveAttribute("aria-checked", "false");
    expect(builtins.getByText(/Your organisation: myco\.com$/)).toBeInTheDocument();

    expect(screen.getByRole("heading", { name: "Your rules (2 of 50)" })).toBeInTheDocument();
    expect(ownerRuleRows().map((row) => row.textContent)).toEqual([
      `Large Stripe refunds${STRIPE.summary}Remove`,
      `Outside guests on Outlook events${OUTLOOK.summary}Remove`,
    ]);
    expect(screen.getByText("The switch is on in Settings → Permissions.")).toBeInTheDocument();
    expect(screen.queryByText(/Tool rules are off/)).not.toBeInTheDocument();
    expect(screen.queryByText(/could not be read just now/)).not.toBeInTheDocument();
  });

  it("says plainly when the tool rules switch is off and when the rules could not be read", async () => {
    await renderLoaded(rulesView({ enabled: false, store_ok: false }));

    expect(
      screen.getByText("Tool rules are off in Settings → Permissions, so nothing here is applied."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Your rules could not be read just now. Until they can, Crawler asks before every change."),
    ).toBeInTheDocument();
    expect(screen.queryByText("The switch is on in Settings → Permissions.")).not.toBeInTheDocument();
  });

  it("says when the owner has no rules yet and when no organisation domain is known", async () => {
    await renderLoaded(rulesView({ rules: [], org_domains: [] }));

    expect(screen.getByRole("heading", { name: "Your rules (0 of 50)" })).toBeInTheDocument();
    expect(screen.getByText("No rules of your own yet. Built-in rules still apply.")).toBeInTheDocument();
    expect(screen.getByText(/No organisation domains are known yet, so this rule stays quiet\.$/)).toBeInTheDocument();
    expect(screen.queryByText(/Your organisation:/)).not.toBeInTheDocument();
  });

  it("adds a rule with a list condition and a number condition and shows it in the list", async () => {
    const created: ToolRule = {
      id: "r3",
      name: "Big refunds in odd currencies",
      tool: "mcp.stripe.*",
      conditions: [
        { arg: "amount", op: "number_gt", value: 500 },
        { arg: "currency", op: "in_list", value: ["usd", "eur"] },
      ],
      summary: 'Ask before any mcp.stripe.* call when "amount" is more than 500 and "currency" is one of usd, eur.',
      created_at: "2026-10-14T12:10:00+00:00",
      created_by: "owner@myco.com",
    };
    vi.mocked(createToolRule).mockResolvedValue(created);
    await renderLoaded(rulesView({ rules: [] }));

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: " Big refunds in odd currencies " } });
    fireEvent.change(screen.getByLabelText("Tool"), { target: { value: " mcp.stripe.* " } });
    fireEvent.click(screen.getByRole("button", { name: "Add a condition" }));
    fireEvent.click(screen.getByRole("button", { name: "Add a condition" }));
    fireEvent.change(screen.getByLabelText("Condition 1: argument"), { target: { value: " amount " } });
    fireEvent.change(screen.getByLabelText("Condition 1: check"), { target: { value: "number_gt" } });
    expect(screen.getByLabelText("Condition 1: value")).toHaveAttribute("type", "number");
    fireEvent.change(screen.getByLabelText("Condition 1: value"), { target: { value: "500" } });
    fireEvent.change(screen.getByLabelText("Condition 2: argument"), { target: { value: "currency" } });
    fireEvent.change(screen.getByLabelText("Condition 2: check"), { target: { value: "in_list" } });
    expect(screen.getByLabelText("Condition 2: value")).toHaveAttribute("type", "text");
    fireEvent.change(screen.getByLabelText("Condition 2: value"), { target: { value: " usd, , eur " } });
    fireEvent.click(screen.getByRole("button", { name: "Save rule" }));

    expect(await screen.findByText(created.summary)).toBeInTheDocument();
    expect(vi.mocked(createToolRule).mock.calls).toEqual([
      [
        {
          name: "Big refunds in odd currencies",
          tool: "mcp.stripe.*",
          conditions: [
            { arg: "amount", op: "number_gt", value: 500 },
            { arg: "currency", op: "in_list", value: ["usd", "eur"] },
          ],
        },
      ],
    ]);
    expect(screen.getByRole("heading", { name: "Your rules (1 of 50)" })).toBeInTheDocument();
    expect(ownerRuleRows()).toHaveLength(1);
    expect(screen.getByLabelText("Name")).toHaveValue("");
    expect(screen.getByLabelText("Tool")).toHaveValue("");
    expect(screen.queryByLabelText("Condition 1: argument")).not.toBeInTheDocument();
  });

  it("shows the server's reason for refusing a rule beside the form unchanged", async () => {
    vi.mocked(createToolRule).mockRejectedValue(new ApiError(PATTERN_REASON, 422));
    await renderLoaded();

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Odd subjects" } });
    fireEvent.change(screen.getByLabelText("Tool"), { target: { value: "google_workspace.send_email" } });
    fireEvent.click(screen.getByRole("button", { name: "Add a condition" }));
    fireEvent.change(screen.getByLabelText("Condition 1: argument"), { target: { value: "subject" } });
    fireEvent.change(screen.getByLabelText("Condition 1: check"), { target: { value: "regex" } });
    fireEvent.change(screen.getByLabelText("Condition 1: value"), { target: { value: "a*b*" } });
    fireEvent.click(screen.getByRole("button", { name: "Save rule" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe(PATTERN_REASON);
    expect(vi.mocked(createToolRule).mock.calls).toEqual([
      [
        {
          name: "Odd subjects",
          tool: "google_workspace.send_email",
          conditions: [{ arg: "subject", op: "regex", value: "a*b*" }],
        },
      ],
    ]);
    expect(screen.getByLabelText("Name")).toHaveValue("Odd subjects");
    expect(screen.getByLabelText("Condition 1: value")).toHaveValue("a*b*");
    expect(ownerRuleRows()).toHaveLength(2);
  });

  it("turning a built-in rule off asks first and cancel leaves it on without calling the server", async () => {
    await renderLoaded();

    fireEvent.click(builtinSwitch("More than 10 recipients"));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("heading", { name: "Turn off 'More than 10 recipients'?" })).toBeInTheDocument();
    expect(dialog).toHaveTextContent(
      "Crawler will no longer ask before one action addresses more than 10 people. This makes Crawler less careful.",
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(builtinSwitch("More than 10 recipients")).toHaveAttribute("aria-checked", "true");
    expect(setBuiltinToolRule).not.toHaveBeenCalled();
  });

  it("turning a built-in rule off after confirming saves it off, and turning it on does not ask", async () => {
    vi.mocked(setBuiltinToolRule).mockImplementation(async (key: string, enabled: boolean) => ({
      ...BUILTINS.find((rule) => rule.key === key)!,
      enabled,
      changed_at: "2026-10-14T12:20:00+00:00",
    }));
    await renderLoaded();

    fireEvent.click(builtinSwitch("More than 10 recipients"));
    const dialog = await screen.findByRole("dialog");
    expect(setBuiltinToolRule).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Turn off" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(builtinSwitch("More than 10 recipients")).toHaveAttribute("aria-checked", "false");

    fireEvent.click(builtinSwitch("Link seen only in content Crawler read"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await waitFor(() =>
      expect(builtinSwitch("Link seen only in content Crawler read")).toHaveAttribute("aria-checked", "true"),
    );
    expect(vi.mocked(setBuiltinToolRule).mock.calls).toEqual([
      ["many_recipients", false],
      ["untrusted_link", true],
    ]);
    expect(builtinSwitch("Address seen only in content Crawler read")).toHaveAttribute("aria-checked", "true");
  });

  it("keeps a built-in rule on when turning it off fails, with the reason in the dialog", async () => {
    vi.mocked(setBuiltinToolRule).mockRejectedValue(new ApiError("No such built-in rule.", 404));
    await renderLoaded();

    fireEvent.click(builtinSwitch("More than 10 recipients"));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Turn off" }));

    expect(await within(dialog).findByText("No such built-in rule.")).toBeInTheDocument();
    expect(builtinSwitch("More than 10 recipients")).toHaveAttribute("aria-checked", "true");
  });

  it("a built-in rule the server refuses to turn on stays off with the reason on its own row", async () => {
    vi.mocked(setBuiltinToolRule).mockRejectedValue(
      new ApiError("Only the owner of this install can change this.", 403),
    );
    await renderLoaded();

    fireEvent.click(builtinSwitch("Link seen only in content Crawler read"));

    const row = builtinSwitch("Link seen only in content Crawler read").closest("li") as HTMLElement;
    expect(await within(row).findByRole("alert")).toHaveTextContent("Only the owner of this install can change this.");
    expect(builtinSwitch("Link seen only in content Crawler read")).toHaveAttribute("aria-checked", "false");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getAllByRole("alert")).toHaveLength(1);
  });

  it("remove asks first and removes only its own row", async () => {
    vi.mocked(deleteToolRule).mockResolvedValue(undefined);
    await renderLoaded();

    fireEvent.click(screen.getByRole("button", { name: "Remove the rule Large Stripe refunds" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("heading", { name: "Remove the rule 'Large Stripe refunds'?" })).toBeInTheDocument();
    expect(dialog).toHaveTextContent("Crawler will stop asking before the calls it matched.");
    expect(deleteToolRule).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(vi.mocked(deleteToolRule).mock.calls).toEqual([["r1"]]);
    expect(ownerRuleRows().map((row) => row.querySelector("p")?.textContent)).toEqual([
      "Outside guests on Outlook events",
    ]);
    expect(screen.getByRole("heading", { name: "Your rules (1 of 50)" })).toBeInTheDocument();
  });

  it("keeps the rule when removing it fails, with the server's reason in the dialog", async () => {
    vi.mocked(deleteToolRule).mockRejectedValue(new ApiError("No such tool rule.", 404));
    await renderLoaded();

    fireEvent.click(screen.getByRole("button", { name: "Remove the rule Large Stripe refunds" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove" }));

    expect(await within(dialog).findByText("No such tool rule.")).toBeInTheDocument();
    expect(ownerRuleRows()).toHaveLength(2);
  });

  it("shows which tools a pattern matches and warns when reads are among them", async () => {
    const names = Array.from({ length: 14 }, (_, i) => `google_workspace.tool_${String(i + 1).padStart(2, "0")}`);
    vi.mocked(previewToolRule).mockResolvedValue(
      preview({
        summary: "Ask before any google_workspace.* call.",
        matches: names.map((tool, i) => ({ tool, category: i < 3 ? "read" : "write" })),
        reads: 3,
        writes: 11,
      }),
    );
    await renderLoaded();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

    fireEvent.change(screen.getByLabelText("Tool"), { target: { value: "google_workspace.s" } });
    await advance(200);
    fireEvent.change(screen.getByLabelText("Tool"), { target: { value: "google_workspace.*" } });
    await advance(399);
    expect(previewToolRule).not.toHaveBeenCalled();
    await advance(1);

    expect(vi.mocked(previewToolRule).mock.calls).toEqual([[{ tool: "google_workspace.*", conditions: [] }]]);
    expect(screen.getByText("Ask before any google_workspace.* call.")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Matches 14 tools: google_workspace.tool_01, google_workspace.tool_02, google_workspace.tool_03, " +
          "google_workspace.tool_04, google_workspace.tool_05…",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("3 of them are reads: Crawler will stop and ask in chat before those reads."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/MCP servers/)).not.toBeInTheDocument();
  });

  it("previews the conditions too, says when a pattern also covers MCP servers, and drops a stale answer", async () => {
    let answerFirst: (value: ToolRulePreview) => void = () => undefined;
    vi.mocked(previewToolRule)
      .mockImplementationOnce(() => new Promise<ToolRulePreview>((resolve) => (answerFirst = resolve)))
      .mockResolvedValueOnce(
        preview({ summary: 'Ask before any mcp.stripe.* call when "amount" is more than 500.', matches: [], writes: 0, mcp: true }),
      );
    await renderLoaded();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

    fireEvent.change(screen.getByLabelText("Tool"), { target: { value: "mcp.stripe.*" } });
    await advance(400);
    expect(screen.getByText("Checking which tools this covers…")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add a condition" }));
    fireEvent.change(screen.getByLabelText("Condition 1: argument"), { target: { value: "amount" } });
    fireEvent.change(screen.getByLabelText("Condition 1: check"), { target: { value: "number_gt" } });
    fireEvent.change(screen.getByLabelText("Condition 1: value"), { target: { value: "500" } });
    await advance(400);
    await act(async () => answerFirst(preview({ summary: "The first, older answer." })));

    expect(vi.mocked(previewToolRule).mock.calls).toEqual([
      [{ tool: "mcp.stripe.*", conditions: [] }],
      [{ tool: "mcp.stripe.*", conditions: [{ arg: "amount", op: "number_gt", value: 500 }] }],
    ]);
    const form = within(screen.getByRole("form", { name: "Add a tool rule" }));
    expect(form.getByText('Ask before any mcp.stripe.* call when "amount" is more than 500.')).toBeInTheDocument();
    expect(screen.getByText("Matches no tools in the catalog.")).toBeInTheDocument();
    expect(screen.getByText("Also matches tools from MCP servers with that name.")).toBeInTheDocument();
    expect(screen.queryByText("The first, older answer.")).not.toBeInTheDocument();
    expect(screen.queryByText(/of them (is a read|are reads)/)).not.toBeInTheDocument();
  });

  it("shows the preview's reason for an invalid draft but still lets the owner save", async () => {
    vi.mocked(previewToolRule).mockResolvedValue(
      preview({ valid: false, error: PATTERN_REASON, summary: "", matches: [], writes: 0 }),
    );
    vi.mocked(createToolRule).mockResolvedValue({
      ...STRIPE,
      id: "r4",
      name: "Odd subjects",
      tool: "google_workspace.send_email",
      conditions: [{ arg: "subject", op: "regex", value: "a*b*" }],
      summary: 'Ask before google_workspace.send_email when "subject" matches the pattern a*b*.',
    });
    await renderLoaded();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Odd subjects" } });
    fireEvent.change(screen.getByLabelText("Tool"), { target: { value: "google_workspace.send_email" } });
    fireEvent.click(screen.getByRole("button", { name: "Add a condition" }));
    fireEvent.change(screen.getByLabelText("Condition 1: argument"), { target: { value: "subject" } });
    fireEvent.change(screen.getByLabelText("Condition 1: check"), { target: { value: "regex" } });
    fireEvent.change(screen.getByLabelText("Condition 1: value"), { target: { value: "a*b*" } });
    await advance(400);

    expect(screen.getByText(PATTERN_REASON)).toBeInTheDocument();
    expect(screen.queryByText(/^Matches /)).not.toBeInTheDocument();
    const save = screen.getByRole("button", { name: "Save rule" });
    expect(save).toBeEnabled();
    fireEvent.click(save);
    await advance(0);

    expect(vi.mocked(createToolRule).mock.calls).toEqual([
      [
        {
          name: "Odd subjects",
          tool: "google_workspace.send_email",
          conditions: [{ arg: "subject", op: "regex", value: "a*b*" }],
        },
      ],
    ]);
    expect(ownerRuleRows()).toHaveLength(3);
  });

  it("suggests the catalog's tools and the arguments of the tools the pattern covers", async () => {
    await renderLoaded();
    const tool = screen.getByLabelText("Tool");
    const tools = () =>
      Array.from(document.getElementById(tool.getAttribute("list")!)!.querySelectorAll("option")).map((o) => o.value);
    await waitFor(() => expect(tools()).toHaveLength(4));
    expect(tools()).toEqual(CATALOG.tools.map((entry) => entry.tool));
    expect(screen.getByText(/MCP tools are named mcp\.<server>\.<tool>\./)).toBeInTheDocument();

    fireEvent.change(tool, { target: { value: "google_workspace.*" } });
    fireEvent.click(screen.getByRole("button", { name: "Add a condition" }));
    const arg = screen.getByLabelText("Condition 1: argument");
    const args = Array.from(document.getElementById(arg.getAttribute("list")!)!.querySelectorAll("option")).map(
      (o) => o.value,
    );
    expect(args).toEqual(["body", "query", "subject", "to", "*"]);
  });

  it("a load failure offers try again and a retry loads the rules", async () => {
    vi.mocked(listToolRules)
      .mockRejectedValueOnce(new ApiError("Request failed: Service Unavailable", 503))
      .mockResolvedValueOnce(rulesView());
    render(<ToolRulesTab />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The tool rules could not be loaded.");
    expect(screen.queryByRole("switch")).not.toBeInTheDocument();
    fireEvent.click(within(alert).getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("heading", { name: "Your rules (2 of 50)" })).toBeInTheDocument();
    expect(listToolRules).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("a member the server refuses sees only that the tab is the owner's, with no controls", async () => {
    vi.mocked(listToolRules).mockRejectedValue(new ApiError("Only the owner of this install can change this.", 403));
    render(<ToolRulesTab />);

    expect(await screen.findByText("Only the owner can see tool rules.")).toBeInTheDocument();
    expect(screen.queryByRole("switch")).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Add a tool rule" })).not.toBeInTheDocument();
    expect(getToolRuleCatalog).not.toHaveBeenCalled();
  });

  it("never offers more than five conditions or a sixth add button", async () => {
    await renderLoaded();

    for (let i = 0; i < 5; i += 1) {
      fireEvent.click(screen.getByRole("button", { name: "Add a condition" }));
    }
    expect(screen.getAllByLabelText(/^Condition \d: argument$/)).toHaveLength(5);
    expect(screen.queryByRole("button", { name: "Add a condition" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Remove condition 5" }));
    expect(screen.getAllByLabelText(/^Condition \d: argument$/)).toHaveLength(4);
    expect(screen.getByRole("button", { name: "Add a condition" })).toBeInTheDocument();
  });
});
