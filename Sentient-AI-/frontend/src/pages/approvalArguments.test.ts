/**
 * Tests for the approval-card helpers: shownArguments leaves the backend's reserved key out of a
 * desktop.act, browser.act, browser.checkout or VirusTotal upload card and shows every other
 * tool's arguments whole;
 * purchaseCard reads a checkout card's `_checkout` facts; approvalImage accepts only a base64
 * raster data URL; approvalDetails lists every value in everyday words (the server's `details`, or
 * the arguments labelled here for an older server) and stepLabel names a finished step plainly.
 *
 * Why it exists: Guards against a reserved key cluttering the card a person approves from, against
 * the rule spreading to tools where a key starting with "_" could be a real argument the person
 * would then approve without seeing, and against anything but an image reaching an <img>. The
 * person approving is not a developer (docs/bot-message-style.md), so the card must never fall
 * back to JSON or a tool id, and must still show every value whole (spec F3).
 */

import { describe, expect, it } from "vitest";
import {
  approvalDetails,
  approvalImage,
  humanizeKey,
  isDetailsCard,
  labelArguments,
  purchaseCard,
  shownArguments,
  stepLabel,
} from "@/pages/approvalArguments";
import type { PendingApproval } from "@/types";

function approval(tool_name: string, args: Record<string, unknown>): PendingApproval {
  return { action_id: "a1", tool_name, arguments: args, reason: "r" };
}

const CHECKOUT = {
  checkout_id: "ck1",
  origin: "https://shop.example.com",
  host: "shop.example.com",
  amount_usd: "23.40",
  currency: "USD",
  items: ["Concert ticket — $19.00", "Service fee — $4.40"],
  card_label: "Visa ····4242",
  outline: "9f2c1a",
  notice: "Crawler can make mistakes. Check the amount and the site before you approve.",
};

describe("shownArguments", () => {
  it("leaves the stored screen out of a desktop.act card", () => {
    const shown = shownArguments(
      approval("desktop.act", {
        action: "click",
        ref: "d3",
        _screen: { app: "Mail", outline: "9f2c1a" },
      }),
    );
    expect(shown).toEqual({ action: "click", ref: "d3" });
  });

  it("leaves the stored page out of a browser.act card", () => {
    const shown = shownArguments(
      approval("browser.act", {
        action: "fill",
        ref: "e3",
        text: "ada@example.com",
        _page: { origin: "https://shop.example.com", outline: "9f2c1a", scheme: "https" },
      }),
    );
    expect(shown).toEqual({ action: "fill", ref: "e3", text: "ada@example.com" });
  });

  it("leaves the stored checkout facts out of a browser.checkout card", () => {
    const shown = shownArguments(
      approval("browser.checkout", { merchant: "shop.example.com", amount: 23.4, _checkout: CHECKOUT }),
    );
    expect(shown).toEqual({ merchant: "shop.example.com", amount: 23.4 });
  });

  it("hides the reserved _upload key of a VirusTotal upload card", () => {
    const shown = shownArguments(
      approval("security.upload_to_virustotal", {
        sha256: "ab".repeat(32),
        file_name: "invoice.pdf",
        _upload: { holder: "h-1", size: 1234 },
      }),
    );
    expect(shown).toEqual({ sha256: "ab".repeat(32), file_name: "invoice.pdf" });
  });

  it("shows every argument of any other tool", () => {
    const args = { query: "x", _private_flag: true };
    expect(shownArguments(approval("mcp.github.search", args))).toEqual(args);
  });

  it("copes with a card that has no arguments", () => {
    const bare = { action_id: "a2", tool_name: "desktop.act", reason: "r" } as PendingApproval;
    expect(shownArguments(bare)).toEqual({});
  });
});

describe("purchaseCard", () => {
  it("reads the _checkout block of a browser.checkout card", () => {
    const card = purchaseCard(approval("browser.checkout", { merchant: "shop.example.com", _checkout: CHECKOUT }));
    expect(card).toEqual({
      checkout_id: "ck1",
      origin: "https://shop.example.com",
      host: "shop.example.com",
      amount_usd: "23.40",
      currency: "USD",
      items: CHECKOUT.items,
      card_label: "Visa ····4242",
      notice: CHECKOUT.notice,
    });
  });

  it("is null for another tool, a missing block, or one without a host and amount", () => {
    expect(purchaseCard(approval("browser.act", { _checkout: CHECKOUT }))).toBeNull();
    expect(purchaseCard(approval("browser.checkout", { merchant: "shop.example.com" }))).toBeNull();
    expect(purchaseCard(approval("browser.checkout", { _checkout: "not an object" }))).toBeNull();
    expect(
      purchaseCard(approval("browser.checkout", { _checkout: { ...CHECKOUT, amount_usd: 23.4 } })),
    ).toBeNull();
  });

  it("fills in what a malformed block leaves out rather than rendering it", () => {
    const card = purchaseCard(
      approval("browser.checkout", {
        _checkout: { host: "shop.example.com", amount_usd: "5.00", items: ["ok", 7], card_label: null },
      }),
    );
    expect(card).toEqual({
      checkout_id: "",
      origin: "",
      host: "shop.example.com",
      amount_usd: "5.00",
      currency: "USD",
      items: [],
      card_label: "",
      notice: "",
    });
  });
});

describe("approvalImage", () => {
  it.each([
    "data:image/jpeg;base64,/9j/4AAQSkZJRg==",
    "data:image/png;base64,iVBORw0KGgo=",
    "data:image/webp;base64,UklGRg==",
  ])("accepts the raster data URL %s", (image) => {
    expect(approvalImage({ ...approval("browser.checkout", {}), image })).toBe(image);
  });

  it.each([
    "https://shop.example.com/receipt.png",
    "data:image/svg+xml;base64,PHN2Zz4=",
    "data:text/html;base64,PGh0bWw+",
    "data:image/png;base64,not base64!",
    "javascript:alert(1)",
    "",
    null,
    undefined,
  ])("rejects %s", (image) => {
    expect(approvalImage({ ...approval("browser.checkout", {}), image })).toBeNull();
  });
});

describe("humanizeKey", () => {
  it("turns a key into a sentence-case label", () => {
    expect(humanizeKey("subject")).toBe("Subject");
    expect(humanizeKey("message_id")).toBe("Message ID");
    expect(humanizeKey("sendAt")).toBe("Send at");
    expect(humanizeKey("page_url")).toBe("Page URL");
    expect(humanizeKey("__")).toBe("Details");
  });
});

describe("labelArguments", () => {
  it("labels every value in order, keeping every line and adding no JSON", () => {
    const details = labelArguments({
      to: "priya@acme.com",
      body: "Hi Priya,\nare we still on for noon?",
      urgent: false,
      cc: ["a@acme.com", "b@acme.com"],
      event: { start: "2026-10-15T12:00", attendees: [{ email: "a@acme.com" }] },
      note: "",
      later: null,
    });
    expect(details).toEqual([
      { label: "To", value: "priya@acme.com" },
      { label: "Body", value: "Hi Priya,\nare we still on for noon?" },
      { label: "Urgent", value: "No" },
      { label: "CC", value: "a@acme.com\nb@acme.com" },
      {
        label: "Event",
        value: "Start: 2026-10-15T12:00\nAttendees:\n   1. Email: a@acme.com",
      },
      { label: "Note", value: "(empty)" },
      { label: "Later", value: "(none)" },
    ]);
    const text = details.map((d) => `${d.label} ${d.value}`).join(" ");
    expect(text).not.toMatch(/[{}"]/);
  });

  it("keeps a long value whole", () => {
    const long = "word ".repeat(2000).trim();
    expect(labelArguments({ body: long })[0].value).toBe(long);
  });
});

describe("approvalDetails", () => {
  it("uses the server's labelled details when it sent them", () => {
    const sent = [{ label: "Email ID", value: "m-1" }];
    expect(approvalDetails({ ...approval("google_workspace.trash_email", { message_id: "m-1" }), details: sent })).toBe(
      sent,
    );
  });

  it("labels the arguments itself for an older server, leaving reserved keys out", () => {
    const old = approval("desktop.act", { action: "type", text: "hello", _screen: { app: "Notepad" } });
    expect(approvalDetails(old)).toEqual([
      { label: "Action", value: "type" },
      { label: "Text", value: "hello" },
    ]);
    expect(approvalDetails({ ...old, details: [] })).toHaveLength(2);
    expect(approvalDetails({ ...old, details: [{ label: 1 }] as never })).toHaveLength(2);
  });
});

describe("isDetailsCard", () => {
  it("lists values on every card but a purchase and a browser.act step", () => {
    expect(isDetailsCard(approval("google_workspace.send_email", {}))).toBe(true);
    expect(isDetailsCard(approval("desktop.act", {}))).toBe(true);
    expect(isDetailsCard(approval("browser.checkout", {}))).toBe(false);
    expect(isDetailsCard(approval("browser.act", {}))).toBe(false);
  });
});

describe("stepLabel", () => {
  it("names a finished step by the app it used, never its tool id", () => {
    expect(stepLabel("web.search")).toBe("Used the web");
    expect(stepLabel("google_workspace.send_email")).toBe("Used your Google account");
    expect(stepLabel("canvas__1f2e3d4c.get_courses")).toBe("Used Canvas");
    expect(stepLabel("tools.find")).toBe("Looked up what Crawler can do");
    expect(stepLabel("spotify_player.play")).toBe("Used Spotify player");
    expect(stepLabel("")).toBe("Finished a step");
  });
});
