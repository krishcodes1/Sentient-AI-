/**
 * Tests for the approval-card helpers: shownArguments leaves the backend's reserved key out of a
 * desktop.act, browser.act or browser.checkout card and shows every other tool's arguments whole;
 * purchaseCard reads a checkout card's `_checkout` facts; approvalImage accepts only a base64
 * raster data URL.
 *
 * Why it exists: Guards against a reserved key cluttering the card a person approves from, against
 * the rule spreading to tools where a key starting with "_" could be a real argument the person
 * would then approve without seeing, and against anything but an image reaching an <img>.
 */

import { describe, expect, it } from "vitest";
import { approvalImage, purchaseCard, shownArguments } from "@/pages/approvalArguments";
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
