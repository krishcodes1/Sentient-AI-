/**
 * What an approval card shows of the request it was made for: shownArguments (the arguments
 * without the keys the backend reserves for itself), purchaseCard (the `_checkout` facts of a
 * browser.checkout card) and approvalImage (a checkout's or a browser.act's screenshot, only as a
 * raster data URL).
 *
 * Why it exists: A desktop.act approval also stores the screen it was made from under "_screen",
 * a browser.act one the page under "_page" and a browser.checkout one the page facts under
 * "_checkout" (all set by the backend, never by the model). Chat's approval cards and Dashboard's
 * approval rows both show arguments, so they share these rules.
 */

import type { PendingApproval, PurchaseCard } from "@/types";

/** The tool whose card is a purchase: rendered as PurchaseApproval, not as a JSON dump. */
export const PURCHASE_TOOL = "browser.checkout";
/** The tool whose card is its one sentence (`Click "Add to cart" on shop.example.com`), built by
 *  the backend from facts: a browser.act's arguments are refs and typed text, which a JSON dump
 *  would only obscure, and the typed text is never shown on the card. */
export const ACT_TOOL = "browser.act";

// Only these tools have reserved keys: each toolkit refuses any argument no action takes, so a
// key starting with "_" there was added by the backend. Every other tool's arguments are shown
// whole, so nothing that will run is hidden from the person approving it.
const RESERVED_KEY_TOOLS = new Set(["desktop.act", "browser.act", PURCHASE_TOOL]);

export function shownArguments(approval: PendingApproval): Record<string, unknown> {
  const args = approval.arguments ?? {};
  if (!RESERVED_KEY_TOOLS.has(approval.tool_name)) return args;
  return Object.fromEntries(Object.entries(args).filter(([key]) => !key.startsWith("_")));
}

/** The alt text of a browser.act card's picture (the page, with the step's target outlined). */
export const ACT_PICTURE_ALT = "The page this step will run on, with its target outlined in red";

/** Whether the card is its reason sentence alone: no tool line, no JSON of the arguments. */
export function isSentenceCard(approval: PendingApproval): boolean {
  return approval.tool_name === ACT_TOOL;
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

/**
 * The purchase facts stored with a browser.checkout card, or null when the card is not a
 * purchase or the block is missing or malformed (the page then falls back to the plain card
 * rather than rendering "undefined" as an amount).
 */
export function purchaseCard(approval: PendingApproval): PurchaseCard | null {
  if (approval.tool_name !== PURCHASE_TOOL) return null;
  const raw = approval.arguments?._checkout;
  if (!raw || typeof raw !== "object") return null;
  const c = raw as Record<string, unknown>;
  if (typeof c.host !== "string" || typeof c.amount_usd !== "string") return null;
  return {
    checkout_id: typeof c.checkout_id === "string" ? c.checkout_id : "",
    origin: typeof c.origin === "string" ? c.origin : "",
    host: c.host,
    amount_usd: c.amount_usd,
    currency: typeof c.currency === "string" ? c.currency : "USD",
    items: isStringList(c.items) ? c.items : [],
    card_label: typeof c.card_label === "string" ? c.card_label : "",
    notice: typeof c.notice === "string" ? c.notice : "",
  };
}

// Only a base64 raster image may reach an <img>: anything else (a URL, an SVG, a script) is
// dropped rather than rendered, the same rule the backend applies to chat images.
const IMAGE_DATA_URL = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+=*$/;

/** The card's screenshot when it is a data URL the page may render, else null. */
export function approvalImage(approval: PendingApproval): string | null {
  const image = approval.image;
  return typeof image === "string" && IMAGE_DATA_URL.test(image) ? image : null;
}
