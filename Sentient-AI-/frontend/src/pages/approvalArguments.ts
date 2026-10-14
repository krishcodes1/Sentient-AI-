/**
 * What an approval card shows of the request it was made for: shownArguments (the arguments
 * without the keys the backend reserves for itself), approvalDetails (every value as an everyday
 * label and its plain value, from the server's `details` or labelled here for an older server),
 * isDetailsCard (whether the card lists those values), purchaseCard (the `_checkout` facts of a
 * browser.checkout card), approvalImage (a checkout's or a browser.act's screenshot, only as a
 * raster data URL) and stepLabel (the plain label of a finished step, "Used Gmail").
 *
 * Why it exists: A desktop.act approval also stores the screen it was made from under "_screen",
 * a browser.act one the page under "_page" and a browser.checkout one the page facts under
 * "_checkout" (all set by the backend, never by the model). Chat's approval cards and Dashboard's
 * approval rows both show the request, so they share these rules. The person approving is not a
 * developer (docs/bot-message-style.md): a card lists "To: priya@acme.com", never a tool id or a
 * JSON dump, and still shows every value whole (spec F3).
 */

import type { ApprovalDetail, PendingApproval, PurchaseCard } from "@/types";

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

/** Whether the card lists its values as labelled details: every card but a purchase (its page's
 *  facts, PurchaseApproval) and a browser.act step (its sentence and picture). */
export function isDetailsCard(approval: PendingApproval): boolean {
  return approval.tool_name !== PURCHASE_TOOL && !isSentenceCard(approval);
}

// ── plain words for a card's values ──────────────────────────────────────
// The server sends each card's values already labelled (`details`, from
// services/notifications/cards.detail_pairs, the same words the Telegram and
// Slack cards use). These label the arguments in the same spirit when an
// older server sent none: "message_id" reads "Message ID", true reads "Yes",
// a list one item per line, nested values as indented "Label: value" lines.
// Nothing is dropped or cut.

// Words kept in capitals when a key is turned into a label.
const ACRONYMS: Record<string, string> = {
  id: "ID",
  ids: "IDs",
  url: "URL",
  urls: "URLs",
  api: "API",
  html: "HTML",
  pdf: "PDF",
  cc: "CC",
  bcc: "BCC",
  csv: "CSV",
  sms: "SMS",
  ai: "AI",
  utc: "UTC",
};
// How deep nested values are followed before the rest is shown as one line.
const MAX_DEPTH = 12;
// Indent of a value's lines under its label, as the chat cards indent them.
const INDENT = "   ";

/** "message_id" -> "Message ID", "sendAt" -> "Send at"; "Details" when there are no words. */
export function humanizeKey(key: string): string {
  const words = String(key)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[\s_\-.]+/)
    .filter(Boolean)
    .map((word) => word.toLowerCase());
  if (words.length === 0) return "Details";
  return words
    .map((word, i) => {
      if (Object.prototype.hasOwnProperty.call(ACRONYMS, word)) return ACRONYMS[word];
      return i === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word;
    })
    .join(" ");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function scalarText(value: unknown): string {
  if (value === null || value === undefined) return "(none)";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "string") return value === "" ? "(empty)" : value;
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  try {
    return String(value);
  } catch {
    return "(a value that can't be shown)";
  }
}

/** The lines one value shows as, and whether they go under its label (nested details, a numbered
 *  list and anything on more than one line do), as services/notifications/cards.py lays them out:
 *  a list one item per line (numbered when it holds nested values), a nested value as its own
 *  "Label: value" lines, anything else as its text split at line breaks. */
function valueLines(value: unknown, depth: number): { lines: string[]; under: boolean } {
  if (Array.isArray(value) && depth < MAX_DEPTH) {
    if (value.length === 0) return { lines: ["(none)"], under: false };
    const numbered = value.some((item) => typeof item === "object" && item !== null);
    const lines: string[] = [];
    value.forEach((item, i) => {
      const itemLines = valueLines(item, depth + 1).lines;
      const prefix = numbered ? `${i + 1}. ` : "";
      const pad = numbered ? " ".repeat(prefix.length) : INDENT;
      lines.push(prefix + itemLines[0]);
      for (const line of itemLines.slice(1)) lines.push(line ? pad + line : "");
    });
    return { lines, under: numbered || lines.length > 1 };
  }
  if (isPlainObject(value) && depth < MAX_DEPTH) {
    const entries = Object.entries(value);
    if (entries.length === 0) return { lines: ["(none)"], under: false };
    const lines = entries.flatMap(([key, item]) => labelled(humanizeKey(key), valueLines(item, depth + 1)));
    return { lines, under: true };
  }
  // Past the depth limit (a value nested a dozen levels deep), the rest is shown as one line of
  // text rather than not at all.
  let text: string;
  if (typeof value === "object" && value !== null) {
    try {
      text = JSON.stringify(value) ?? scalarText(value);
    } catch {
      text = scalarText(value);
    }
  } else {
    text = scalarText(value);
  }
  const lines = text.split(/\r\n|[\n\r\u2028\u2029]/);
  return { lines, under: lines.length > 1 };
}

/** "Label: value" for a value that reads well on one line, else "Label:" with every line of the
 *  value indented under it, so text inside a value can never pass for another labelled line. */
function labelled(label: string, { lines, under }: { lines: string[]; under: boolean }): string[] {
  if (!under) return [`${label}: ${lines[0]}`];
  return [`${label}:`, ...lines.map((line) => (line ? INDENT + line : ""))];
}

/** Arguments as labelled details, in their own order, nothing dropped or cut. */
export function labelArguments(args: Record<string, unknown>): ApprovalDetail[] {
  try {
    return Object.entries(args ?? {}).map(([key, value]) => ({
      label: humanizeKey(key),
      value: valueLines(value, 0).lines.join("\n"),
    }));
  } catch {
    return [{ label: "Details", value: scalarText(args) }];
  }
}

function isDetail(value: unknown): value is ApprovalDetail {
  return isPlainObject(value) && typeof value.label === "string" && typeof value.value === "string";
}

/** The labelled values a card lists: the server's `details` when it sent them, else the shown
 *  arguments labelled here (an older server, or one that could not work them out). */
export function approvalDetails(approval: PendingApproval): ApprovalDetail[] {
  const sent = approval.details;
  if (Array.isArray(sent) && sent.length > 0 && sent.every(isDetail)) return sent;
  return labelArguments(shownArguments(approval));
}

// Each tool family's everyday name, as services/action_text.py's _FAMILY_APPS
// names it ("canvas__1f2e3d4c" is a second Canvas connector).
const FAMILY_NAMES: Record<string, string> = {
  system: "your computer",
  desktop: "your computer",
  browser: "the web browser",
  web: "the web",
  memory: "your saved memories",
  watch: "your page watches",
  files: "your uploaded files",
  schedule: "your scheduled tasks",
  knowledge: "your saved documents",
  study: "your flashcards",
  triggers: "your triggers",
  reminders: "your reminders",
  tutor: "tutor mode",
  video: "video transcripts",
  canvas: "Canvas",
  google_workspace: "your Google account",
  microsoft: "your Microsoft account",
  github: "GitHub",
  notion: "Notion",
  slack: "Slack",
  robinhood: "Robinhood",
  mcp: "a connected app",
};

/** The plain label of a step that ran ("Used the web", "Used your Google account"), never its
 *  tool id. */
export function stepLabel(toolName: string): string {
  const family = String(toolName ?? "").split(".")[0].split("__")[0].toLowerCase();
  // tools.find looks up which of Crawler's skills to load: no app was used.
  if (family === "tools") return "Looked up what Crawler can do";
  if (Object.prototype.hasOwnProperty.call(FAMILY_NAMES, family)) return `Used ${FAMILY_NAMES[family]}`;
  const words = family.split(/[_\-\s]+/).filter(Boolean).join(" ");
  return words ? `Used ${words.charAt(0).toUpperCase()}${words.slice(1)}` : "Finished a step";
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
