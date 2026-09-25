/**
 * Screenshot rules for the chat: which image URLs may be shown (isScreenshotDataUrl), the alt text
 * (screenshotAlt), whether a saved tool result had a screenshot that was not kept
 * (hasDroppedScreenshot), and which note says why one is not shown (missingScreenshotNote).
 *
 * Why it exists: A tool's screenshot reaches the live chat once and is never saved, so the thread
 * must show it while it is here and say plainly when it is gone. Only a base64 PNG, JPEG or WebP
 * data URL ever goes into an <img>: a remote URL would be fetched on render (tracking,
 * exfiltration), which is why MarkdownMessage never shows images either.
 */

import type { TurnImage } from "@/types";

/** The note that stands in for a screenshot after a reload. */
export const SCREENSHOT_NOT_KEPT = "Screenshot not kept — ask again to see it";
/** The notes for a screenshot the live reply did not show: one past the per-reply limit, or one
 *  that is not a picture this page shows. Asking again changes neither, so neither says to. */
export const SCREENSHOT_OVER_LIMIT = "Screenshot not shown (limit of 3 per reply)";
export const SCREENSHOT_NOT_SHOWN = "Screenshot not shown";

// Most screenshots one reply carries: the server sends the first 3
// (agent.MAX_CHANNEL_IMAGES).
const MAX_REPLY_SCREENSHOTS = 3;

// What the server saves in place of the image (runtime.redact_binary_for_model).
const SAVED_PLACEHOLDER = "[image captured and delivered to the user separately]";

// The server's check, repeated here: the whole string one base64 raster data
// URL, no bigger than an attachment may be (5 MB once decoded).
const SCREENSHOT_URL = /^data:image\/(?:png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/;
const MAX_SCREENSHOT_CHARS = "data:image/jpeg;base64,".length + Math.floor((5 * 1024 * 1024 * 4) / 3) + 4;

// The facts alt text may name: a dotted tool name, and a host or an app name.
const TOOL_NAME = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$/;
const SOURCE_NAME = /^[\p{L}\p{N}_ .&'+()-]{1,253}$/u;

export function isScreenshotDataUrl(url: unknown): url is string {
  if (typeof url !== "string" || url.length > MAX_SCREENSHOT_CHARS) return false;
  const match = SCREENSHOT_URL.exec(url);
  return match !== null && match[1].length % 4 === 0;
}

/** "Screenshot of www.google.com (web.screenshot)": facts only, never a page title or model text. */
export function screenshotAlt(image: Pick<TurnImage, "tool" | "source">): string {
  const source = typeof image.source === "string" && SOURCE_NAME.test(image.source) ? image.source : "";
  const tool = typeof image.tool === "string" && TOOL_NAME.test(image.tool) ? image.tool : "";
  return `Screenshot${source ? ` of ${source}` : ""}${tool ? ` (${tool})` : ""}`;
}

/** Which note stands in for a screenshot that is not shown. `image` is what the live reply sent
 *  for this tool call, `turnImages` everything it sent; a reloaded thread has neither. */
export function missingScreenshotNote(
  image: TurnImage | undefined,
  turnImages: readonly TurnImage[] | undefined,
): string {
  if (image !== undefined) return SCREENSHOT_NOT_SHOWN;
  if (turnImages === undefined) return SCREENSHOT_NOT_KEPT;
  return turnImages.length >= MAX_REPLY_SCREENSHOTS ? SCREENSHOT_OVER_LIMIT : SCREENSHOT_NOT_SHOWN;
}

/** True when a saved tool result held a screenshot: the keys a screenshot tool fills carry the
 *  placeholder the server keeps instead of the image. */
export function hasDroppedScreenshot(result: unknown): boolean {
  if (typeof result !== "object" || result === null) return false;
  const { image, user_image: userImage, needs_human: needsHuman } = result as Record<string, unknown>;
  const handoffImage =
    typeof needsHuman === "object" && needsHuman !== null
      ? (needsHuman as Record<string, unknown>).user_image
      : undefined;
  return [image, userImage, handoffImage].includes(SAVED_PLACEHOLDER);
}
