/**
 * ToolScreenshot: a screenshot a tool took this turn (web.screenshot, browser.read,
 * desktop.screenshot), shown as an image under its tool call, or a short note saying why it is not:
 * "not kept" once the thread is reloaded and only the saved placeholder is left, "not shown" when
 * the live reply did not carry it (past the per-reply limit).
 *
 * Why it exists: The chat printed a screenshot result as a JSON string. The image is delivered to
 * the live turn only (never saved), and anything but a base64 PNG, JPEG or WebP data URL is shown
 * as the note instead, so an <img> here never fetches a remote URL.
 */

import { ImageOff } from "lucide-react";
import type { TurnImage } from "@/types";
import {
  isScreenshotDataUrl,
  missingScreenshotNote,
  screenshotAlt,
} from "@/components/toolScreenshots";

/** `image` is what the live reply sent for this tool call, `turnImages` all it sent (neither after
 *  a reload). */
export default function ToolScreenshot({
  image,
  turnImages,
}: {
  image?: TurnImage;
  turnImages?: readonly TurnImage[];
}) {
  if (image && isScreenshotDataUrl(image.data_url)) {
    return (
      <img
        src={image.data_url}
        alt={screenshotAlt(image)}
        decoding="async"
        className="block mt-1 max-w-full max-h-[480px] w-auto h-auto object-contain rounded-[8px]"
        style={{ border: "1px solid var(--claw-border)" }}
      />
    );
  }
  return (
    <p className="mono-tag flex items-center gap-1.5 mt-1" style={{ color: "var(--text-muted)" }}>
      <ImageOff className="w-3.5 h-3.5 shrink-0" aria-hidden />
      {missingScreenshotNote(image, turnImages)}
    </p>
  );
}
