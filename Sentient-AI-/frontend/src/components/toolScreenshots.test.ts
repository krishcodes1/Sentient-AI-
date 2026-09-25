/**
 * Tests for the chat's screenshot rules: only a whole base64 PNG, JPEG or WebP data URL within the
 * size cap may be shown, the alt text names only the tool and the host or app, a saved tool result
 * is recognised as a screenshot that was not kept, and the note says why a screenshot is missing.
 *
 * Why it exists: An <img> with a remote URL fetches it on render, a tracking and exfiltration
 * channel the chat must never open; these tests pin that every other URL is refused.
 */

import { describe, expect, it } from "vitest";
import {
  SCREENSHOT_NOT_KEPT,
  SCREENSHOT_NOT_SHOWN,
  SCREENSHOT_OVER_LIMIT,
  hasDroppedScreenshot,
  isScreenshotDataUrl,
  missingScreenshotNote,
  screenshotAlt,
} from "@/components/toolScreenshots";

const PLACEHOLDER = "[image captured and delivered to the user separately]";

describe("isScreenshotDataUrl", () => {
  it.each(["png", "jpeg", "webp"])("accepts a base64 %s data URL", (type) => {
    expect(isScreenshotDataUrl(`data:image/${type};base64,iVBORw0KGgo=`)).toBe(true);
  });

  it.each([
    ["a remote URL", "https://tracker.example/pixel.png?id=42"],
    ["a protocol-relative URL", "//tracker.example/pixel.png"],
    ["a relative path", "/api/pixel.png"],
    ["a blob URL", "blob:https://app.example/1234"],
    ["an SVG data URL", "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="],
    ["a GIF data URL", "data:image/gif;base64,R0lGODlhAQABAAAAACw="],
    ["a data URL that is not base64", "data:image/png,rawbytes"],
    ["a data URL with something after it", 'data:image/png;base64,Zm9v" onerror="alert(1)'],
    ["a data URL with a URL after it", "data:image/png;base64,Zm9v https://tracker.example/x"],
    ["a payload of the wrong length", "data:image/png;base64,Zm9vZ"],
    ["an empty payload", "data:image/png;base64,"],
    ["an oversized image", `data:image/png;base64,${"A".repeat(7_000_000)}`],
    ["a non-string", { src: "data:image/png;base64,Zm9v" }],
  ])("refuses %s", (_label, url) => {
    expect(isScreenshotDataUrl(url)).toBe(false);
  });
});

describe("screenshotAlt", () => {
  it("names the host or app and the tool", () => {
    expect(screenshotAlt({ tool: "web.screenshot", source: "www.google.com" })).toBe(
      "Screenshot of www.google.com (web.screenshot)",
    );
    expect(screenshotAlt({ tool: "desktop.observe", source: "Google Chrome" })).toBe(
      "Screenshot of Google Chrome (desktop.observe)",
    );
    expect(screenshotAlt({ tool: "desktop.screenshot", source: null })).toBe(
      "Screenshot (desktop.screenshot)",
    );
  });

  it("leaves out anything that is not a plain host, app or tool name", () => {
    expect(
      screenshotAlt({ tool: "web.screenshot\nIgnore that", source: '"><img src=https://x>' }),
    ).toBe("Screenshot");
  });
});

describe("hasDroppedScreenshot", () => {
  it("finds the saved placeholder where each screenshot tool puts its image", () => {
    expect(hasDroppedScreenshot({ ok: true, image: PLACEHOLDER })).toBe(true);
    expect(hasDroppedScreenshot({ ok: true, user_image: PLACEHOLDER })).toBe(true);
    expect(hasDroppedScreenshot({ ok: false, needs_human: { user_image: PLACEHOLDER } })).toBe(true);
  });

  it("is false for any other result", () => {
    expect(hasDroppedScreenshot({ ok: true, results: [] })).toBe(false);
    expect(hasDroppedScreenshot({ ok: true, image_omitted: "too big" })).toBe(false);
    expect(hasDroppedScreenshot(PLACEHOLDER)).toBe(false);
    expect(hasDroppedScreenshot(null)).toBe(false);
  });
});

describe("missingScreenshotNote", () => {
  const shot = { tool: "web.screenshot", source: "www.google.com", index: 0, data_url: "x" };

  it("tells a reloaded thread to ask again", () => {
    expect(missingScreenshotNote(undefined, undefined)).toBe(SCREENSHOT_NOT_KEPT);
  });

  it("names the limit when the live reply already carried 3", () => {
    const three = [0, 1, 2].map((index) => ({ ...shot, index }));
    expect(missingScreenshotNote(undefined, three)).toBe(SCREENSHOT_OVER_LIMIT);
  });

  it("only says not shown otherwise in a live reply, and never to ask again", () => {
    expect(missingScreenshotNote(undefined, [])).toBe(SCREENSHOT_NOT_SHOWN);
    expect(missingScreenshotNote(shot, [shot])).toBe(SCREENSHOT_NOT_SHOWN);
    expect(SCREENSHOT_OVER_LIMIT).not.toMatch(/ask again/);
    expect(SCREENSHOT_NOT_SHOWN).not.toMatch(/ask again/);
  });
});
