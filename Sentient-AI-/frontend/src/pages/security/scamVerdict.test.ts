/**
 * Tests for scamVerdict (the pure helpers behind Security ▸ "Check for scams"): they prove every
 * verdict maps to its fixed headline and tone and anything unknown to "I couldn't check this",
 * that link levels, sources and origins read in plain words, that the "Checked:" line counts
 * what was looked at, and that readImage refuses SVG and oversize pictures and returns a data URL
 * for a PNG.
 *
 * Why it exists: the words are the safety rule. A headline that ever read "safe", an unknown
 * verdict shown as anything reassuring, or a picture the server would refuse sent anyway would
 * each mislead someone deciding whether to trust a message.
 */

import { describe, expect, it } from "vitest";
import {
  ImageRefused,
  MAX_SCAM_IMAGE_BYTES,
  checkedSummary,
  headlineFor,
  levelLabel,
  originLabel,
  readImage,
  sourceLabel,
} from "@/pages/security/scamVerdict";

/** Four bytes of PNG header: enough for FileReader to produce a data URL. */
function pngFile(name = "shot.png") {
  return new File([Uint8Array.from([137, 80, 78, 71])], name, { type: "image/png" });
}

/** A file that reports `size` bytes without allocating them. */
function sized(file: File, size: number): File {
  Object.defineProperty(file, "size", { value: size });
  return file;
}

describe("scamVerdict", () => {
  it("every verdict maps to its fixed headline and tone, and an unknown one to not checked", () => {
    expect(headlineFor("likely_scam")).toEqual({ text: "Likely a scam", tone: "danger" });
    expect(headlineFor("suspicious")).toEqual({ text: "Suspicious, be careful", tone: "warning" });
    expect(headlineFor("no_signs_found")).toEqual({ text: "No signs of a scam found", tone: "neutral" });
    expect(headlineFor("not_checked")).toEqual({ text: "I couldn't check this", tone: "muted" });
    for (const unknown of ["safe", "clean", "", "toString", "LIKELY_SCAM"]) {
      expect(headlineFor(unknown)).toEqual({ text: "I couldn't check this", tone: "muted" });
    }
    for (const verdict of ["likely_scam", "suspicious", "no_signs_found", "not_checked", "safe"]) {
      expect(headlineFor(verdict).text).not.toMatch(/safe/i);
    }
  });

  it("link levels, sources and origins read in plain words, and unknown ones are never reassuring", () => {
    expect(levelLabel("malicious")).toBe("known bad");
    expect(levelLabel("suspicious")).toBe("look-alike or risky");
    expect(levelLabel("no_signs_found")).toBe("nothing found");
    expect(levelLabel("not_checked")).toBe("not checked");
    expect(levelLabel("clean")).toBe("not checked");
    expect(sourceLabel("local")).toBe("Crawler's lists");
    expect(sourceLabel("safe_browsing")).toBe("Google Safe Browsing");
    expect(sourceLabel("web_risk")).toBe("Google Web Risk");
    expect(sourceLabel("other_list")).toBe("other_list");
    expect(originLabel("text")).toBe("the text");
    expect(originLabel("picture")).toBe("a picture");
    expect(originLabel("qr")).toBe("a QR code");
    expect(originLabel("sender")).toBe("the sender");
  });

  it("the checked line counts the text, pictures and links and says where the check was saved", () => {
    expect(checkedSummary({ text_chars: 412, images: 1, links: 1 }, true)).toBe(
      'Checked: the text, 1 picture, 1 link. Saved in your "Scam checks" chat.',
    );
    expect(checkedSummary({ text_chars: 0, images: 2, links: 3 }, false)).toBe(
      "Checked: 2 pictures, 3 links.",
    );
    expect(checkedSummary({ text_chars: 0, images: 0, links: 0 }, false)).toBe(
      "Checked: nothing could be read.",
    );
  });

  it("readImage rejects svg and oversize files and returns a data URL for png", async () => {
    const svg = new File(["<svg xmlns='http://www.w3.org/2000/svg'/>"], "logo.svg", {
      type: "image/svg+xml",
    });
    await expect(readImage(svg)).rejects.toBeInstanceOf(ImageRefused);
    await expect(readImage(svg)).rejects.toThrow("logo.svg isn't a PNG, JPEG, WebP or GIF picture.");

    const big = sized(pngFile("big.png"), MAX_SCAM_IMAGE_BYTES + 1);
    await expect(readImage(big)).rejects.toThrow("big.png is larger than 4 MB.");

    // Exactly the cap is still accepted.
    const atCap = sized(pngFile("edge.png"), MAX_SCAM_IMAGE_BYTES);
    await expect(readImage(atCap)).resolves.toMatch(/^data:image\/png;base64,/);

    await expect(readImage(pngFile())).resolves.toBe("data:image/png;base64,iVBORw==");
  });
});
