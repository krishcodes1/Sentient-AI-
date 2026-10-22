/**
 * scamVerdict: the pure helpers behind Security ▸ "Check for scams" — the fixed headline and tone
 * for each verdict, the plain words for a link's level, the source that checked it and where it
 * was found, the "Checked: ..." summary line, and `readImage`, which turns a picked or pasted
 * picture into the data URL the server accepts.
 *
 * Why it exists: the wording is the safety rule here. A verdict must never read as "safe", an
 * unknown verdict from a newer or broken server must fall back to "I couldn't check this" rather
 * than to anything reassuring, and a picture the server would refuse (wrong type, over 4 MB) is
 * refused in the browser before a request is made. Keeping these in a component-free module lets
 * them be pinned by plain unit tests and keeps Fast Refresh working for the tab.
 */

/** The server stores at most 8,000 characters of pasted text (ScamCheckIn.text). */
export const MAX_SCAM_TEXT = 8000;
/** The owner's own note beside the text (ScamCheckIn.note). */
export const MAX_SCAM_NOTE = 500;
/** Pictures per check (ScamCheckIn.images). */
export const MAX_SCAM_IMAGES = 4;
/** Pictures are sent inline as base64, so each stays at the composer's 4 MB (the server allows 5). */
export const MAX_SCAM_IMAGE_BYTES = 4 * 1024 * 1024;
/** The picture types the server's ImageAttachment accepts; SVG is refused (it is markup). */
export const SCAM_IMAGE_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"] as const;

export type HeadlineTone = "danger" | "warning" | "neutral" | "muted";

export interface Headline {
  text: string;
  tone: HeadlineTone;
}

/**
 * The fixed headline for a verdict. Anything this page does not know (a typo, a newer server)
 * is "I couldn't check this": the one answer that claims nothing.
 */
export function headlineFor(verdict: string): Headline {
  switch (verdict) {
    case "likely_scam":
      return { text: "Likely a scam", tone: "danger" };
    case "suspicious":
      return { text: "Suspicious, be careful", tone: "warning" };
    case "no_signs_found":
      return { text: "No signs of a scam found", tone: "neutral" };
    default:
      return { text: "I couldn't check this", tone: "muted" };
  }
}

/** What a link's level means in plain words; an unknown level was not checked. */
export function levelLabel(level: string): string {
  switch (level) {
    case "malicious":
      return "known bad";
    case "suspicious":
      return "look-alike or risky";
    case "no_signs_found":
      return "nothing found";
    default:
      return "not checked";
  }
}

/** Who checked a link. An unknown source is shown as the server named it (plain text). */
export function sourceLabel(source: string): string {
  switch (source) {
    case "local":
      return "Crawler's lists";
    case "safe_browsing":
      return "Google Safe Browsing";
    case "web_risk":
      return "Google Web Risk";
    default:
      return source;
  }
}

/** Where in the checked content a link was found. */
export function originLabel(origin: string): string {
  switch (origin) {
    case "text":
      return "the text";
    case "picture":
      return "a picture";
    case "qr":
      return "a QR code";
    case "sender":
      return "the sender";
    default:
      return origin;
  }
}

function counted(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * The "Checked: ..." line under a result: what was looked at, and whether the check was saved.
 * The server saves every web check in the person's "Scam checks" chat; `conversation_id` is null
 * only when it could not.
 */
export function checkedSummary(
  checked: { text_chars: number; images: number; links: number },
  saved: boolean,
): string {
  const parts: string[] = [];
  if (checked.text_chars > 0) parts.push("the text");
  if (checked.images > 0) parts.push(counted(checked.images, "picture", "pictures"));
  if (checked.links > 0) parts.push(counted(checked.links, "link", "links"));
  const line = parts.length > 0 ? `Checked: ${parts.join(", ")}.` : "Checked: nothing could be read.";
  return saved ? `${line} Saved in your "Scam checks" chat.` : line;
}

/** Why a picture was refused before any request was made. */
export class ImageRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImageRefused";
  }
}

function isScamImageType(type: string): boolean {
  return (SCAM_IMAGE_TYPES as readonly string[]).includes(type);
}

/**
 * Read a picked, pasted or dropped picture into a `data:` URL. Refuses (rejects with
 * `ImageRefused` and a plain sentence) anything but PNG, JPEG, WebP or GIF, and anything over
 * 4 MB, so the server never has to.
 */
export function readImage(file: File): Promise<string> {
  const name = file.name || "That picture";
  if (!isScamImageType(file.type)) {
    return Promise.reject(new ImageRefused(`${name} isn't a PNG, JPEG, WebP or GIF picture.`));
  }
  if (file.size > MAX_SCAM_IMAGE_BYTES) {
    return Promise.reject(
      new ImageRefused(`${name} is larger than ${MAX_SCAM_IMAGE_BYTES / (1024 * 1024)} MB.`),
    );
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = typeof reader.result === "string" ? reader.result : "";
      if (result.startsWith("data:")) resolve(result);
      else reject(new ImageRefused(`${name} could not be read.`));
    };
    reader.onerror = () => reject(new ImageRefused(`${name} could not be read.`));
    reader.readAsDataURL(file);
  });
}
