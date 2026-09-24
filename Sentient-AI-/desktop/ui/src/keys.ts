/**
 * Format rules for keys people paste in "Use my own": SECRET_KEY and ENCRYPTION_KEY.
 *
 * Why it exists: Catching a malformed key in the form beats a backend that refuses to boot
 * after a 15-minute build. The rules match the backend's settings validators and the browser
 * installer's checks (installer/page.html, installer/bootstrap.py); Rust validates again before
 * writing, so these are for fast, specific feedback, not the last line of defence.
 */

/** Why this SECRET_KEY can't be used, or "" when it's fine. */
export function secretKeyProblem(value: string): string {
  if (!value) return "Enter a SECRET_KEY.";
  if (/\s/.test(value)) return "SECRET_KEY must not contain spaces or line breaks.";
  if (value.length < 32) {
    return `SECRET_KEY must be at least 32 characters (this one has ${value.length}).`;
  }
  if (value.length > 512) return "SECRET_KEY must be at most 512 characters.";
  if (/[^\x21-\x7e]/.test(value)) {
    return "SECRET_KEY must use plain letters, digits and symbols (ASCII).";
  }
  if (/["'`\\$#]/.test(value)) {
    return "SECRET_KEY must not contain quotes, backticks, backslashes, $ or #.";
  }
  if (/replace_me|changeme|change-me|your-secret/i.test(value)) {
    return "SECRET_KEY still looks like a placeholder; use a random value.";
  }
  return "";
}

/** Why this ENCRYPTION_KEY can't be used, or "" when it's base64 of exactly 32 bytes. */
export function encryptionKeyProblem(value: string): string {
  if (!value) return "Enter an ENCRYPTION_KEY.";
  if (/\s/.test(value)) return "ENCRYPTION_KEY must not contain spaces or line breaks.";
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) {
    return "ENCRYPTION_KEY must be base64 text (A-Z, a-z, 0-9, + / or - _, with = padding).";
  }
  const invalid = "ENCRYPTION_KEY isn’t valid base64; check the = padding at the end.";
  if (value.length % 4 !== 0) return invalid;
  let raw: string;
  try {
    raw = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    return invalid;
  }
  if (raw.length !== 32) {
    return `ENCRYPTION_KEY must decode to exactly 32 bytes (this one decodes to ${raw.length}).`;
  }
  return "";
}
