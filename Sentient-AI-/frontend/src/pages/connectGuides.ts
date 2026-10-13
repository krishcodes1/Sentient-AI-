/**
 * The guided connect flow's words and rules: per service, the numbered steps a person follows to
 * get the code they paste, plain labels for the catalog's credential fields, which fields are
 * optional extras, how a pasted code is recognized (and Slack's several codes sorted into their
 * fields), and the messages after the check that runs once a connector is saved.
 *
 * Why it exists: the catalog (GET /connectors/types) describes credentials in a developer's terms
 * (access token, base_url, bot token). People who do not know what a token is need steps in plain
 * words with one button per page to open, and the service's own names only where they have to
 * click them. Keeping that copy and the pure rules here leaves Connectors.tsx to render them and
 * lets them be tested without a DOM. A service without a guide (MCP, or one added to the backend
 * later) keeps the catalog's own form.
 */

import type { CanvasSchool, ConnectorTestResult, ConnectorTypeInfo } from "@/types";
import { ROBINHOOD_TYPE, SLACK_TYPE } from "./connectorCatalog";

export const CANVAS_TYPE = "canvas";
export const NOTION_TYPE = "notion";
export const GITHUB_TYPE = "github";
export const GOOGLE_TYPE = "google_workspace";

// ---------------------------------------------------------------------------
// Guides
// ---------------------------------------------------------------------------

export type GuideStep =
  /** Canvas: search for the school, which fills its address (the "url" field). */
  | { kind: "school"; title: string }
  /** Robinhood: make the key pair in the browser (fills the private key field). */
  | { kind: "keypair"; title: string; body: string }
  /** Open the page where the code is made: the catalog's token link, under `button`. */
  | { kind: "open"; title: string; body: string; button: string }
  /** Paste the code (or Slack's codes) into the main fields. */
  | { kind: "paste"; title: string; body?: string }
  /** Something to do in the service after connecting. */
  | { kind: "note"; title: string; body: string };

/** A plain label (and optional placeholder) for one catalog credential field. */
export interface FieldCopy {
  label: string;
  placeholder?: string;
}

/** One code a paste box recognizes, by the prefix the service puts on it. */
export interface PastedCode {
  key: string;
  prefix: string;
  name: string;
  /** What it adds, for an optional code ("chat in Slack DMs"); "" for the one that is needed. */
  adds: string;
}

export interface ConnectGuide {
  /** The service's short name ("Canvas", not "Canvas LMS"). */
  service: string;
  steps: GuideStep[];
  /** Plain labels by field key; a field missing here keeps the catalog's label. */
  fields: Record<string, FieldCopy>;
  /** Optional fields folded under "Advanced (optional)", with a line on what they are for. */
  advanced: string[];
  advancedNote?: string;
  /** Fields filled from one box by prefix, so several codes can be pasted at once. */
  pasteBox?: { label: string; codes: PastedCode[] };
  /** What to do when the check after saving says the service refused what was pasted. */
  fix: string;
}

const GUIDES: Record<string, ConnectGuide> = {
  [CANVAS_TYPE]: {
    service: "Canvas",
    steps: [
      { kind: "school", title: "Find your school" },
      {
        kind: "open",
        title: "Make a connection code in Canvas",
        body:
          'On the page that opens, find Approved integrations and press "New access token". Type Crawler as the purpose, press "Generate token" and copy the long code Canvas shows. It shows it only once.',
        button: "Open my Canvas settings",
      },
      { kind: "paste", title: "Paste the code here" },
    ],
    fields: {
      base_url: { label: "Your school's Canvas address", placeholder: "https://myschool.instructure.com" },
      access_token: { label: "Canvas code", placeholder: "Paste the code from Canvas" },
      client_id: { label: "Developer key ID" },
      client_secret: { label: "Developer key secret" },
      refresh_token: { label: "Refresh code" },
    },
    advanced: ["client_id", "client_secret", "refresh_token"],
    advancedNote:
      "Only if your school gave you a developer key. With these, Crawler renews the Canvas code by itself when it runs out.",
    fix: "Canvas did not accept that code. Make a new one in your Canvas settings (step 2) and paste it again.",
  },
  [NOTION_TYPE]: {
    service: "Notion",
    steps: [
      {
        kind: "open",
        title: "Create a Crawler connection in Notion",
        body:
          'Make a new internal connection named Crawler for your workspace. Open its Configuration tab and copy the code labeled "API token". It starts with ntn_.',
        button: "Open Notion connections",
      },
      { kind: "paste", title: "Paste the code here" },
      {
        kind: "note",
        title: "Choose the pages Crawler can see",
        body:
          "In Notion, open a page, press the ... menu, choose Connections and add Crawler. Crawler sees only the pages you add it to.",
      },
    ],
    fields: { access_token: { label: "Notion code", placeholder: "ntn_..." } },
    advanced: [],
    fix: "Notion did not accept that code. Copy it again from the connection's Configuration tab and paste it.",
  },
  [SLACK_TYPE]: {
    service: "Slack",
    steps: [
      {
        kind: "open",
        title: "Create the Crawler app in Slack",
        body:
          'Pick your workspace, press "Next" and then "Create". On the page that follows, press "Install" and then "Allow".',
        button: "Open Slack app setup",
      },
      {
        kind: "note",
        title: "Copy the codes Slack shows you",
        body:
          'You need the bot code: on the "OAuth & Permissions" page, copy the "Bot User OAuth Token" (it starts with xoxb-). Two more are optional. An app code lets you chat with Crawler in Slack DMs: on "Basic Information", under "App-Level Tokens", make one with connections:write (it starts with xapp-). The "User OAuth Token" adds search and setting your status (it starts with xoxp-).',
      },
      { kind: "paste", title: "Paste them here", body: "All at once or one after another." },
      {
        kind: "note",
        title: "Invite Crawler to your channels",
        body: "Invite the app to a channel before asking Crawler to read it: type /invite @Crawler in that channel.",
      },
    ],
    fields: {
      bot_token: { label: "Bot code", placeholder: "xoxb-..." },
      app_token: { label: "App code, for Slack DMs", placeholder: "xapp-..." },
      user_token: { label: "User code, for search and status", placeholder: "xoxp-..." },
    },
    advanced: [],
    pasteBox: {
      label: "Slack codes",
      codes: [
        { key: "bot_token", prefix: "xoxb-", name: "Bot code", adds: "" },
        { key: "app_token", prefix: "xapp-", name: "App code", adds: "chat in Slack DMs" },
        { key: "user_token", prefix: "xoxp-", name: "User code", adds: "search and status" },
      ],
    },
    fix: "Slack did not accept the bot code. Copy the Bot User OAuth Token again (it starts with xoxb-) and paste it.",
  },
  [GITHUB_TYPE]: {
    service: "GitHub",
    steps: [
      {
        kind: "open",
        title: "Make a GitHub code",
        body:
          'GitHub opens a form already filled in with a name and read-only access. Choose the repositories Crawler may see, press "Generate token" and copy the code. It starts with github_pat_.',
        button: "Open the GitHub form",
      },
      { kind: "paste", title: "Paste the code here" },
    ],
    fields: { access_token: { label: "GitHub code", placeholder: "github_pat_..." } },
    advanced: [],
    fix: "GitHub did not accept that code. Make a new one with the form in step 1 and paste it.",
  },
  [ROBINHOOD_TYPE]: {
    service: "Robinhood",
    steps: [
      {
        kind: "keypair",
        title: "Make a key pair",
        body:
          "Crawler makes two matching keys. The private one stays here, encrypted, and never goes to Robinhood. You give Robinhood the public one.",
      },
      {
        kind: "open",
        title: "Add the public key at Robinhood",
        body:
          "Add a new API credential, paste the public key from step 1 and keep it read-only. Robinhood then shows you an API key. This page is on Robinhood's website, for US accounts.",
        button: "Open Robinhood crypto settings",
      },
      { kind: "paste", title: "Paste the API key Robinhood shows you" },
    ],
    fields: {
      api_key: { label: "Robinhood API key", placeholder: "rh-api-..." },
      api_secret: { label: "Private key" },
    },
    advanced: [],
    fix:
      "Robinhood did not accept the API key with this key pair. Check that you added the public key from step 1, or make a new pair and add it again.",
  },
  [GOOGLE_TYPE]: {
    service: "Google",
    steps: [
      {
        kind: "open",
        title: "Get a temporary code from Google",
        body:
          'On the left, tick the Gmail and Calendar items Crawler should use, press "Authorize APIs" and sign in. Then press "Exchange authorization code for tokens" and copy the "Access token". It starts with ya29.',
        button: "Open Google's test page",
      },
      {
        kind: "paste",
        title: "Paste the code here",
        body:
          "This code stops working after about an hour. For a connection that lasts, ask whoever runs this Crawler to set up Google sign-in.",
      },
    ],
    fields: {
      access_token: { label: "Google code", placeholder: "ya29...." },
      refresh_token: { label: "Refresh code", placeholder: "1//..." },
      client_id: { label: "Client ID" },
      client_secret: { label: "Client secret" },
    },
    advanced: ["refresh_token", "client_id", "client_secret"],
    advancedNote:
      `Only if you have your own Google sign-in app. Before step 1, open the test page's settings (the gear), tick "Use your own OAuth credentials" and enter your app's client ID and secret. Then paste the refresh code from that page, with the same client ID and secret, and Crawler renews the Google code by itself.`,
    fix:
      "Google did not accept that code. Codes from the test page stop working after about an hour, so get a fresh one (step 1).",
  },
};

/** The guided flow for a catalog entry, or null to use the catalog's own form. */
export function connectGuide(entry: ConnectorTypeInfo | undefined): ConnectGuide | null {
  if (!entry || !entry.auth.methods.includes("token") || entry.auth.fields.length === 0) return null;
  return GUIDES[entry.key] ?? null;
}

/** The private key field the Robinhood key pair fills. */
export const KEYPAIR_FIELD = "api_secret";

/** The address field the school search fills (the "url" field Canvas's token link is built from). */
export function schoolFieldKey(entry: ConnectorTypeInfo): string {
  return entry.auth.fields.find((f) => f.type === "url")?.key ?? "base_url";
}

/** The field keys a step shows: the school step its address, the key pair step the private key,
 *  and the paste step every other field that is not an advanced extra. */
export function stepFields(entry: ConnectorTypeInfo, guide: ConnectGuide, step: GuideStep): string[] {
  const all = entry.auth.fields.map((f) => f.key);
  const elsewhere = new Set<string>(guide.advanced);
  for (const other of guide.steps) {
    if (other.kind === "school") elsewhere.add(schoolFieldKey(entry));
    if (other.kind === "keypair") elsewhere.add(KEYPAIR_FIELD);
  }
  if (step.kind === "school") return all.filter((k) => k === schoolFieldKey(entry));
  if (step.kind === "keypair") return all.filter((k) => k === KEYPAIR_FIELD);
  if (step.kind === "paste") return all.filter((k) => !elsewhere.has(k));
  return [];
}

/** Catalog fields with the guide's plain labels and placeholders (hints dropped: the steps say
 *  what each is for), limited to `keys` when given. Without a guide the fields come back as is. */
export function plainFields(
  entry: ConnectorTypeInfo,
  guide: ConnectGuide | null,
  keys?: readonly string[],
): ConnectorTypeInfo["auth"]["fields"] {
  const chosen = keys ? entry.auth.fields.filter((f) => keys.includes(f.key)) : entry.auth.fields;
  if (!guide) return chosen;
  return chosen.map((f) => {
    const copy = guide.fields[f.key];
    if (!copy) return f;
    return { ...f, label: copy.label, placeholder: copy.placeholder ?? "", hint: "" };
  });
}

/** The service's short name for messages: the guide's, else the catalog label. */
export function serviceName(entry: ConnectorTypeInfo): string {
  return GUIDES[entry.key]?.service ?? entry.label;
}

// ---------------------------------------------------------------------------
// Canvas schools
// ---------------------------------------------------------------------------

const HOSTNAME =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** The Canvas address for a school from the search, or null when its domain is not a plain
 *  hostname (the server filters these too; the page never builds a link from anything else). */
export function schoolAddress(school: CanvasSchool): string | null {
  const domain = school.domain.trim().toLowerCase();
  return HOSTNAME.test(domain) ? `https://${domain}` : null;
}

/** The name a new connector gets when the person leaves it blank: "Canvas (NYIT)" once a school
 *  is picked, else the service's catalog label. */
export function defaultDisplayName(entry: ConnectorTypeInfo, school: CanvasSchool | null): string {
  const name = school?.name.trim();
  if (entry.key === CANVAS_TYPE && name) return `Canvas (${name})`;
  return entry.label;
}

// ---------------------------------------------------------------------------
// Pasted codes
// ---------------------------------------------------------------------------

export interface SplitCodes {
  /** Field key to code, for each recognized code (the first of each kind). */
  values: Record<string, string>;
  /** A second code of a kind already found. */
  duplicates: number;
  /** Pieces of the paste that match no known prefix. */
  unknown: number;
}

const EDGE_SEPARATORS = /^[\s,;"'`]+|[\s,;"'`]+$/g;

/**
 * Sorts whatever was pasted into `codes`' fields by prefix. Codes may be separated by spaces,
 * commas or new lines, or run together: a password box drops the line breaks of a multi-line
 * paste, so a new code starts wherever a known prefix does.
 */
export function splitPastedCodes(text: string, codes: readonly PastedCode[]): SplitCodes {
  const result: SplitCodes = { values: {}, duplicates: 0, unknown: 0 };
  const starts: { at: number; code: PastedCode }[] = [];
  for (const code of codes) {
    for (let at = text.indexOf(code.prefix); at !== -1; at = text.indexOf(code.prefix, at + 1)) {
      starts.push({ at, code });
    }
  }
  starts.sort((a, b) => a.at - b.at);
  if (text.slice(0, starts[0]?.at ?? text.length).replace(EDGE_SEPARATORS, "")) result.unknown += 1;
  starts.forEach((start, i) => {
    const end = i + 1 < starts.length ? starts[i + 1].at : text.length;
    const [value, ...rest] = text.slice(start.at, end).replace(EDGE_SEPARATORS, "").split(/[\s,;]+/);
    // Anything after a separator inside the piece is not part of this code.
    if (rest.some(Boolean)) result.unknown += 1;
    if (result.values[start.code.key] !== undefined) result.duplicates += 1;
    else result.values[start.code.key] = value;
  });
  return result;
}

/** What a pasted value looks like, by the prefix its service puts on it. */
interface KnownCode {
  test: RegExp;
  entry: string;
  /** The field it belongs in, when the service has several. */
  field?: string;
  name: string;
}

const CLASSIC_GITHUB = "a classic GitHub code";

const KNOWN_CODES: KnownCode[] = [
  { test: /^github_pat_/, entry: GITHUB_TYPE, name: "a GitHub code" },
  { test: /^gh[pousr]_/, entry: GITHUB_TYPE, name: CLASSIC_GITHUB },
  { test: /^(ntn_|secret_)/, entry: NOTION_TYPE, name: "a Notion code" },
  { test: /^xoxb-/, entry: SLACK_TYPE, field: "bot_token", name: "a Slack bot code" },
  { test: /^xapp-/, entry: SLACK_TYPE, field: "app_token", name: "a Slack app code" },
  { test: /^xoxp-/, entry: SLACK_TYPE, field: "user_token", name: "a Slack user code" },
  { test: /^ya29\./, entry: GOOGLE_TYPE, field: "access_token", name: "a Google code" },
  { test: /^1\/\//, entry: GOOGLE_TYPE, field: "refresh_token", name: "a Google refresh code" },
  { test: /^\d+~[A-Za-z0-9]{20,}$/, entry: CANVAS_TYPE, field: "access_token", name: "a Canvas code" },
];

export interface Recognition {
  ok: boolean;
  text: string;
}

/**
 * A one-line read of what was pasted into a field: recognized ("Looks like a GitHub code."), or a
 * warning when it belongs to another service or another field, or has a space in the middle.
 * Null when there is nothing useful to say: an unfamiliar format is not necessarily wrong.
 */
export function recognizeCode(
  entry: ConnectorTypeInfo,
  fieldKey: string,
  raw: string | undefined,
): Recognition | null {
  const value = (raw ?? "").trim();
  if (!value) return null;
  if (/\s/.test(value)) {
    return { ok: false, text: "There is a space in the middle. Copy the code again, without spaces." };
  }
  const known = KNOWN_CODES.find((k) => k.test.test(value));
  if (!known) return null;
  if (known.entry !== entry.key) {
    return { ok: false, text: `This looks like ${known.name}, not one from ${serviceName(entry)}.` };
  }
  if (known.field && known.field !== fieldKey) {
    const here = plainFields(entry, GUIDES[entry.key] ?? null, [fieldKey])[0]?.label ?? fieldKey;
    return { ok: false, text: `This looks like ${known.name}, which does not go in ${here}.` };
  }
  if (known.name === CLASSIC_GITHUB) {
    return {
      ok: true,
      text: "Looks like a classic GitHub code. It works, but a code from the form reaches only the repositories you choose.",
    };
  }
  return { ok: true, text: `Looks like ${known.name}.` };
}

// ---------------------------------------------------------------------------
// The check after saving
// ---------------------------------------------------------------------------

/** "Connected to NYIT as Rafi Hossain", from the check's answer. `account` wins over the server's
 *  (a school picked by name reads better than its address). */
export function connectedText(
  entry: ConnectorTypeInfo,
  result: Pick<ConnectorTestResult, "account" | "user">,
  account?: string | null,
): string {
  const where = (account ?? "").trim() || (result.account ?? "").trim() || serviceName(entry);
  const who = (result.user ?? "").trim();
  return who ? `Connected to ${where} as ${who}` : `Connected to ${where}`;
}

const UNREACHABLE =
  /could not (reach|connect)|timed? ?out|ConnectError|ConnectTimeout|ReadTimeout|blocked by network policy|getaddrinfo/i;

/** The check's answer when something other than the service answered at the address. */
const WRONG_ADDRESS = /answered, but not like this service/i;

/** The plain message, with what to do, when the check after saving fails. */
export function checkFailureText(entry: ConnectorTypeInfo, detail: string): string {
  const service = serviceName(entry);
  if (WRONG_ADDRESS.test(detail)) {
    return entry.key === CANVAS_TYPE
      ? "That address is not your school's Canvas. Find your school again in step 1, or check the address you typed."
      : `That address does not look like ${service}. Check it and try again.`;
  }
  if (UNREACHABLE.test(detail)) {
    const what =
      entry.key === CANVAS_TYPE ? "your school's address and your internet connection" : "your internet connection";
    return `Crawler could not reach ${service}. Check ${what}, then try again.`;
  }
  return GUIDES[entry.key]?.fix ?? `${service} did not accept what you entered. Check it and try again.`;
}
