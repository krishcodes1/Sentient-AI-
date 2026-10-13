/**
 * Tests for the guided connect flow's pure rules: which services have a guide, which fields each
 * step shows and which are folded away, plain labels, school addresses and default names, sorting
 * pasted Slack codes by prefix, recognizing what was pasted, and the messages after the check.
 *
 * Why it exists: these rules decide what a person who has never seen a token is asked to do and
 * what they are told when it works or does not; a wrong field split, a missed prefix or a link
 * built from a bad school domain would break connecting. Pure functions; no DOM, no network.
 */

import { describe, expect, it } from "vitest";
import type { ConnectorTypeInfo } from "@/types";
import { MCP_ENTRY } from "./connectorCatalog";
import {
  checkFailureText,
  connectGuide,
  connectedText,
  defaultDisplayName,
  plainFields,
  recognizeCode,
  schoolAddress,
  splitPastedCodes,
  stepFields,
  type ConnectGuide,
} from "./connectGuides";

function entry(key: string, label: string, fields: [string, "text" | "password" | "url", boolean][]): ConnectorTypeInfo {
  return {
    ...MCP_ENTRY,
    key,
    label,
    auth: {
      ...MCP_ENTRY.auth,
      methods: ["token"],
      fields: fields.map(([k, type, required]) => ({ key: k, label: k, type, required, placeholder: "", hint: "" })),
    },
  };
}

const CANVAS = entry("canvas", "Canvas LMS", [
  ["base_url", "url", true],
  ["access_token", "password", true],
  ["client_id", "text", false],
  ["client_secret", "password", false],
  ["refresh_token", "password", false],
]);
const SLACK = entry("slack", "Slack", [
  ["bot_token", "password", true],
  ["app_token", "password", false],
  ["user_token", "password", false],
]);
const NOTION = entry("notion", "Notion", [["access_token", "password", true]]);
const GITHUB = entry("github", "GitHub", [["access_token", "password", true]]);
const ROBINHOOD = entry("robinhood", "Robinhood (read-only)", [
  ["api_key", "password", true],
  ["api_secret", "password", true],
]);
const GOOGLE = entry("google_workspace", "Google Workspace", [
  ["access_token", "password", true],
  ["refresh_token", "password", false],
  ["client_id", "text", false],
  ["client_secret", "password", false],
]);

function guideFor(e: ConnectorTypeInfo): ConnectGuide {
  const guide = connectGuide(e);
  if (!guide) throw new Error(`no guide for ${e.key}`);
  return guide;
}

function fieldsOf(e: ConnectorTypeInfo, kind: string): string[] {
  const guide = guideFor(e);
  const step = guide.steps.find((s) => s.kind === kind);
  if (!step) throw new Error(`no ${kind} step`);
  return stepFields(e, guide, step);
}

describe("connectGuide", () => {
  it("guides the pasted-code services and leaves MCP and unknown ones to the catalog form", () => {
    for (const e of [CANVAS, SLACK, NOTION, GITHUB, ROBINHOOD, GOOGLE]) {
      expect(connectGuide(e)).not.toBeNull();
    }
    expect(connectGuide(MCP_ENTRY)).toBeNull();
    expect(connectGuide(entry("mystery", "Mystery", [["access_token", "password", true]]))).toBeNull();
    // A service that cannot take a pasted code here has nothing to guide.
    expect(connectGuide({ ...GITHUB, auth: { ...GITHUB.auth, methods: ["device"] } })).toBeNull();
    expect(connectGuide({ ...GITHUB, auth: { ...GITHUB.auth, fields: [] } })).toBeNull();
    expect(connectGuide(undefined)).toBeNull();
  });

  it("keeps developer words out of step titles and plain labels", () => {
    const jargon = /\b(token|api key|oauth|base_url|bearer)\b/i;
    for (const e of [CANVAS, SLACK, NOTION, GITHUB, GOOGLE]) {
      const guide = guideFor(e);
      for (const step of guide.steps) expect(step.title).not.toMatch(jargon);
      for (const field of plainFields(e, guide)) expect(field.label).not.toMatch(jargon);
    }
  });
});

describe("stepFields and plainFields", () => {
  it("gives the school step the address, the paste step the code, and folds the extras away", () => {
    expect(fieldsOf(CANVAS, "school")).toEqual(["base_url"]);
    expect(fieldsOf(CANVAS, "paste")).toEqual(["access_token"]);
    expect(guideFor(CANVAS).advanced).toEqual(["client_id", "client_secret", "refresh_token"]);
    expect(fieldsOf(GOOGLE, "paste")).toEqual(["access_token"]);
  });

  it("gives the key pair step the private key and the paste step Robinhood's key", () => {
    expect(fieldsOf(ROBINHOOD, "keypair")).toEqual(["api_secret"]);
    expect(fieldsOf(ROBINHOOD, "paste")).toEqual(["api_key"]);
  });

  it("puts every Slack code in the one paste box", () => {
    expect(fieldsOf(SLACK, "paste")).toEqual(["bot_token", "app_token", "user_token"]);
  });

  it("swaps in plain labels and keeps the catalog's rules", () => {
    const [address, code] = plainFields(CANVAS, guideFor(CANVAS), ["base_url", "access_token"]);
    expect(address).toMatchObject({ key: "base_url", label: "Your school's Canvas address", type: "url", required: true });
    expect(code).toMatchObject({ key: "access_token", label: "Canvas code", type: "password", hint: "" });
    expect(plainFields(MCP_ENTRY, null)).toBe(MCP_ENTRY.auth.fields);
  });
});

describe("Canvas schools", () => {
  it("builds the address only from a plain host name", () => {
    expect(schoolAddress({ name: "NYIT", domain: "nyit.instructure.com" })).toBe("https://nyit.instructure.com");
    expect(schoolAddress({ name: "Caps", domain: " Canvas.School.EDU " })).toBe("https://canvas.school.edu");
    for (const domain of ["javascript:alert(1)", "evil.test/path", "user@evil.test", "evil.test:8443", "localhost", "", "a..b"]) {
      expect(schoolAddress({ name: "x", domain })).toBeNull();
    }
  });

  it("names a new Canvas connector after the school picked", () => {
    expect(defaultDisplayName(CANVAS, { name: " NYIT ", domain: "nyit.instructure.com" })).toBe("Canvas (NYIT)");
    expect(defaultDisplayName(CANVAS, null)).toBe("Canvas LMS");
    expect(defaultDisplayName(SLACK, { name: "NYIT", domain: "nyit.instructure.com" })).toBe("Slack");
  });
});

describe("splitPastedCodes", () => {
  const codes = guideFor(SLACK).pasteBox?.codes ?? [];

  it("sorts codes separated by spaces, commas or lines into their fields", () => {
    expect(splitPastedCodes("xoxb-1-a, xapp-1-b\nxoxp-1-c", codes)).toEqual({
      values: { bot_token: "xoxb-1-a", app_token: "xapp-1-b", user_token: "xoxp-1-c" },
      duplicates: 0,
      unknown: 0,
    });
  });

  it("splits codes run together, as a password box leaves a multi-line paste", () => {
    expect(splitPastedCodes("xoxb-1-axapp-1-b", codes).values).toEqual({ bot_token: "xoxb-1-a", app_token: "xapp-1-b" });
  });

  it("counts text that is not a code and a second code of a kind, keeping the first", () => {
    expect(splitPastedCodes("hello xoxb-1-a xoxb-2-b trailing", codes)).toEqual({
      values: { bot_token: "xoxb-1-a" },
      duplicates: 1,
      unknown: 2,
    });
    expect(splitPastedCodes("  ", codes)).toEqual({ values: {}, duplicates: 0, unknown: 0 });
    expect(splitPastedCodes("not-a-code", codes).unknown).toBe(1);
  });
});

describe("recognizeCode", () => {
  it("recognizes a code from the right service and field", () => {
    expect(recognizeCode(GITHUB, "access_token", "github_pat_abc")).toEqual({ ok: true, text: "Looks like a GitHub code." });
    expect(recognizeCode(NOTION, "access_token", "ntn_abc")).toEqual({ ok: true, text: "Looks like a Notion code." });
    expect(recognizeCode(NOTION, "access_token", "secret_abc")?.ok).toBe(true);
    expect(recognizeCode(GOOGLE, "access_token", "ya29.abc")?.ok).toBe(true);
    expect(recognizeCode(CANVAS, "access_token", "1234~abcdefghijklmnopqrstuvwxyz")?.ok).toBe(true);
    expect(recognizeCode(GITHUB, "access_token", "ghp_abc")?.text).toMatch(/classic GitHub code/);
  });

  it("warns about another service's code, a code in the wrong field, and spaces", () => {
    expect(recognizeCode(GITHUB, "access_token", "xoxb-1-a")).toEqual({
      ok: false,
      text: "This looks like a Slack bot code, not one from GitHub.",
    });
    expect(recognizeCode(GOOGLE, "access_token", "1//refresh")).toEqual({
      ok: false,
      text: "This looks like a Google refresh code, which does not go in Google code.",
    });
    expect(recognizeCode(CANVAS, "access_token", "abc def")?.ok).toBe(false);
  });

  it("stays quiet about a blank field or an unfamiliar format", () => {
    expect(recognizeCode(GITHUB, "access_token", "")).toBeNull();
    expect(recognizeCode(ROBINHOOD, "api_key", "some-key-format")).toBeNull();
  });
});

describe("the check after saving", () => {
  it("says where and as whom it connected, preferring the school picked by name", () => {
    expect(connectedText(CANVAS, { account: "nyit.instructure.com", user: "Rafi" }, "NYIT")).toBe("Connected to NYIT as Rafi");
    expect(connectedText(CANVAS, { account: "nyit.instructure.com", user: "Rafi" })).toBe(
      "Connected to nyit.instructure.com as Rafi",
    );
    expect(connectedText(GITHUB, { user: "octocat" })).toBe("Connected to GitHub as octocat");
    expect(connectedText(ROBINHOOD, {})).toBe("Connected to Robinhood");
    expect(connectedText(entry("mystery", "Mystery", []), { account: " ", user: null })).toBe("Connected to Mystery");
  });

  it("explains a refusal with the service's fix, and a network failure as one", () => {
    expect(checkFailureText(CANVAS, "Authentication failed: 401")).toMatch(/^Canvas did not accept that code/);
    expect(checkFailureText(CANVAS, "Connection test failed (ConnectError).")).toBe(
      "Crawler could not reach Canvas. Check your school's address and your internet connection, then try again.",
    );
    expect(checkFailureText(SLACK, "Outbound request blocked by network policy: x")).toMatch(/could not reach Slack/);
    expect(
      checkFailureText(CANVAS, "Could not reach the service. Check the address and the internet connection, then try again."),
    ).toMatch(/^Crawler could not reach Canvas/);
    expect(checkFailureText(CANVAS, "The address answered, but not like this service. Check the address.")).toBe(
      "That address is not your school's Canvas. Find your school again in step 1, or check the address you typed.",
    );
    expect(checkFailureText(NOTION, "The address answered, but not like this service. Check the address.")).toBe(
      "That address does not look like Notion. Check it and try again.",
    );
    expect(checkFailureText(entry("mystery", "Mystery", []), "nope")).toBe(
      "Mystery did not accept what you entered. Check it and try again.",
    );
  });
});
