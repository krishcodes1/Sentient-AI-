/**
 * Tests for the token-link helpers in connectorCatalog.ts: tokenLink, tokenLinkWaitsFor and
 * tokenLinkLabel.
 *
 * Why it exists: the token link sends people straight to the page where they create a credential,
 * and for Canvas it is built from an address the user typed, so it must never render a blank,
 * invalid or javascript: link. Pure functions; no network.
 */

import { describe, expect, it } from "vitest";
import type { ConnectorTypeInfo } from "@/types";
import { MCP_ENTRY, tokenLink, tokenLinkLabel, tokenLinkWaitsFor } from "@/pages/connectorCatalog";

function withAuth(auth: Partial<ConnectorTypeInfo["auth"]>): ConnectorTypeInfo {
  return { ...MCP_ENTRY, key: "acme", label: "Acme", auth: { ...MCP_ENTRY.auth, ...auth } };
}

const CANVAS = withAuth({
  fields: [
    { key: "base_url", label: "Canvas URL", type: "url", required: true, placeholder: "", hint: "" },
    { key: "access_token", label: "Access token", type: "password", required: true, placeholder: "", hint: "" },
  ],
  token_url: "{base_url}/profile/settings",
  token_url_label: "Open your Canvas token page",
});

const GITHUB = withAuth({
  token_url: "https://github.com/settings/personal-access-tokens/new?name=Crawler%20AI",
  token_url_label: "Create a GitHub token",
});

describe("tokenLink", () => {
  it("is null without a token_url", () => {
    expect(tokenLink(MCP_ENTRY)).toBeNull();
    expect(tokenLink(withAuth({ token_url: "" }))).toBeNull();
  });

  it("returns a plain link as is, with or without typed values", () => {
    expect(tokenLink(GITHUB)).toBe(GITHUB.auth.token_url);
    expect(tokenLink(GITHUB, { access_token: "x" })).toBe(GITHUB.auth.token_url);
  });

  it("fills a template from the typed address, trimmed and without trailing slashes", () => {
    expect(tokenLink(CANVAS, { base_url: "https://school.instructure.com" })).toBe(
      "https://school.instructure.com/profile/settings",
    );
    expect(tokenLink(CANVAS, { base_url: "  https://school.instructure.com//  " })).toBe(
      "https://school.instructure.com/profile/settings",
    );
    // A self-hosted Canvas on plain http is accepted, as the form accepts it.
    expect(tokenLink(CANVAS, { base_url: "http://canvas.school.test:8080" })).toBe(
      "http://canvas.school.test:8080/profile/settings",
    );
  });

  it("uses only the typed address's origin, so a pasted page address still works", () => {
    for (const pasted of [
      "https://school.instructure.com/courses/123",
      "https://school.instructure.com/?login_success=1",
      "https://school.instructure.com/#dashboard",
    ]) {
      expect(tokenLink(CANVAS, { base_url: pasted })).toBe("https://school.instructure.com/profile/settings");
    }
  });

  it("is null when a template would leave the typed host", () => {
    const typed = { base_url: "https://school.instructure.com" };
    expect(tokenLink(withAuth({ ...CANVAS.auth, token_url: "{base_url}@x.test/t" }), typed)).toBeNull();
    expect(tokenLink(withAuth({ ...CANVAS.auth, token_url: "{base_url}.x.test/t" }), typed)).toBeNull();
  });

  it("is null while the address is blank or invalid", () => {
    expect(tokenLink(CANVAS)).toBeNull();
    expect(tokenLink(CANVAS, { base_url: "   " })).toBeNull();
    expect(tokenLink(CANVAS, { base_url: "school.instructure.com" })).toBeNull();
    expect(tokenLink(CANVAS, { base_url: "not a url" })).toBeNull();
    expect(tokenLink(CANVAS, { base_url: "/" })).toBeNull();
  });

  it("never renders a javascript: or data: link", () => {
    expect(tokenLink(CANVAS, { base_url: "javascript:alert(1)" })).toBeNull();
    expect(tokenLink(CANVAS, { base_url: "data:text/html,hi" })).toBeNull();
    expect(tokenLink(withAuth({ token_url: "javascript:alert(1)" }))).toBeNull();
    expect(tokenLink(withAuth({ token_url: "/relative/path" }))).toBeNull();
  });

  it("is null when the template names no url field", () => {
    expect(tokenLink(withAuth({ ...CANVAS.auth, token_url: "{nope}/x" }), { nope: "https://a.test" })).toBeNull();
    const onToken = withAuth({ ...CANVAS.auth, token_url: "{access_token}/x" });
    expect(tokenLink(onToken, { access_token: "https://a.test" })).toBeNull();
  });
});

describe("tokenLinkWaitsFor", () => {
  it("names the url field a template needs, else null", () => {
    expect(tokenLinkWaitsFor(CANVAS)?.key).toBe("base_url");
    expect(tokenLinkWaitsFor(CANVAS)?.label).toBe("Canvas URL");
    expect(tokenLinkWaitsFor(GITHUB)).toBeNull();
    expect(tokenLinkWaitsFor(MCP_ENTRY)).toBeNull();
    expect(tokenLinkWaitsFor(withAuth({ ...CANVAS.auth, token_url: "{access_token}/x" }))).toBeNull();
  });
});

describe("tokenLinkLabel", () => {
  it("uses the catalog's label, falling back to a generic one", () => {
    expect(tokenLinkLabel(CANVAS)).toBe("Open your Canvas token page");
    expect(tokenLinkLabel(withAuth({ token_url: "https://a.test" }))).toBe("Get your code");
    expect(tokenLinkLabel(withAuth({ token_url_label: "  " }))).toBe("Get your code");
  });
});
