/**
 * Tests for the security wave's API calls (one section per skill in api.ts): they prove every
 * function reaches exactly one of the server's Security routes with the right method, that
 * together they cover every route (the same 45 rows as the backend's PROTECTED_ROUTES), that a
 * key test without a typed key sends an empty body, that a fingerprint check sends JSON while a
 * file upload sends the raw file as the body, and that a refused upload reads as the server's
 * sentence.
 *
 * Why it exists: WAVE 0 writes these calls before any tab uses them, and each skill's builder
 * may only correct its own section. A path or method that drifted from the backend would show
 * up only when a tab is built, as a 404 or 405 in a page nobody can test yet.
 */

import { describe, expect, it } from "vitest";
import * as api from "@/services/api";
import { jsonResponse, mockFetch } from "@/test/http";

const ID = "00000000-0000-4000-8000-000000000001";

// [what the test calls, method, path under /api]. The paths are tests/test_route_security.py's
// PROTECTED_ROUTES rows for the security wave, in its order.
const CALLS: [string, () => Promise<unknown>, string, string][] = [
  ["getLinkReputationStatus", () => api.getLinkReputationStatus(), "GET", "/security/link-reputation/status"],
  ["getSecurityKeys", () => api.getSecurityKeys(), "GET", "/security/keys"],
  ["testSecurityKey", () => api.testSecurityKey("safe_browsing", "AIza-typed"), "POST", "/security/keys/safe_browsing/test"],
  ["saveSecurityKey", () => api.saveSecurityKey("safe_browsing", "AIza-typed"), "PUT", "/security/keys/safe_browsing"],
  ["removeSecurityKey", () => api.removeSecurityKey("safe_browsing"), "DELETE", "/security/keys/safe_browsing"],

  ["getOutboundSettings", () => api.getOutboundSettings(), "GET", "/security/outbound"],
  ["forgetKnownRecipients", () => api.forgetKnownRecipients(), "DELETE", "/security/outbound/known-recipients"],
  ["addOrganisationDomain", () => api.addOrganisationDomain("acme.co.uk"), "POST", "/security/outbound/domains"],
  ["removeOrganisationDomain", () => api.removeOrganisationDomain(ID), "DELETE", `/security/outbound/domains/${ID}`],

  ["getMailScanStatus", () => api.getMailScanStatus(), "GET", "/security/mail/status"],
  ["listMailAlerts", () => api.listMailAlerts(), "GET", "/security/mail/alerts?view=open"],
  ["requestMailAlertAction", () => api.requestMailAlertAction(ID, "move_to_spam"), "POST", `/security/mail/alerts/${ID}/actions`],
  ["dismissMailAlert", () => api.dismissMailAlert(ID), "POST", `/security/mail/alerts/${ID}/dismiss`],
  ["setMailScanPaused", () => api.setMailScanPaused(ID, true), "PATCH", `/security/mail/accounts/${ID}`],

  ["checkScam", () => api.checkScam({ text: "You won a prize", images: [] }), "POST", "/security/scam-check"],
  ["getScamCheckStatus", () => api.getScamCheckStatus(), "GET", "/security/scam-check/status"],

  ["getMcpReviews", () => api.getMcpReviews(), "GET", "/security/mcp/reviews"],
  ["getMcpToolReview", () => api.getMcpToolReview(ID), "GET", `/security/mcp/pins/${ID}`],
  ["approveMcpTool", () => api.approveMcpTool(ID, "ab".repeat(32)), "POST", `/security/mcp/pins/${ID}/approve`],
  ["keepMcpToolOff", () => api.keepMcpToolOff(ID), "POST", `/security/mcp/pins/${ID}/keep-off`],
  ["approveMcpServer", () => api.approveMcpServer(ID, { [ID]: "ab".repeat(32) }), "POST", `/security/mcp/servers/${ID}/approve`],

  ["getBreachMonitor", () => api.getBreachMonitor(), "GET", "/security/breach"],
  ["addBreachAddress", () => api.addBreachAddress("me@example.com"), "POST", "/security/breach/addresses"],
  ["setBreachAddressPaused", () => api.setBreachAddressPaused(ID, true), "PATCH", `/security/breach/addresses/${ID}`],
  ["removeBreachAddress", () => api.removeBreachAddress(ID), "DELETE", `/security/breach/addresses/${ID}`],
  ["checkBreachAddress", () => api.checkBreachAddress(ID), "POST", `/security/breach/addresses/${ID}/check`],
  ["acknowledgeBreachFinding", () => api.acknowledgeBreachFinding(ID), "POST", `/security/breach/findings/${ID}/acknowledge`],
  ["acknowledgeAllBreachFindings", () => api.acknowledgeAllBreachFindings(), "POST", "/security/breach/findings/acknowledge-all"],
  ["getPwnedRange", () => api.getPwnedRange("21BD1"), "POST", "/security/pwned-passwords/range"],

  ["getSiteRules", () => api.getSiteRules(), "GET", "/security/site-rules"],
  ["createSiteRule", () => api.createSiteRule({ site: "example-casino.com", include_subdomains: true, kind: "blocked" }), "POST", "/security/site-rules"],
  ["updateSiteRule", () => api.updateSiteRule(ID, "always_ask"), "PATCH", `/security/site-rules/${ID}`],
  ["deleteSiteRule", () => api.deleteSiteRule(ID), "DELETE", `/security/site-rules/${ID}`],
  ["setSiteCategory", () => api.setSiteCategory("banks", "trusted"), "PUT", "/security/site-rules/categories/banks"],
  ["checkSite", () => api.checkSite("secure.chase.com"), "POST", "/security/site-rules/check"],

  ["listToolRules", () => api.listToolRules(), "GET", "/security/tool-rules"],
  ["createToolRule", () => api.createToolRule({ name: "Big refunds", tool: "mcp.stripe.*", conditions: [] }), "POST", "/security/tool-rules"],
  ["deleteToolRule", () => api.deleteToolRule(ID), "DELETE", `/security/tool-rules/${ID}`],
  ["setBuiltinToolRule", () => api.setBuiltinToolRule("many_recipients", false), "PUT", "/security/tool-rules/builtins/many_recipients"],
  ["previewToolRule", () => api.previewToolRule({ tool: "mcp.stripe.*", conditions: [] }), "POST", "/security/tool-rules/preview"],
  ["getToolRuleCatalog", () => api.getToolRuleCatalog(), "GET", "/security/tool-rules/catalog"],

  ["listFileChecks", () => api.listFileChecks(), "GET", "/security/files?limit=50"],
  ["checkFileHash", () => api.checkFileHash({ sha256: "ab".repeat(32) }), "POST", "/security/files/check"],
  ["requestFileUpload", () => api.requestFileUpload(ID), "POST", `/security/files/${ID}/upload`],
  ["forgetFileCheck", () => api.forgetFileCheck(ID), "DELETE", `/security/files/${ID}`],
];

describe("security wave API calls", () => {
  it.each(CALLS)("%s reaches its route with its method", async (_name, call, method, path) => {
    const fetchMock = mockFetch(() => jsonResponse(200, {}));
    await call();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`/api${path}`);
    expect(init?.method ?? "GET").toBe(method);
  });

  it("covers each of the server's 45 security routes exactly once", () => {
    const routes = CALLS.map(([, , method, path]) => `${method} ${path.split("?")[0]}`);
    expect(routes).toHaveLength(45);
    expect(new Set(routes).size).toBe(45);
  });

  it("tests the saved key with an empty body when no key is typed", async () => {
    const fetchMock = mockFetch(() => jsonResponse(200, { ok: true, detail: "Google accepted the key." }));
    await api.testSecurityKey("hibp");
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({});
  });

  it("sends only the fingerprint as JSON for a file check", async () => {
    const fetchMock = mockFetch(() => jsonResponse(200, { id: "c1" }));
    await api.checkFileHash({ sha256: "ab".repeat(32), name: "invoice.pdf", size_bytes: 10 });
    const init = fetchMock.mock.calls[0][1];
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(JSON.parse(String(init?.body))).toEqual({ sha256: "ab".repeat(32), name: "invoice.pdf", size_bytes: 10 });
  });

  it("sends a picked file for upload as the raw body with its type, never as JSON", async () => {
    localStorage.setItem("auth_token", "tok-1");
    const fetchMock = mockFetch(() =>
      jsonResponse(202, { action_id: "a1", expires_at: "2026-10-14T13:00:00Z", state: "upload_pending", reason: "r" }),
    );
    const file = new File(["MZ"], "setup.exe", { type: "application/x-msdownload" });

    const result = await api.requestFileUpload(ID, file);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`/api/security/files/${ID}/upload`);
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(file);
    const headers = init?.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/x-msdownload");
    expect(headers.Authorization).toBe("Bearer tok-1");
    expect(result.action_id).toBe("a1");
  });

  it("asks for an upload with no body when the server holds the file", async () => {
    const fetchMock = mockFetch(() => jsonResponse(202, { action_id: "a1" }));
    await api.requestFileUpload(ID);
    expect(fetchMock.mock.calls[0][1]?.body).toBeUndefined();
  });

  it("a refused upload reads as the server's sentence", async () => {
    mockFetch(() => jsonResponse(413, { detail: "This file is too large to send to VirusTotal." }));
    await expect(api.requestFileUpload(ID, new File(["x"], "big.iso"))).rejects.toThrow(
      "This file is too large to send to VirusTotal.",
    );
  });
});
