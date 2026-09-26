/**
 * Tests for PURCHASE_NOTICE: the web copy is the sentence the design fixes, and it equals the
 * fixture the backend publishes, so a purchase card reads the same in chat, on the dashboard and
 * in Telegram.
 *
 * Why it exists: Guards against the two copies drifting apart when one side rewords the notice.
 */

import { describe, expect, it } from "vitest";
import { PURCHASE_NOTICE } from "@/pages/purchaseNotice";

// The test runs in Node, but the frontend does not depend on @types/node, so
// the modules are loaded by name rather than imported: typed `any`, and the
// same whether or not a parent directory happens to hold those typings.
const NODE_FS = "node:fs";
const NODE_PATH = "node:path";
const NODE_URL = "node:url";
const fs = await import(/* @vite-ignore */ NODE_FS);
const path = await import(/* @vite-ignore */ NODE_PATH);
const url = await import(/* @vite-ignore */ NODE_URL);

// backend/tests/fixtures/purchase_notice.txt, from frontend/src/pages. Built
// from the path string, not `new URL(..., import.meta.url)`, which Vite would
// rewrite into a dev-server asset URL that no file check can see.
const FIXTURE = path.resolve(
  path.dirname(url.fileURLToPath(import.meta.url)),
  "../../../backend/tests/fixtures/purchase_notice.txt",
);

describe("PURCHASE_NOTICE", () => {
  it("is the sentence the design fixes", () => {
    expect(PURCHASE_NOTICE).toBe(
      "Crawler can make mistakes. Check the amount and the site before you approve.",
    );
  });

  // The fixture is written by the backend's checkout package. Until it is in
  // the tree there is nothing to compare against, and a missing file must
  // not pass as a match — so this case skips, visibly, rather than fakes it.
  it.skipIf(!fs.existsSync(FIXTURE))("matches the backend fixture word for word", () => {
    expect(String(fs.readFileSync(FIXTURE, "utf8")).trim()).toBe(PURCHASE_NOTICE);
  });
});
