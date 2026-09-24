/**
 * Post-build check that dist/ fits the app's strict CSP (`default-src 'self'`): no inline
 * scripts or styles in index.html, nothing loaded from another origin, no data: URIs, and the
 * browser-preview fake left out of the bundle.
 *
 * Why it exists: A single CDN font, an inlined asset or a stray inline <script> would be
 * blocked by the CSP inside the Tauri window and fail silently on someone's Mac. Failing the
 * build here catches it on the developer's machine and in CI instead. Runs after `vite build`.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));
const problems = [];

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)],
  );
}

const files = walk(dist);
const html = readFileSync(join(dist, "index.html"), "utf8");

for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
  if (!/\bsrc=/.test(match[1]) || match[2].trim()) problems.push("index.html: inline <script>");
}
if (/<style\b/i.test(html)) problems.push("index.html: inline <style>");
if (/\sstyle=/i.test(html)) problems.push("index.html: style= attribute");
if (/\son[a-z]+=/i.test(html)) problems.push("index.html: inline event handler attribute");
for (const match of html.matchAll(/\b(?:src|href)=["']([^"']+)["']/gi)) {
  if (/^(?:[a-z]+:)?\/\//i.test(match[1]) || /^data:/i.test(match[1])) {
    problems.push(`index.html: loads ${match[1]} (only same-origin files are allowed)`);
  }
}

for (const file of files.filter((f) => f.endsWith(".css"))) {
  const css = readFileSync(file, "utf8");
  if (/@import/i.test(css)) problems.push(`${file}: @import`);
  for (const match of css.matchAll(/url\(\s*["']?([^"')]+)/gi)) {
    if (/^(?:[a-z]+:)?\/\//i.test(match[1]) || /^data:/i.test(match[1])) {
      problems.push(`${file}: url(${match[1]})`);
    }
  }
}

for (const file of files.filter((f) => f.endsWith(".js"))) {
  const js = readFileSync(file, "utf8");
  if (js.includes("Unknown command in preview")) problems.push(`${file}: contains the browser-preview fake`);
}

if (problems.length) {
  console.error("dist/ would break the app's Content-Security-Policy:");
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}
console.log(`check-dist: ${files.length} files OK (no inline scripts, no remote or data: resources, no preview fake)`);
