// Tests for stage-stack.mjs: what is kept out of the bundle (secrets above all) and that a
// staged tree has the expected shape. Run with `npm test` (node --test) from desktop/.

import { strict as assert } from "node:assert";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { isExcluded, stageStack } from "./stage-stack.mjs";

const tmp = mkdtempSync(join(tmpdir(), "stage-stack-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

function touch(path, body = "x") {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, body);
}

test("secrets never ship; .env.example does", () => {
  for (const name of [".env", ".env.local", ".env.production", ".env.bak-20260924", "prod.env"]) {
    assert.equal(isExcluded(`backend/${name}`, false), true, name);
  }
  assert.equal(isExcluded("backend/.env.example", false), false);
});

test("private keys, certificates and local database data never ship", () => {
  for (const rel of [
    "backend/certs/server.pem",
    "backend/certs/server.key",
    "backend/certs/client.p12",
    "backend/certs/client.pfx",
    "backend/AuthKey_ABC123.p8",
    "backend/id_rsa",
    "backend/id_ed25519",
    "backend/dev_verify.db",
    "docker\\data\\pg\\PG_VERSION",
  ]) {
    assert.equal(isExcluded(rel, false), true, rel);
  }
  assert.equal(isExcluded("docker/data", true), true, "docker/data (the old bind-mounted Postgres folder)");
  // Only the top-level docker/data folder: a source package named data stays.
  assert.equal(isExcluded("backend/services/data", true), false);
  assert.equal(isExcluded("backend/services/data/schema.py", false), false);
});

test("dependencies, build output, tests and caches are excluded at any depth", () => {
  for (const dir of ["node_modules", "dist", "tests", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv"]) {
    assert.equal(isExcluded(`frontend/${dir}`, true), true, dir);
    assert.equal(isExcluded(`backend/a/${dir}/b.py`, false), true, `${dir} nested`);
  }
  assert.equal(isExcluded("backend/core/x.pyc", false), true);
  assert.equal(isExcluded("frontend\\node_modules\\react\\index.js", false), true, "windows separators");
});

test("source files are kept", () => {
  for (const rel of ["backend/main.py", "backend/requirements.txt", "frontend/src/App.tsx", "frontend/src/test/setup.ts", "docker/docker-compose.yml"]) {
    assert.equal(isExcluded(rel, false), false, rel);
  }
});

test("stageStack copies the three trees, skips excluded entries and writes VERSION", () => {
  const project = join(tmp, "project");
  const desktop = join(project, "desktop");
  touch(join(desktop, "package.json"), JSON.stringify({ version: "9.8.7" }));
  touch(join(project, "backend/main.py"));
  touch(join(project, "backend/.env"), "SECRET_KEY=do-not-ship");
  touch(join(project, "backend/.env.example"));
  touch(join(project, "backend/tests/test_x.py"));
  touch(join(project, "backend/core/__pycache__/x.cpython-312.pyc"));
  touch(join(project, "frontend/src/App.tsx"));
  touch(join(project, "frontend/node_modules/react/index.js"));
  touch(join(project, "frontend/dist/index.html"));
  touch(join(project, "docker/docker-compose.yml"));
  touch(join(project, "docker/data/pg/PG_VERSION"));
  touch(join(project, "backend/certs/server.key"));
  touch(join(desktop, "stack/stale.txt")); // from an earlier run: must be cleared
  let linked = true;
  try {
    symlinkSync(join(project, "backend/.env"), join(project, "backend/link.env.txt"));
  } catch {
    linked = false; // Windows without symlink rights: nothing to check
  }

  const { stackDir, version } = stageStack({ projectDir: project, desktopDir: desktop, log: () => {} });

  assert.equal(version, "9.8.7");
  assert.equal(readFileSync(join(stackDir, "VERSION"), "utf8"), "9.8.7\n");
  for (const kept of ["backend/main.py", "backend/.env.example", "frontend/src/App.tsx", "docker/docker-compose.yml"]) {
    assert.ok(existsSync(join(stackDir, kept)), `kept ${kept}`);
  }
  for (const gone of ["backend/.env", "backend/tests", "backend/core/__pycache__", "frontend/node_modules", "frontend/dist", "docker/data", "backend/certs/server.key", "stale.txt"]) {
    assert.ok(!existsSync(join(stackDir, gone)), `excluded ${gone}`);
  }
  if (linked) assert.ok(!existsSync(join(stackDir, "backend/link.env.txt")), "symlinks are not followed");
});
