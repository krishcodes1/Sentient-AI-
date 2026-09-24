#!/usr/bin/env node
// Copies the Crawler AI source the app runs (../backend, ../frontend, ../docker) into
// desktop/stack/ and writes stack/VERSION, so `tauri build` can bundle it as a resource.
//
// Why it exists: the app installs Crawler AI from the exact source that was signed with it
// (the stack module extracts this copy and runs `docker compose` there), so what gets built
// on a user's machine is what shipped — nothing unsigned is downloaded except Docker's base
// images. Secrets (.env and its backups), dependencies, build output, tests and tool caches
// are left out: they are either rebuilt inside the containers or must never ship.
//
// Usage: node scripts/stage-stack.mjs   (run from desktop/; tauri's beforeBuildCommand does)
// Cross-platform: plain Node fs, no shell commands, no symlinks followed.

import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const DESKTOP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROJECT_DIR = resolve(DESKTOP_DIR, "..");

/** The three source trees the stack needs, relative to the project root. */
export const SOURCES = ["backend", "frontend", "docker"];

/** Directory names that are never copied, wherever they appear. */
export const EXCLUDED_DIRS = new Set([
  "node_modules",
  "dist",
  "build",
  "tests",
  "__pycache__",
  ".pytest_cache",
  ".mypy_cache",
  ".ruff_cache",
  ".venv",
  "venv",
  "htmlcov",
  "coverage",
  ".git",
  ".claude",
]);

/**
 * Paths (relative to the project root, POSIX separators) that are never copied.
 * docker/data/ is the old bind-mounted Postgres folder (.gitignore): real user data.
 */
export const EXCLUDED_PATHS = ["docker/data"];

/** Private keys and certificates with their keys (TLS, Apple signing, SSH): never ship. */
const PRIVATE_KEY_FILE = /\.(pem|key|p8|p12|pfx|jks|keystore)$/i;
const SSH_KEY_FILE = /^id_(rsa|dsa|ecdsa|ed25519)$/;

/** File names that are never copied, wherever they appear. */
export const EXCLUDED_FILES = new Set([
  ".DS_Store",
  ".coverage",
  "coverage.xml",
  "tsconfig.tsbuildinfo",
  "bootstrap.log",
]);

/**
 * True when a file or directory at `relPath` (relative to the project root, e.g.
 * "backend/.env"; POSIX or native separators) must stay out of the bundle. `.env.example` is
 * kept: it documents the settings the keys module fills in.
 */
export function isExcluded(relPath, isDir) {
  const parts = relPath.split(/[\\/]/).filter(Boolean);
  const name = parts[parts.length - 1] ?? "";
  const posix = parts.join("/");
  if (EXCLUDED_PATHS.some((p) => posix === p || posix.startsWith(`${p}/`))) return true;
  if (parts.slice(0, -1).some((p) => EXCLUDED_DIRS.has(p))) return true;
  if (isDir) return EXCLUDED_DIRS.has(name);
  if (EXCLUDED_FILES.has(name)) return true;
  // Secrets: .env, .env.local, .env.bak-<time> (installer backups hold the old keys), foo.env
  if (name === ".env" || name.endsWith(".env")) return true;
  if (name.startsWith(".env.") && name !== ".env.example") return true;
  if (PRIVATE_KEY_FILE.test(name) || SSH_KEY_FILE.test(name)) return true;
  if (/\.py[cod]$/.test(name)) return true;
  if (name.endsWith(".db") || name.endsWith(".log")) return true;
  return false;
}

/**
 * Recursively copies `src` into `dest`, skipping excluded entries and symlinks.
 * Returns the number of files copied. Entries are visited in sorted order so the bundle
 * is identical across machines.
 */
export function copyTree(src, dest, root = src) {
  let copied = 0;
  mkdirSync(dest, { recursive: true });
  for (const name of readdirSync(src).sort()) {
    const from = join(src, name);
    const to = join(dest, name);
    const stat = lstatSync(from);
    const rel = relative(root, from);
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) {
      if (isExcluded(rel, true)) continue;
      copied += copyTree(from, to, root);
    } else if (stat.isFile()) {
      if (isExcluded(rel, false)) continue;
      copyFileSync(from, to); // keeps the mode bits (executable scripts stay executable)
      copied += 1;
    }
  }
  return copied;
}

/** The app version: desktop/package.json is the single source (tauri.conf.json reads it too). */
export function appVersion(desktopDir = DESKTOP_DIR) {
  const pkg = JSON.parse(readFileSync(join(desktopDir, "package.json"), "utf8"));
  if (typeof pkg.version !== "string" || !pkg.version) {
    throw new Error("desktop/package.json has no version");
  }
  return pkg.version;
}

/** Rebuilds `<desktopDir>/stack` from `<projectDir>/{backend,frontend,docker}`. */
export function stageStack({ projectDir = PROJECT_DIR, desktopDir = DESKTOP_DIR, log = console.log } = {}) {
  const stackDir = join(desktopDir, "stack");
  // Guard the rm -rf: only ever delete <desktopDir>/stack.
  if (!stackDir.startsWith(desktopDir + sep)) throw new Error(`refusing to clear ${stackDir}`);
  rmSync(stackDir, { recursive: true, force: true });
  mkdirSync(stackDir, { recursive: true });

  let total = 0;
  for (const name of SOURCES) {
    const src = join(projectDir, name);
    if (!existsSync(src)) throw new Error(`missing ${src}`);
    // Paths are matched relative to the project root ("docker/data", "backend/.env").
    const n = copyTree(src, join(stackDir, name), projectDir);
    log(`stage-stack: ${name}/ ${n} files`);
    total += n;
  }
  const version = appVersion(desktopDir);
  writeFileSync(join(stackDir, "VERSION"), `${version}\n`);
  log(`stage-stack: ${total} files, VERSION ${version} -> ${relative(process.cwd(), stackDir) || "."}`);
  return { stackDir, total, version };
}

/** True when node was started with this file (not when a test imports it). */
function invokedDirectly() {
  if (!process.argv[1]) return false;
  // realpath: /tmp vs /private/tmp on macOS; lower-case: drive-letter case on Windows.
  const canonical = (p) => {
    const real = realpathSync(p);
    return process.platform === "win32" ? real.toLowerCase() : real;
  };
  try {
    return canonical(resolve(process.argv[1])) === canonical(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  try {
    stageStack();
  } catch (err) {
    console.error(`stage-stack: ${err.message}`);
    process.exit(1);
  }
}
