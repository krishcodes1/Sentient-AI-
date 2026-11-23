#!/bin/bash
# Gets everything the native Mac app ships besides the stack source, after stage-stack.mjs
# has staged it (tauri.macos.conf.json runs both before every Mac build):
#
#   src-tauri/binaries/uv-*-apple-darwin   uv, universal, run as a Tauri sidecar
#   postgres/                              PostgreSQL 16 (zonky's relocatable build: universal,
#                                          signed and hardened by EnterpriseDB)
#   stack/frontend-dist/                   the built web app the backend serves
#   stack/backend/requirements.lock        every package pinned with its SHA-256; first open
#                                          installs with --require-hashes
#   stack/mac/                             crawler-native.sh, which the app runs
#
# Downloads are pinned and checked against SHA-256s written here; a mismatch stops the build.
# Usage (from desktop/): bash scripts/prep-mac.sh
set -euo pipefail

UV_VERSION=0.11.7
UV_SHA_AARCH64=66e37d91f839e12481d7b932a1eccbfe732560f42c1cfb89faddfa2454534ba8
UV_SHA_X86_64=0a4bc8fcde4974ea3560be21772aeecab600a6f43fa6e58169f9fa7b3b71d302
PG_VERSION=16.16.0
PG_SHA=f8c8cbd962a25a15e918fe094813a9ad48e6c99e0c9e93a1cf98b986cb840dd7

DESKTOP="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="$(cd "$DESKTOP/.." && pwd)"
STACK="$DESKTOP/stack"
DL="$DESKTOP/.downloads"
BIN="$DESKTOP/src-tauri/binaries"

[ -d "$STACK/backend" ] || { echo "prep-mac: run stage-stack first (npm run stage-stack)" >&2; exit 1; }
mkdir -p "$DL" "$BIN"

fetch() { # url sha256 -> path in .downloads
  local file="$DL/$(basename "$1")"
  if [ ! -f "$file" ] || ! echo "$2  $file" | shasum -a 256 -c --status; then
    curl -fsSL --retry 3 -o "$file.part" "$1"
    mv "$file.part" "$file"
  fi
  echo "$2  $file" | shasum -a 256 -c --status || { echo "prep-mac: checksum mismatch for $1" >&2; rm -f "$file"; exit 1; }
  echo "$file"
}

echo "prep-mac: uv $UV_VERSION"
uv_dir="$DL/uv-$UV_VERSION"
mkdir -p "$uv_dir"
for arch in aarch64 x86_64; do
  sha_var="UV_SHA_$(echo "$arch" | tr '[:lower:]' '[:upper:]')"
  tgz="$(fetch "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-$arch-apple-darwin.tar.gz" "${!sha_var}")"
  tar -xzf "$tgz" -C "$uv_dir"
done
lipo -create -output "$BIN/uv-universal-apple-darwin" \
  "$uv_dir/uv-aarch64-apple-darwin/uv" "$uv_dir/uv-x86_64-apple-darwin/uv"
# Tauri looks a sidecar up by the build's target triple.
cp "$BIN/uv-universal-apple-darwin" "$BIN/uv-aarch64-apple-darwin"
cp "$BIN/uv-universal-apple-darwin" "$BIN/uv-x86_64-apple-darwin"
UV="$BIN/uv-universal-apple-darwin"

echo "prep-mac: PostgreSQL $PG_VERSION"
PG="$DESKTOP/postgres"
if [ ! -f "$PG/.version" ] || [ "$(cat "$PG/.version")" != "$PG_VERSION" ]; then
  jar="$(fetch "https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-darwin-arm64v8/$PG_VERSION/embedded-postgres-binaries-darwin-arm64v8-$PG_VERSION.jar" "$PG_SHA")"
  rm -rf "$PG" && mkdir -p "$PG"
  unzip -p "$jar" postgres-darwin-arm_64.txz | tar -xJf - -C "$PG"
  # The archive stores each library under every alias name as a full copy (libicudata alone is
  # 3 x 55 MB). Keep the names some binary actually loads, drop the rest.
  needed="$(find "$PG/bin" "$PG/lib" -type f -exec otool -L {} + 2>/dev/null \
    | awk '/@(rpath|loader_path)\//{print $1}' | sed 's|.*/||' | sort -u)"
  for lib in "$PG"/lib/*.dylib; do
    grep -qxF "$(basename "$lib")" <<<"$needed" || rm -f "$lib"
  done
  echo "$PG_VERSION" >"$PG/.version"
fi
codesign --verify --strict "$PG/bin/postgres"
"$PG/bin/postgres" --version

echo "prep-mac: frontend build"
(cd "$PROJECT/frontend" && npm ci --no-audit --no-fund --loglevel=error && npm run build)
rm -rf "$STACK/frontend-dist"
cp -R "$PROJECT/frontend/dist" "$STACK/frontend-dist"

echo "prep-mac: requirements.lock (hashes)"
# From backend/, so the lock's "# via" comments name requirements.txt, not this machine's path.
(cd "$PROJECT/backend" && "$UV" pip compile --quiet --universal --python-version 3.12 \
  --generate-hashes --no-header -o "$STACK/backend/requirements.lock" requirements.txt)

echo "prep-mac: mac scripts"
rm -rf "$STACK/mac"
cp -R "$DESKTOP/mac" "$STACK/mac"
chmod +x "$STACK/mac/"*.sh

echo "prep-mac: done ($(du -sh "$PG" | cut -f1) Postgres, $(du -sh "$STACK/frontend-dist" | cut -f1) web app)"
