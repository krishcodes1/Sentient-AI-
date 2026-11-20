#!/bin/bash
# Installs, starts and stops Crawler AI natively on this Mac, for the desktop app.
#
# Why it exists: on a Mac the app runs Crawler AI without Docker, so screen and computer
# control work and macOS asks for permissions in the app's name. The app (src-tauri/src/
# native.rs) runs this script, streams its output into the setup window, maps its "==> "
# lines to progress phases and shows an "error: " line as the failure message.
#
# Usage: crawler-native.sh install | start | stop
#
# The app passes (all absolute paths):
#   CRAWLER_STACK  this version's stack: backend/ (with .env and requirements.lock),
#                  frontend-dist/, mac/
#   CRAWLER_HOME   ~/Library/Application Support/Crawler AI/native
#   CRAWLER_CACHE  ~/Library/Caches/Crawler AI
#   CRAWLER_UV     the bundled uv
#   CRAWLER_PG     the bundled PostgreSQL (bin/, lib/, share/)
#
# What it makes under CRAWLER_HOME: python/ (uv's Python 3.12), venv/, playwright/ (Chromium),
# postgres/ (the database: Unix socket only, no TCP port), run/ (socket, pid), logs/.
# Only uv's download cache lives in CRAWLER_CACHE, so a cleaned cache never breaks the venv.

set -euo pipefail

for var in CRAWLER_STACK CRAWLER_HOME CRAWLER_CACHE CRAWLER_UV CRAWLER_PG; do
  [ -n "${!var:-}" ] || { echo "error: $var is not set (run this from the Crawler AI app)."; exit 2; }
done

# 3000 is the OAuth redirect origin; CRAWLER_PORT exists only for testing beside a running copy.
PORT="${CRAWLER_PORT:-3000}"
BACKEND="$CRAWLER_STACK/backend"
ENV_FILE="$BACKEND/.env"
VENV="$CRAWLER_HOME/venv"
PY="$VENV/bin/python"
PGDATA="$CRAWLER_HOME/postgres"
RUN="$CRAWLER_HOME/run"
LOGS="$CRAWLER_HOME/logs"
PG_BIN="$CRAWLER_PG/bin"
BROWSER_PROFILES="Application Support/Crawler AI/browser-profiles"

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export UV_CACHE_DIR="$CRAWLER_CACHE/uv"
export UV_PYTHON_INSTALL_DIR="$CRAWLER_HOME/python"
export UV_PYTHON_PREFERENCE=only-managed
export UV_NO_CONFIG=1
export PLAYWRIGHT_BROWSERS_PATH="$CRAWLER_HOME/playwright"
export PIP_DISABLE_PIP_VERSION_CHECK=1
# Postgres refuses to start ("postmaster became multithreaded") without a valid locale.
export LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8

phase() { echo "==> $1"; }
say()   { echo "    $*"; }
die()   { echo "error: $*"; exit 1; }

pid_alive()  { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }
port_owner() { { lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null || true; } | awk 'NR>1{print $1" (pid "$2")"}' | sort -u | head -1; }
pg_running() { [ -f "$PGDATA/PG_VERSION" ] && "$PG_BIN/pg_ctl" -D "$PGDATA" status >/dev/null 2>&1; }

# Set KEY=value lines in .env (owner-only, atomically). Values come from the environment
# (named by the arguments), never from argv, so the database password stays out of `ps`.
set_env() {
  "$PY" - "$ENV_FILE" "$@" <<'PY'
import os, sys
path, keys = sys.argv[1], sys.argv[2:]
want = {k: os.environ[k] for k in keys}
out, seen = [], set()
for line in open(path, encoding="utf-8").read().splitlines():
    key = line.split("=", 1)[0].strip()
    if key in want and not line.lstrip().startswith("#"):
        if key not in seen:
            out.append(f"{key}={want[key]}")
            seen.add(key)
        continue
    out.append(line)
out += [f"{k}={v}" for k, v in want.items() if k not in seen]
tmp = path + ".tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
os.replace(tmp, path)
PY
}

env_has_our_database() {
  grep -q "^DATABASE_URL=postgresql+asyncpg://.*host=" "$ENV_FILE" 2>/dev/null
}

check_port() {
  pid_alive "$RUN/backend.pid" && return 0
  local owner
  owner="$(port_owner "$PORT")"
  [ -z "$owner" ] || die "Port $PORT is in use by $owner. Quit that app (or an older Crawler AI started from Terminal), then click Retry."
}

# ── install ──────────────────────────────────────────────────────────────────
cmd_install() {
  phase building
  [ -f "$ENV_FILE" ] || die "The security keys are missing. Click Retry."
  [ -f "$BACKEND/requirements.lock" ] || die "This copy of the app is incomplete. Download Crawler AI again."
  mkdir -p "$CRAWLER_HOME" "$RUN" "$LOGS" "$CRAWLER_CACHE"
  chmod 700 "$CRAWLER_HOME" "$RUN"
  # macOS caps a socket path at 104 bytes.
  [ "${#RUN}" -le 88 ] || die "The folder $RUN is too long a path for the database socket. Please report this."

  local free_gb
  free_gb="$(df -k "$CRAWLER_HOME" | awk 'NR==2{print int($4/1024/1024)}')"
  [ "$free_gb" -ge 3 ] || die "Only ${free_gb} GB of disk space is free; Crawler AI needs about 3 GB. Free some space, then click Retry."
  check_port

  say "Python 3.12"
  if [ ! -x "$PY" ] || ! "$PY" -c 'import sys' 2>/dev/null; then
    rm -rf "$VENV"
    "$CRAWLER_UV" venv --quiet --seed --python 3.12 "$VENV" \
      || die "Couldn't download Python. Check your internet connection, then click Retry."
  fi
  say "$("$PY" -V)"

  say "Backend packages (each one checked against its pinned SHA-256)"
  "$CRAWLER_UV" pip install --no-progress --python "$PY" --require-hashes -r "$BACKEND/requirements.lock" \
    || die "Couldn't install the backend packages. Check your internet connection, then click Retry."

  say "Chromium for the browser tools"
  "$PY" -m playwright install chromium >"$LOGS/playwright-install.log" 2>&1 \
    || die "Couldn't download Chromium (details in $LOGS/playwright-install.log). Check your internet connection, then click Retry."

  # The password lives only in .env, so the database and that line are made together. A
  # database without its line is from an install that never finished: start it over.
  if [ -f "$PGDATA/PG_VERSION" ] && ! env_has_our_database; then
    # Never delete a database Crawler AI has run on: that is the user's data.
    [ ! -f "$CRAWLER_HOME/installed-version" ] \
      || die "The database password is missing from $ENV_FILE. Restore that file from a backup, or contact support; your data is untouched."
    pg_running && "$PG_BIN/pg_ctl" -D "$PGDATA" -m fast -w stop >/dev/null
    rm -rf "$PGDATA"
  fi
  if [ ! -f "$PGDATA/PG_VERSION" ]; then
    say "Creating the private database"
    local pwfile pgpass
    pgpass="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(24))')"
    pwfile="$RUN/pgpass.tmp"
    (umask 077 && printf '%s\n' "$pgpass" >"$pwfile")
    "$PG_BIN/initdb" -D "$PGDATA" -U sentientai --pwfile="$pwfile" -A scram-sha-256 \
      -E UTF8 --locale=en_US.UTF-8 >"$LOGS/initdb.log" 2>&1 \
      || { rm -f "$pwfile"; die "Couldn't create the database (details in $LOGS/initdb.log)."; }
    rm -f "$pwfile"
    cat >>"$PGDATA/postgresql.conf" <<EOF

# Crawler AI: a Unix socket in an owner-only folder, no TCP port at all.
listen_addresses = ''
unix_socket_directories = '$RUN'
EOF
    echo "CREATE DATABASE sentientai;" | "$PG_BIN/postgres" --single -D "$PGDATA" postgres >>"$LOGS/initdb.log" 2>&1 \
      || die "Couldn't create the database (details in $LOGS/initdb.log)."
    local socket
    socket="$("$PY" -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe="/"))' "$RUN")"
    DATABASE_URL="postgresql+asyncpg://sentientai:$pgpass@/sentientai?host=$socket" \
    REDIS_URL="" \
    ALLOWED_HOSTS='["localhost","127.0.0.1"]' \
      set_env DATABASE_URL REDIS_URL ALLOWED_HOSTS
    say "Database ready (no network port; socket in $RUN)"
  fi

  cmd_start
}

# ── start / stop ─────────────────────────────────────────────────────────────
cmd_start() {
  phase starting
  [ -x "$PY" ] && [ -f "$PGDATA/PG_VERSION" ] || die "Crawler AI isn't installed yet. Click Install."
  mkdir -p "$RUN" "$LOGS"
  chmod 700 "$CRAWLER_HOME" "$RUN"

  if pg_running; then
    say "Database already running"
  else
    "$PG_BIN/pg_ctl" -D "$PGDATA" -l "$LOGS/postgres.log" -w -t 60 start >/dev/null \
      || die "The database didn't start. Last lines of its log: $(tail -5 "$LOGS/postgres.log" | tr '\n' ' ')"
    say "Database started"
  fi

  if pid_alive "$RUN/backend.pid"; then
    say "Backend already running"
    return 0
  fi
  check_port
  (
    cd "$BACKEND"
    FRONTEND_DIST="$CRAWLER_STACK/frontend-dist" \
      nohup "$VENV/bin/uvicorn" main:app --host 127.0.0.1 --port "$PORT" \
      >>"$LOGS/backend.log" 2>&1 </dev/null &
    echo $! >"$RUN/backend.pid"
  )
  say "Backend starting on http://127.0.0.1:$PORT (the first start sets up the database tables)"
}

cmd_stop() {
  local pid i
  if pid_alive "$RUN/backend.pid"; then
    pid="$(cat "$RUN/backend.pid")"
    kill "$pid" 2>/dev/null || true
    for ((i = 0; i < 30; i++)); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$pid" 2>/dev/null || true
    say "Backend stopped"
  fi
  rm -f "$RUN/backend.pid"
  # Browser windows the backend opened for its own profiles.
  pkill -f "$BROWSER_PROFILES" 2>/dev/null || true
  if pg_running; then
    "$PG_BIN/pg_ctl" -D "$PGDATA" -m fast -w -t 30 stop >/dev/null
    say "Database stopped"
  fi
}

case "${1:-}" in
  install) cmd_install ;;
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  *)       echo "usage: $0 install | start | stop"; exit 2 ;;
esac
