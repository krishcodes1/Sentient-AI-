#!/bin/bash
# Crawler AI installer for macOS. Double-click this file in Finder: it opens a
# local page in your browser that checks Docker, creates your security keys,
# builds Crawler AI and opens it. Nothing to type.
#
# Downloaded as a ZIP and macOS says it "cannot be opened"? Right-click the
# file > Open once (macOS 15+: System Settings > Privacy & Security > Open
# Anyway). See installer/README.md.

cd "$(dirname "$0")" || exit 1

echo
echo "  Crawler AI installer"
echo

# /usr/bin/python3 exists on every Mac, but until Apple's Command Line Tools
# are installed it is only a stub that asks to install them.
if ! python3 -c 'pass' >/dev/null 2>&1; then
  echo "  This installer needs Python 3, which comes with Apple's Command Line Tools."
  echo "  A window will ask to install them: click Install and wait for it to finish,"
  echo "  then double-click \"Install Crawler AI.command\" again."
  echo
  xcode-select --install >/dev/null 2>&1 || true
  exit 1
fi

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
  echo "  This installer needs Python 3.9 or newer (found $(python3 -V 2>&1))."
  echo "  Install the latest from python.org/downloads, then double-click this file again."
  echo
  exit 1
fi

exec python3 installer/bootstrap.py "$@"
