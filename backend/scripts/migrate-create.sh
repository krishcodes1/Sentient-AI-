#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
alembic revision --autogenerate -m "${1:-migration}"
