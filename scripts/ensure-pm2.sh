#!/usr/bin/env bash
set -euo pipefail

if command -v pm2 >/dev/null 2>&1; then
  pm2 --version
  exit 0
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "PM2 is not installed, and npm is not available to install it." >&2
  echo "Install Node.js/npm, then run: npm install -g pm2" >&2
  exit 69
fi

npm install -g pm2
pm2 --version
