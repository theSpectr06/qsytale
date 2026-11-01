#!/usr/bin/env bash
# End-to-end crypto test against a throwaway server and database (never touches data/).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=$(mktemp -d)
npx esbuild tests/e2e_crypto.mjs --bundle --platform=node --format=esm \
  --banner:js="import {createRequire as __cr} from 'module'; const require = __cr(import.meta.url);" \
  --outfile="$OUT/e2e.mjs" --log-level=error
node "$OUT/e2e.mjs"
