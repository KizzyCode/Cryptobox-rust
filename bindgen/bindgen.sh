#!/bin/sh
set -euo pipefail

bindgen --no-layout-tests --no-derive-debug --no-recursive-allowlist --size_t-is-usize \
  --allowlist-type "sodium_.*" --allowlist-type "crypto_.*" \
  --allowlist-function "sodium_.*" --allowlist-function "crypto_.*" --allowlist-function "randombytes_buf" \
  --allowlist-var "sodium_.*" --allowlist-var "crypto_.*" \
  --output sodium.rs "$SODIUM_H"
