#!/usr/bin/env bash
# Fetch and build the upstream tools this demo drives, pinned to the commits it was tested with.
# They live next to this repo (../predge-zcash-escrow-deps) so their code stays separate.
# Builds are niced and capped at 2 jobs. Needs rustup's toolchain (rustc >= 1.90).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPS="${ZESCROW_DEPS:-$ROOT/../predge-zcash-escrow-deps}"
export PATH="$HOME/.cargo/bin:$PATH"
mkdir -p "$DEPS"
fetch() { # repo dir commit
  [[ -d "$DEPS/$2" ]] || git clone -q "https://github.com/$1.git" "$DEPS/$2"
  git -C "$DEPS/$2" fetch -q origin "$3" 2>/dev/null || true
  git -C "$DEPS/$2" checkout -q "$3"
}
fetch ZcashFoundation/frost-tools frost-tools 53df99c
fetch zcash/zcash-devtool zcash-devtool 0b3436b
(cd "$DEPS/frost-tools" && nice -n 15 cargo build --release -j 2 -p zcash-sign -p frost-client -p frostd)
# Static liblzma avoids linking a Homebrew x86_64 dylib on Apple Silicon.
(cd "$DEPS/zcash-devtool" && LZMA_API_STATIC=1 PKG_CONFIG=/usr/bin/false nice -n 15 cargo build --release -j 2 --features regtest_support)
(cd "$ROOT/crates/zescrow-frost" && nice -n 15 cargo build --release -j 2)
(cd "$ROOT/app" && npm ci)
echo "built: $DEPS/frost-tools/target/release/zcash-sign, $DEPS/zcash-devtool/target/release/zcash-devtool, crates/zescrow-frost"
