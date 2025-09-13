#!/usr/bin/env bash
set -euo pipefail
# Simple coverage helper using cargo-llvm-cov
if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "cargo-llvm-cov not installed. Install via: cargo install cargo-llvm-cov" >&2
  exit 1
fi

# Run full workspace coverage with HTML + summary
cargo llvm-cov --workspace --exclude loadtest --exclude migration --lcov --output-path lcov.info
cargo llvm-cov --workspace --exclude loadtest --exclude migration --html --output-dir target/coverage/html

echo "Generated: lcov.info and target/coverage/html/index.html"
