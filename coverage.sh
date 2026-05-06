#!/usr/bin/env bash
set -euo pipefail
# Simple coverage helper using cargo-llvm-cov + cargo-nextest

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "cargo-llvm-cov not installed. Install via: cargo install cargo-llvm-cov --locked" >&2
  exit 1
fi
if ! cargo nextest --version >/dev/null 2>&1; then
  echo "cargo-nextest not installed. Install via: cargo install cargo-nextest --locked" >&2
  exit 1
fi

# Collect coverage once using nextest
cargo llvm-cov nextest \
  --workspace \
  --exclude loadtest \
  --exclude migration \
  --no-report

# Generate reports from collected data
cargo llvm-cov report --lcov --output-path lcov.info
cargo llvm-cov report --html --output-dir target/coverage/html

echo "Generated: lcov.info and target/coverage/html/index.html"
