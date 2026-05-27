#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo fmt
cargo check --features whir --tests
cargo test --features whir symbt3_n8 -- --nocapture
cargo test --features whir native_oracle -- --nocapture
cargo test --features whir verify_public -- --nocapture
cargo test --features whir
cargo bench --bench whir_scaling --features whir --no-run
git diff --check
