#!/usr/bin/env bash
# Validate infra/template.yaml: cfn-lint, then the guardrail assertions
# (throttling, reserved concurrency, timeout, log retention, forbidden
# resources) in crates/service/tests/template.rs.
set -euo pipefail
cd "$(dirname "$0")/.."
if command -v cfn-lint >/dev/null; then
  cfn-lint infra/template.yaml
  echo "cfn-lint: ok"
else
  echo "cfn-lint not installed (pip install cfn-lint); skipping lint" >&2
fi
cargo test -q -p service --test template
