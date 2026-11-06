#!/usr/bin/env bash
# Run every ```bash code block in the user-facing docs, in order, in one
# shell session against the local dev setup (SPEC §12: doc samples must be
# verified). Blocks fenced as ```sh, ```text or ```console are NOT run
# (they need AWS, are interactive, or are illustrative output).
#
# Prerequisites: docker compose up -d; cargo run -p service -- seed;
# cargo run -p service; (cd examples/node-app && npm start) -- each in its own terminal.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

FILES=(docs/cli.md docs/integration-guide.md docs/operations.md README.md)

cargo build -q -p clang-auth-cli
export PATH="$ROOT/target/debug:$PATH"
set -a; . ./.env.example; set +a

# The middleware in the integration guide must be the example app's file,
# verbatim (minus its 3-line header comment).
snippet=$(awk '/^```ts$/{n++; if(n==1){f=1; next}} /^```$/{if(f){exit}} f' docs/integration-guide.md)
if [ "$snippet" != "$(tail -n +4 examples/node-app/src/auth.ts)" ]; then
  echo "docs/integration-guide.md middleware differs from examples/node-app/src/auth.ts" >&2; exit 1
fi
echo "integration-guide middleware matches examples/node-app/src/auth.ts"

curl -sf "$AUTH_BASE_URL/health" >/dev/null || { echo "service not running at $AUTH_BASE_URL" >&2; exit 1; }

# Clean leftovers from a previous run so the examples are repeatable.
clang-auth user delete alice@example.com --yes >/dev/null 2>&1 || true
clang-auth app delete recipes --yes >/dev/null 2>&1 || true

script=$(mktemp)
trap 'rm -f "$script"' EXIT
{
  echo 'set -euo pipefail'
  for f in "${FILES[@]}"; do
    awk -v file="$f" '
      /^```bash[[:space:]]*$/ { inblock=1; n++; printf "echo \"--- %s block %d\"\n", file, n; next }
      /^```/ && inblock     { inblock=0; next }
      inblock               { print }
    ' "$f"
  done
} > "$script"

blocks=$(grep -c '^echo "--- ' "$script" || true)
echo "running $blocks doc blocks from: ${FILES[*]}"
(cd "$ROOT" && bash "$script")
echo "all $blocks doc example blocks ran successfully"
