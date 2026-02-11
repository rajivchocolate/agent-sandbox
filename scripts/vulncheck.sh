#!/usr/bin/env bash
# vulncheck.sh — Tiered vulnerability checking for CI.
#
# Stdlib vulns (crypto/tls, net/http, etc.) can only be fixed by upgrading the
# Go toolchain. They should not block PRs — Dependabot handles those upgrades.
#
# Dependency vulns that your code actually calls ARE blocking — those are fixable
# by bumping go.mod and are your responsibility.
#
# Usage:
#   scripts/vulncheck.sh          # default: warn on stdlib, fail on deps
#   scripts/vulncheck.sh --strict # fail on everything (scheduled audit)
set -uo pipefail

STRICT="${1:-}"
OUTFILE=$(mktemp)
trap 'rm -f "$OUTFILE"' EXIT

if ! command -v govulncheck &> /dev/null; then
    echo "ERROR: govulncheck not installed. Run 'make setup' first."
    exit 1
fi

echo "Running govulncheck..."
govulncheck ./... > "$OUTFILE" 2>&1
rc=$?

if [ "$rc" -eq 0 ]; then
    echo "No vulnerabilities found."
    exit 0
fi

cat "$OUTFILE"
echo ""

if [ "$STRICT" = "--strict" ]; then
    echo "STRICT MODE: failing on all vulnerabilities."
    exit 1
fi

# Check whether any non-stdlib vulns are present.
# Stdlib vulns show "Found in: <pkg>@go1.x.y" (the @go prefix).
# Module vulns show  "Found in: <module>@v1.x.y" (the @v prefix).
if grep -q 'Found in:.*@v' "$OUTFILE"; then
    echo "ERROR: Dependency vulnerabilities found — these block CI."
    echo "Fix: run 'go get <module>@latest && go mod tidy' for the affected modules."
    exit 1
fi

echo "---"
echo "ADVISORY: Only Go standard library vulnerabilities found."
echo "These are fixed by upgrading the Go toolchain and do not block this PR."
echo "Dependabot will open a PR when the patched Go release is available."
exit 0
