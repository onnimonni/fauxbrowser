#!/usr/bin/env bash
# scripts/check-vendor-hash.sh
#
# Warns if go.sum has staged changes but flake.nix vendorHash hasn't
# been updated. Run as a pre-commit hook to catch stale vendorHash
# before it reaches CI.
#
# Exit codes:
#   0 = OK (either go.sum didn't change, or flake.nix was also touched)
#   1 = go.sum changed but flake.nix vendorHash likely stale

set -euo pipefail

# Only check if go.sum is in the staged changeset.
if ! git diff --cached --name-only | grep -q "^go\.sum$"; then
  exit 0
fi

# go.sum changed — check if flake.nix is also staged.
if git diff --cached --name-only | grep -q "^flake\.nix$"; then
  # flake.nix was touched — probably updated vendorHash. Trust it.
  exit 0
fi

echo ""
echo "WARNING: go.sum has staged changes but flake.nix was not modified."
echo "         The vendorHash in flake.nix is likely stale."
echo ""
echo "  Fix: nix build .# 2>&1 | grep 'got:' and update vendorHash"
echo "  Or:  set vendorHash = \"\"; in flake.nix, run nix build, copy the hash"
echo ""
exit 1
