#!/usr/bin/env bash
# scripts/check-flake-version.sh
#
# Verifies that flake.nix's `version = "X.Y.Z"` literal matches a
# given git tag (or, if no arg, the most recent v*.*.* tag).
#
# Why this exists: fauxbrowser shipped v0.6.0 with a stale
# `version = "0.5.0"` literal in flake.nix, so the nix derivation
# and store path were labelled 0.5.0 even though the release binary
# itself reported 0.6.0. This script is wired into the release
# workflow and into a git pre-push hook so the mismatch can't
# slip past again.
#
# Usage:
#   scripts/check-flake-version.sh                  # check latest tag on HEAD
#   scripts/check-flake-version.sh v0.7.0           # check specific tag
#   scripts/check-flake-version.sh refs/tags/v0.7.0 # accept git ref form
#
# Exit codes:
#   0 = match
#   1 = mismatch (with diff printed)
#   2 = no tag found / bad input / flake.nix unreadable

set -euo pipefail

FLAKE="flake.nix"

input="${1:-}"
if [ -z "$input" ]; then
  # No arg: find the most recent v*.*.* tag.
  input="$(git describe --tags --abbrev=0 --match='v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true)"
  if [ -z "$input" ]; then
    echo "check-flake-version: no v*.*.* tag found via git describe" >&2
    exit 2
  fi
fi

# Strip refs/tags/ prefix if present (pre-push hook passes refs).
input="${input#refs/tags/}"
# Strip leading v.
want="${input#v}"

if [ ! -f "$FLAKE" ]; then
  echo "check-flake-version: $FLAKE not found (cwd=$(pwd))" >&2
  exit 2
fi

# Extract version from flake.nix: first line matching
# `version = "X.Y.Z"`. Uses awk so it's portable across
# BSD/macOS and GNU/Linux without needing GNU sed.
got="$(awk -F'"' '/^[[:space:]]*version = "/ { print $2; exit }' "$FLAKE")"

if [ -z "$got" ]; then
  echo "check-flake-version: could not extract version from $FLAKE" >&2
  exit 2
fi

if [ "$got" != "$want" ]; then
  cat >&2 <<EOF
ERROR: version mismatch between git tag and $FLAKE

  git tag:         v$want
  $FLAKE literal:  $got

The \`version = "X.Y.Z"\` literal inside mkFauxbrowser in $FLAKE
must match the git tag. The nix derivation name and the binary's
main.version ldflag both depend on this value — if they drift,
downstream Nix consumers see the wrong version in their store
paths (e.g. fauxbrowser-0.5.0 when the tag says v0.6.0).

Fix:
  sed -i.bak -E 's/version = "[0-9.]+"/version = "$want"/' $FLAKE && rm $FLAKE.bak
  git add $FLAKE
  git commit --amend --no-edit
  git tag -f v$want   # if the tag already exists locally
EOF
  exit 1
fi

echo "check-flake-version: ok — flake.nix and tag both at v$want"
