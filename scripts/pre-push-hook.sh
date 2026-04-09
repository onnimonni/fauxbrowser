#!/usr/bin/env bash
# scripts/pre-push-hook.sh
#
# Git pre-push hook. Fires on every `git push` and blocks the push
# if ANY of the refs being pushed is a v*.*.* tag whose version
# doesn't match the flake.nix version literal.
#
# No-op for branch pushes. No-op for non-version tags (e.g.
# "nightly", "beta", anything that doesn't match v*.*.*).
#
# Installed as .git/hooks/pre-push by devenv's enterShell (see
# devenv.nix).

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
CHECK="$REPO_ROOT/scripts/check-flake-version.sh"

if [ ! -x "$CHECK" ]; then
  # Script missing — skip to avoid blocking unrelated pushes.
  exit 0
fi

# git passes push info on stdin, one line per ref:
#   <local_ref> <local_sha> <remote_ref> <remote_sha>
while read -r local_ref local_sha remote_ref remote_sha; do
  case "$remote_ref" in
    refs/tags/v[0-9]*.[0-9]*.[0-9]* )
      tag="${remote_ref#refs/tags/}"
      echo "pre-push: verifying $tag matches flake.nix version literal"
      if ! (cd "$REPO_ROOT" && "$CHECK" "$tag"); then
        echo ""
        echo "pre-push: REFUSING to push $tag — fix flake.nix first" >&2
        echo "          (bypass with git push --no-verify if you REALLY know)" >&2
        exit 1
      fi
      ;;
  esac
done

exit 0
