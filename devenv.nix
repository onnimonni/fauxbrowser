{ pkgs, lib, config, inputs, ... }:

{
  packages = [ pkgs.git pkgs.curl ];

  languages.go.enable = true;

  # Install a pre-push git hook that blocks v*.*.* tag pushes when
  # flake.nix's `version = "X.Y.Z"` literal doesn't match. This is
  # a local-only safety net — the same check runs in the GitHub
  # Actions release workflow as the authoritative gate.
  #
  # The hook is a plain script at scripts/pre-push-hook.sh so it's
  # easy to review by hand. We symlink it into .git/hooks/ on every
  # `devenv shell` entry.
  enterShell = ''
    if [ -d .git ]; then
      hook=".git/hooks/pre-push"
      src="$(pwd)/scripts/pre-push-hook.sh"
      if [ -f "$src" ]; then
        if [ ! -L "$hook" ] || [ "$(readlink "$hook" 2>/dev/null)" != "$src" ]; then
          rm -f "$hook"
          ln -s "$src" "$hook"
          echo "devenv: installed git pre-push hook -> $src"
        fi
      fi
    fi
  '';
}
