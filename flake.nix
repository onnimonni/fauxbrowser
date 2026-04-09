{
  description = "fauxbrowser — ProtonVPN WireGuard + TLS fingerprint forging HTTP proxy for crawlers";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # Go build output. Called per-system below.
      mkFauxbrowser = pkgs: pkgs.buildGoModule rec {
        pname = "fauxbrowser";
        version = "0.8.0";
        src = ./.;
        vendorHash = "sha256-OHRRP6yNsxLTs37cZvBwZBzpnfgwLNK6sstNVstj0Qw=";
        subPackages = [ "cmd/fauxbrowser" ];
        ldflags = [
          "-s"
          "-w"
          "-X=main.version=${version}"
        ];
        # Tests run out-of-band via `go test -race ./...` (see CI).
        # Including them in the Nix build path eats multiple gigabytes
        # of /tmp for the race detector's metadata and is redundant
        # with the regular test suite anyway.
        doCheck = false;
        meta = with pkgs.lib; {
          description = "ProtonVPN WireGuard + chrome146 TLS fingerprint forging HTTP proxy for crawlers";
          homepage = "https://github.com/onnimonni/fauxbrowser";
          license = licenses.mit;
          mainProgram = "fauxbrowser";
          platforms = platforms.unix;
          maintainers = [ { name = "Onni Hakala"; github = "onnimonni"; } ];
        };
      };

      # Overlay so `pkgs.fauxbrowser` resolves to the flake's build
      # inside nixosModules.default.
      overlay = final: prev: {
        fauxbrowser = mkFauxbrowser final;
      };
    in
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; overlays = [ overlay ]; };
        fauxbrowser = pkgs.fauxbrowser;
      in {
        packages.default = fauxbrowser;
        packages.fauxbrowser = fauxbrowser;

        apps.default = {
          type = "app";
          program = "${fauxbrowser}/bin/fauxbrowser";
        };

        checks.default = fauxbrowser;

        devShells.default = pkgs.mkShell {
          # chromium is included for development + the optional
          # chromedp WAF challenge solver. The fauxbrowser binary
          # itself does NOT depend on chromium at build time —
          # only at runtime, and only if -solver chromedp is set.
          packages = with pkgs; [ go gopls curl jq chromium ];
        };
      })) // {
        # System-independent outputs.
        overlays.default = overlay;

        nixosModules.default = { config, pkgs, lib, ... }: {
          imports = [ ./nix/module.nix ];
          nixpkgs.overlays = [ overlay ];
        };
      };
}
