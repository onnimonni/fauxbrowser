{
  description = "fauxbrowser — TLS fingerprint forging HTTP proxy";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        fauxbrowser = pkgs.buildGoModule {
          pname = "fauxbrowser";
          version = "0.4.0";
          src = ./.;
          vendorHash = "sha256-n02zSPn/NJADb92FBhFALuoY5xLlW8O9LBKYisFg9Z0=";
          subPackages = [ "cmd/fauxbrowser" ];
          doCheck = true;
          meta = with pkgs.lib; {
            description = "TLS fingerprint forging HTTP proxy (uses bogdanfinn/tls-client)";
            license = licenses.mit;
            mainProgram = "fauxbrowser";
            platforms = platforms.unix;
          };
        };
      in {
        packages.default = fauxbrowser;
        packages.fauxbrowser = fauxbrowser;

        apps.default = {
          type = "app";
          program = "${fauxbrowser}/bin/fauxbrowser";
        };

        checks.default = fauxbrowser;

        devShells.default = pkgs.mkShell {
          packages = [ pkgs.go pkgs.gopls pkgs.curl ];
        };
      });
}
