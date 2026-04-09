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
          version = "0.1.0";
          src = ./.;
          vendorHash = "sha256-tGoMEw8zb3QRjTkXKbFBbFJOQPNHcxpcHEs5DTAiOa4=";
          subPackages = [ "." ];
          doCheck = false;
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

        devShells.default = pkgs.mkShell {
          packages = [ pkgs.go pkgs.gopls pkgs.curl ];
        };
      });
}
