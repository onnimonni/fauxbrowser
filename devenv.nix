{ pkgs, lib, config, inputs, ... }:

{
  packages = [ pkgs.git pkgs.curl ];

  languages.go.enable = true;
}
