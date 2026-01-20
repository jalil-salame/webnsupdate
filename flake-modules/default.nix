{ lib, inputs, ... }:
let
  webnsupdate = ../module.nix;
  cargoToml = lib.importTOML ../Cargo.toml;
in
{
  imports = [
    inputs.treefmt-nix.flakeModule
    ./package.nix
    ./tests.nix
  ];

  flake.nixosModules = {
    default = webnsupdate;
    inherit webnsupdate;
  };

  perSystem =
    { self', pkgs, ... }:
    {
      # Setup formatters
      treefmt = {
        projectRootFile = "flake.nix";
        programs = {
          nixfmt.enable = true;
          rustfmt = {
            enable = true;
            inherit (cargoToml.package) edition; # respect the package's edition
          };
          statix.enable = true;
          typos.enable = true;
        };
        settings.global.excludes = [
          # auto-generated
          "CHANGELOG.md" # by release-plz
          "*.snap" # by insta
        ];
      };

      packages.release-script = pkgs.writeShellApplication {
        name = "release-script";
        runtimeInputs = [ pkgs.release-plz ];
        text = ../scripts/release.bash;
      };

      devShells = {
        default = pkgs.mkShellNoCC {
          packages = with pkgs; [
            cargo-insta
            cargo-udeps
            mold
            git-cliff
          ];
        };
        release = pkgs.mkShellNoCC {
          inputsFrom = [ self'.packages.webnsupdate ];
          packages = [ self'.packages.release-script ];
        };
      };
    };
}
