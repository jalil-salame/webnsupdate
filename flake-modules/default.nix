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
      };

      packages.release-script = pkgs.writeShellApplication {
        name = "release-script";
        runtimeInputs = [ pkgs.release-plz ];
        text = ''
          case "$FORGEJO_REF" in
            # On main create a release
            refs/heads/main)
              # Generate a release (won't do anything if the current version is already published)
              echo "Creating release"
              release-plz release --forge=gitea

              # Create a release PR (will bump the version)
              echo "Creating release PR"
              release-plz release-pr --forge=gitea
              ;;
            # Not on main, do a dry-run
            *)
              # Update package version and changelog
              echo "Updating package version and changelog"
              release-plz update --forge=gitea

              # Do a dry-run
              echo "Release dry-run"
              release-plz release --forge=gitea --dry-run --allow-dirty
              ;;
          esac
        '';
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
