{
  description = "An http server that calls nsupdate internally";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import inputs.systems;
      perSystem =
        {
          lib,
          pkgs,
          self',
          ...
        }:
        {
          packages =
            let
              webnsupdate = pkgs.callPackage ./default.nix { };
            in
            {
              inherit webnsupdate;
              default = webnsupdate;
              cargo-update = pkgs.writeShellApplication {
                name = "cargo-update-lockfile";
                runtimeInputs = with pkgs; [
                  cargo
                  gnused
                ];
                text = ''
                  CARGO_TERM_COLOR=never cargo update 2>&1 | sed '/crates.io index/d' | tee -a cargo_update.log
                '';
              };
            };

          formatter = pkgs.nixfmt-rfc-style;

          checks = {
            fmtRust = pkgs.callPackage ./run-cmd.nix {
              src = inputs.self;
              name = "fmt-rust";
              extraNativeBuildInputs = [ pkgs.rustfmt ];
              cmd = "${lib.getExe pkgs.cargo} fmt --all --check --verbose";
            };
            fmtNix = pkgs.callPackage ./run-cmd.nix {
              src = inputs.self;
              name = "fmt-nix";
              cmd = "${lib.getExe self'.formatter} --check .";
            };
            lintNix = pkgs.callPackage ./run-cmd.nix {
              src = inputs.self;
              name = "lint-nix";
              cmd = "${lib.getExe pkgs.statix} check .";
            };
          };

          devShells.default = pkgs.mkShell {
            packages = [
              pkgs.cargo-insta
              pkgs.cargo-udeps
              pkgs.mold
            ];
          };
        };

      flake = {
        overlays.default = final: prev: { webnsupdate = final.callPackage ./default.nix { }; };

        nixosModules.default = ./module.nix;
      };
    };
}
