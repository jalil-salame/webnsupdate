{
  description = "An http server that calls nsupdate internally";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs =
    {
      self,
      nixpkgs,
      systems,
    }:
    let
      forEachSupportedSystem = nixpkgs.lib.genAttrs (import systems);
    in
    {
      checks = forEachSupportedSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          inherit (nixpkgs) lib;
        in
        {
          fmtRust = pkgs.callPackage ./run-cmd.nix {
            src = self;
            name = "fmt-rust";
            extraNativeBuildInputs = [ pkgs.rustfmt ];
            cmd = "${lib.getExe pkgs.cargo} fmt --all --check --verbose";
          };
          fmtNix = pkgs.callPackage ./run-cmd.nix {
            src = self;
            name = "fmt-nix";
            cmd = "${lib.getExe self.formatter.${system}} --check .";
          };
          lintNix = pkgs.callPackage ./run-cmd.nix {
            src = self;
            name = "lint-nix";
            cmd = "${lib.getExe pkgs.statix} check .";
          };
        }
      );
      formatter = forEachSupportedSystem (system: nixpkgs.legacyPackages.${system}.nixfmt-rfc-style);

      packages = forEachSupportedSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
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
        }
      );

      overlays.default = final: prev: { webnsupdate = final.callPackage ./default.nix { }; };

      nixosModules.default = ./module.nix;

      devShells = forEachSupportedSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo-insta
              pkgs.cargo-udeps
              pkgs.mold
            ];
          };
        }
      );
    };
}
