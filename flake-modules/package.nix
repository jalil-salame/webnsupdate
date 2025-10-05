{ inputs, ... }:
let
  inherit (inputs) crane;
in
{
  flake.overlays.default = final: prev: {
    webnsupdate = prev.callPackage ../default.nix {
      inherit crane;
      pkgSrc = inputs.self;
    };
  };

  perSystem =
    {
      system,
      pkgs,
      lib,
      ...
    }:
    let
      craneLib = (crane.mkLib pkgs).overrideToolchain (
        pkgs:
        pkgs.rust-bin.stable.latest.minimal.override {
          extensions = [
            "clippy"
            "llvm-tools"
          ];
        }
      );
      # Only keep snapshot files
      snapshotFilter = path: _type: builtins.match ".*snap$" path != null;
      snapshotOrCargo = path: type: (snapshotFilter path type) || (craneLib.filterCargoSources path type);
      src = lib.cleanSourceWith {
        src = inputs.self;
        filter = snapshotOrCargo;
        name = "source";
      };

      commonArgs = import ../common-args.nix {
        inherit src lib;
        inherit (pkgs) mold;
      };

      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
      withArtifacts = commonArgs // {
        inherit cargoArtifacts;
      };
      webnsupdate = pkgs.callPackage ../default.nix {
        inherit craneLib cargoArtifacts src;
      };
    in
    {
      # Consume the rust-rust-overlay
      _module.args.pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [ inputs.rust-overlay.overlays.default ];
      };

      checks = {
        nextest = craneLib.cargoNextest (
          withArtifacts
          // {
            doCheck = true;
            withLlvmCov = true;
            cargoLlvmCovExtraArgs = "--lcov --output-path $out/coverage.info";
          }
        );
        deny = craneLib.cargoDeny commonArgs;
        clippy = craneLib.cargoClippy (
          lib.mergeAttrsList [
            withArtifacts
            { cargoClippyExtraArgs = "--all-targets -- --deny warnings"; }
          ]
        );
      };

      packages = {
        inherit webnsupdate;
        default = webnsupdate;
      };
    };
}
