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
      craneLib = (crane.mkLib pkgs).overrideToolchain (pkgs: pkgs.rust-bin.stable.latest.default);
      src = craneLib.cleanCargoSource inputs.self;

      commonArgs = {
        inherit src;
        strictDeps = true;

        doCheck = false; # tests will be run in the `checks` derivation
        NEXTEST_HIDE_PROGRESS_BAR = 1;
        NEXTEST_FAILURE_OUTPUT = "immediate-final";

        nativeBuildInputs = [ pkgs.mold ];

        meta = {
          license = lib.licenses.mit;
          homepage = "https://github.com/jalil-salame/webnsupdate";
          mainProgram = "webnsupdate";
        };
      };

      cargoArtifacts = craneLib.buildDepsOnly commonArgs;
      withArtifacts = lib.mergeAttrsList [
        commonArgs
        { inherit cargoArtifacts; }
      ];
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
        nextest = craneLib.cargoNextest withArtifacts;
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
