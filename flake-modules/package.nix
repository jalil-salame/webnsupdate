{ inputs, ... }:
{
  flake.overlays.default = final: prev: {
    webnsupdate = prev.callPackage ../default.nix {
      inherit (inputs) crane;
      pkgSrc = inputs.self;
    };
  };

  perSystem =
    { pkgs, lib, ... }:
    let
      craneLib = inputs.crane.mkLib pkgs;
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
        inherit (inputs) crane;
        pkgSrc = inputs.self;
      };
    in
    {
      checks = {
        nextest = craneLib.cargoNextest withArtifacts;
        clippy = craneLib.cargoClippy (
          lib.mergeAttrsList [
            withArtifacts
            { cargoClippyExtraArgs = "--all-targets -- --deny warnings"; }
          ]
        );
      };

      packages = {
        inherit webnsupdate;
        inherit (pkgs) git-cliff;
        default = webnsupdate;
      };
    };
}
