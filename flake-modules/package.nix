{ inputs, lib, ... }:
{
  perSystem =
    { pkgs, ... }:
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
      webnsupdate = craneLib.buildPackage (
        lib.mergeAttrsList [
          commonArgs
          { inherit cargoArtifacts; }
        ]
      );
    in
    {
      checks = {
        clippy = craneLib.cargoClippy (
          lib.mergeAttrsList [
            commonArgs
            {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          ]
        );

        nextest = craneLib.cargoNextest (
          lib.mergeAttrsList [
            commonArgs
            { inherit cargoArtifacts; }
          ]
        );
      };

      packages = {
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
    };
}
