let
  inherit (builtins.getFlake (builtins.toString ./.)) inputs;
in
{
  pkgs ? inputs.nixpkgs.legacyPackages.${builtins.currentSystem},
  lib ? pkgs.lib,
  crane ? inputs.crane,
  craneLib ? crane.mkLib pkgs,
  cargoArtifacts ? null,
  src ? craneLib.cleanCargoSource ./.,
  mold ? pkgs.mold,
}:
let
  commonArgs = {
    inherit src;
    strictDeps = true;

    doCheck = false; # tests will be run in the `checks` derivation
    NEXTEST_HIDE_PROGRESS_BAR = 1;
    NEXTEST_FAILURE_OUTPUT = "immediate-final";

    nativeBuildInputs = [ mold ];

    meta = {
      license = lib.licenses.mit;
      homepage = "https://github.com/jalil-salame/webnsupdate";
      mainProgram = "webnsupdate";
    };
  };
in
craneLib.buildPackage (
  lib.mergeAttrsList [
    commonArgs
    {
      cargoArtifacts =
        if cargoArtifacts == null then craneLib.buildDepsOnly commonArgs else cargoArtifacts;
    }
  ]
)
