{
  pkgs ?
    (builtins.getFlake (builtins.toString ./.)).inputs.nixpkgs.legacyPackages.${builtins.currentSystem},
  lib ? pkgs.lib,
  crane ? (builtins.getFlake (builtins.toString ./.)).inputs.crane,
  pkgSrc ? ./.,
  mold ? pkgs.mold,
}:
let
  craneLib = crane.mkLib pkgs;
  src = craneLib.cleanCargoSource pkgSrc;

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

  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
in
craneLib.buildPackage (
  lib.mergeAttrsList [
    commonArgs
    { inherit cargoArtifacts; }
  ]
)
