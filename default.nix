let
  inherit (builtins.getFlake (builtins.toString ./.)) inputs;
in
{
  pkgs ? inputs.nixpkgs.legacyPackages.${builtins.currentSystem},
  lib ? pkgs.lib,
  crane ? inputs.crane,
  craneLib ? crane.mkLib pkgs,
  commonArgs ? (import ./common-args.nix { inherit src lib mold; }),
  cargoArtifacts ? craneLib.buildDepsOnly commonArgs,
  src ? craneLib.cleanCargoSource ./.,
  mold ? pkgs.mold,
}:
craneLib.buildPackage (commonArgs // { inherit cargoArtifacts; })
