{
  description = "An http server that calls nsupdate internally";
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs = {
    self,
    nixpkgs,
    systems,
  }: let
    forEachSupportedSystem = nixpkgs.lib.genAttrs (import systems);
  in {
    formatter = forEachSupportedSystem (system: nixpkgs.legacyPackages.${system}.alejandra);

    packages = forEachSupportedSystem (system: {
      default = nixpkgs.legacyPackages.${system}.callPackage ./default.nix {};
    });

    overlays.default = final: prev: {
      webnsupdate = final.callPackage ./default.nix {};
    };

    nixosModules.default = ./module.nix;

    devShells = forEachSupportedSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.mkShell {
        packages = [pkgs.cargo-insta];
      };
    });
  };
}
