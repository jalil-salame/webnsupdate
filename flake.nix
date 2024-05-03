{
  description = "An http server that calls nsupdate internally";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    supportedSystems = ["x86_64-linux" "aarch64-darwin" "x86_64-darwin" "aarch64-linux"];
    forEachSupportedSystem = f:
      nixpkgs.lib.genAttrs supportedSystems (system:
        f {
          inherit system;
          pkgs = import nixpkgs {inherit system;};
        });
  in {
    formatter = forEachSupportedSystem ({pkgs, ...}: pkgs.alejandra);

    # checks = forEachSupportedSystem ({pkgs, ...}: {
    #   module = pkgs.testers.runNixOSTest {
    #     name = "webnsupdate module test";
    #     nodes.testMachine = {imports = [self.nixosModules.default];};
    #   };
    # });

    packages = forEachSupportedSystem ({pkgs, ...}: {
      default = pkgs.callPackage ./default.nix {};
    });

    overlays.default = final: prev: {
      webnsupdate = final.callPackage ./default.nix {};
    };

    nixosModules.default = ./module.nix;

    devShells = forEachSupportedSystem ({pkgs, ...}: {
      default = pkgs.mkShell {
        packages = [pkgs.cargo-insta];
      };
    });
  };
}
