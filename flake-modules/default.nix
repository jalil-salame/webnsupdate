{ inputs, ... }:
{
  imports = [
    inputs.treefmt-nix.flakeModule
    ./package.nix
    ./module.nix
    ./tests.nix
  ];

  perSystem =
    { pkgs, ... }:
    {
      # Setup formatters
      treefmt = {
        projectRootFile = "flake.nix";
        programs = {
          nixfmt.enable = true;
          rustfmt.enable = true;
          statix.enable = true;
          typos.enable = true;
        };
      };

      devShells.default = pkgs.mkShellNoCC {
        packages = [
          pkgs.cargo-insta
          pkgs.cargo-udeps
          pkgs.mold
        ];
      };
    };
}
