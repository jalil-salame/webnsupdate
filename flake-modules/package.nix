{
  perSystem =
    { pkgs, ... }:
    {
      packages =
        let
          webnsupdate = pkgs.callPackage ../default.nix { };
        in
        {
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
