{ lib, rustPlatform }:
let
  readToml = path: builtins.fromTOML (builtins.readFile path);
  cargoToml = readToml ./Cargo.toml;
  pname = cargoToml.package.name;
  inherit (cargoToml.package) version description;
  src = lib.cleanSourceWith {
    src = ./.;
    name = "${pname}-source";
    # Adapted from <https://github.com/ipetkov/crane/blob/master/lib/filterCargoSources.nix>
    # no need to pull in crane for just this
    filter =
      orig_path: type:
      let
        path = toString orig_path;
        base = baseNameOf path;
        matchesSuffix = lib.any (suffix: lib.hasSuffix suffix base) [
          # Rust sources
          ".rs"
          # TOML files are often used to configure cargo based tools (e.g. .cargo/config.toml)
          ".toml"
        ];
        isCargoLock = base == "Cargo.lock";
      in
      type == "directory" || matchesSuffix || isCargoLock;
  };
in
rustPlatform.buildRustPackage {
  inherit pname version src;
  cargoLock.lockFile = ./Cargo.lock;
  useNextest = true;
  NEXTEST_HIDE_PROGRESS_BAR = 1;
  NEXTEST_FAILURE_OUTPUT = "immediate-final";

  meta = {
    inherit description;
    license = lib.licenses.mit;
    homepage = "https://github.com/jalil-salame/webnsupdate";
    mainProgram = "webnsupdate";
  };
}
