{
  src,
  lib,
  mold,
}:
{
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
    maintainers = [
      {
        email = "jalil.salame@gmail.com";
        github = "jalil-salame";
        githubId = 60845989;
        name = "Jalil David Salamé Messina";
        keys = [ { fingerprint = "7D6B 4D8F EBC5 7CBC 09AC  331F DA33 17E7 5BE9 485C"; } ];
      }
    ];
  };
}
