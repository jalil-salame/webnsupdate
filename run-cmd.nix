{
  stdenvNoCC,
  src,
  name,
  cmd,
  extraBuildInputs ? [],
  extraNativeBuildInputs ? [],
}:
stdenvNoCC.mkDerivation {
  name = "${name}-src";
  inherit src;
  buildInputs = extraBuildInputs;
  nativeBuildInputs = extraNativeBuildInputs;
  buildPhase = cmd;
  installPhase = "mkdir $out";
}
