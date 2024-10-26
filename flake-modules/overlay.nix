{
  flake = {
    overlays.default = _final: prev: { webnsupdate = prev.callPackage ../default.nix { }; };
  };
}
