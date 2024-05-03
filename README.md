# Web NS update

A webserver API for `nsupdate`. This is only intended for my usecase, so feel free to take inspiration, but don't expect this to be useful to you.

## Usage

> [!Note]
> This was made because I needed it. It probably wont fit your usecase.

Using a flake NixOS configuration add these lines:

```nix
{
  inputs.webnsupdate.url = "github:jalil-salame/webnsupdate";
  # inputs.webnsupdate.inputs.nixpkgs.follows = "nixpkgs"; # deduplicate nixpkgs

  # ...
  outputs = {
    nixpkgs,
    webnsupdate,
    ...
  }: {
    # ...
    nixosConfigurations.hostname = let
      system = "...";
      pkgs = import nixpkgs {
        inherit system;
        # IMPORTANT -----------v
        overlays = [webnsupdate.overlays.default];
      };
    in {
      inherit system pkgs;
      modules = [
        webnsupdate.nixosModules.default
        {
          services.webnsupdate = {
            enable = true;
            # ...
          };
        }
      ];
    };
    # ...
  };
}
```
