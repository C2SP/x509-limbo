{
  inputs.nixpkgs.url = "nixpkgs/nixos-unstable-small";
  outputs = { self, nixpkgs }: let
    lib = nixpkgs.lib;
    forEachSystem = systems: f: lib.genAttrs
      systems (system: f nixpkgs.legacyPackages.${system});
    forAllSystems = f: forEachSystem [ "x86_64-linux" "aarch64-darwin" ] f;
  in {
    devShell = forAllSystems (pkgs: pkgs.mkShell {
      buildInputs = with pkgs; [ go gopls ];
    });
  };
}
