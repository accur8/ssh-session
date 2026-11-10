{
  description = "ssh-session: today's ssh session certificate and git key, into the ssh-agent";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEachSystem = nixpkgs.lib.genAttrs systems;
    in
    {
      # The package as a function of nixpkgs, for a flake that composes its own
      # package set: pkgs.callPackage ssh-session.lib.package { }.
      lib.package = import ./package.nix;

      packages = forEachSystem (
        system:
        let
          ssh-session = nixpkgs.legacyPackages.${system}.callPackage ./package.nix { };
        in
        {
          inherit ssh-session;
          default = ssh-session;
        }
      );

      apps = forEachSystem (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/ssh-session";
        };
      });
    };
}
