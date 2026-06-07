# flake.nix — auth-go (GSDS Biblioteca) via substrate's go-library-flake.
# The core module is pure stdlib (zero deps) → vendorHash = null. The heavy,
# SDK-bearing akeyless/ leaf is a separate module (its own go.mod) and is not
# built by this flake's library check — it is import-gated (BOREALIS Law 6) and
# lands a clean nix build once its siblings (akeyless-go SDK, shikumi-go) are
# published. Pre-publish proof is `go test` (green) in both modules.
{
  description = "auth-go — the fleet authentication primitive (AuthResolver/Session seam; zero-dep core + gated akeyless leaf)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ { self, nixpkgs, substrate, ... }:
    (import substrate.goLibraryFlakeBuilder { inherit nixpkgs; }) {
      name = "auth-go";
      version = "0.1.0";
      src = self;
      vendorHash = null; # zero-dep core — pure stdlib
      repo = "pleme-io/auth-go";
    };
}
