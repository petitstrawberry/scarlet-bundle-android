{
  description = "Android userspace bundle producer for Scarlet";
  nixConfig = {
    extra-substituters = [ "https://scarlet-rust-toolchain.cachix.org" "https://scarlet-dev.cachix.org" ];
    extra-trusted-public-keys = [
      "scarlet-rust-toolchain.cachix.org-1:p+coBExi0nNTIvWF/oM9H9/1/GhwFtqGZ2Vs+4pYl6o="
      "scarlet-dev.cachix.org-1:KXKmR/eHKL9t5D4xGFb5NX5s5uUpVVL7HV9PrLZXFHU="
    ];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    scarlet-rust-toolchain.url = "github:petitstrawberry/scarlet-rust-nix/3c23906c35053e28d56f3aa9b1d29142535ffab7";
    scarlet-sdk = {
      url = "github:petitstrawberry/scarlet-sdk/5f7b7cfba43958a6a0d19156fdfe2cae43cfded5";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.scarlet-rust-toolchain.follows = "scarlet-rust-toolchain";
    };
  };
  outputs = { self, nixpkgs, scarlet-rust-toolchain, scarlet-sdk }:
    let
      systems = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];
    in {
      devShells = nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          rust = scarlet-rust-toolchain.packages.${system}.scarlet-rust-toolchain;
          cargo-scarlet = scarlet-sdk.packages.${system}.cargo-scarlet.overrideAttrs (previous: {
            nativeBuildInputs = (previous.nativeBuildInputs or [ ]) ++ [ pkgs.pkg-config ];
            buildInputs = (previous.buildInputs or [ ]) ++ [ pkgs.zstd ];
          });
        in { default = pkgs.mkShell {
              packages = [
                rust
                cargo-scarlet
                pkgs.cacert
                pkgs.coreutils
                pkgs.curl
                pkgs.git
                pkgs.gnutar
                pkgs.gzip
                pkgs.pkg-config
                pkgs.python3
                pkgs.zstd
              ];
              SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            }; });
    };
}
