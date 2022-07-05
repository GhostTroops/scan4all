let
  nixpkgs = <nixpkgs>;
in with import nixpkgs {};
stdenv.mkDerivation {
  name = "nix-shell";
  buildInputs = [
    coreutils bashInteractive jq curl gcc git gnumake
    go golangci-lint cacert openssl python3
  ];
  shellHook = ''
    unset GOPATH
    export NIX_PATH=nixpkgs=${nixpkgs}
  '';
}
