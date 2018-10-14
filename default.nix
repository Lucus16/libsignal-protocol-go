{ pkgs ? import <nixpkgs> {} }:

with pkgs;

buildGoPackage {
  name = "libsignal-protocol-go";
  src = ./.;
  goPackagePath = "github.com/Lucus16/libsignal-protocol-go";
}
