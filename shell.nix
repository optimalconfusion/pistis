with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "pistis-env";
  buildInputs = [ gcc rustfmt ];
}
