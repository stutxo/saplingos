{ pkgs, lib, rustToolchain }:
pkgs.mkShell {
	LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
	CC = "${pkgs.stdenv.cc}/bin/cc";
	CXX = "${pkgs.stdenv.cc}/bin/c++";
	AR = "${pkgs.stdenv.cc}/bin/ar";
	RANLIB = "${pkgs.stdenv.cc}/bin/ranlib";
	RUST_SRC_PATH = "${rustToolchain.rust-src}/lib/rustlib/src/rust/library";
	LD_LIBRARY_PATH = lib.makeLibraryPath ([
		pkgs.openssl.out
		pkgs.sqlite
	] ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.gcc.cc.lib ]);

	packages = [
		rustToolchain.rustc
		rustToolchain.cargo
		rustToolchain.clippy
		rustToolchain.rust-src
		rustToolchain.rust-std
		rustToolchain.rust-analyzer
		pkgs.stdenv.cc
		pkgs.llvmPackages.clang
		# Protocol signature tests link libbitcoinkernel.
		pkgs.cmake
		pkgs.boost
		pkgs.pkg-config
		pkgs.openssl
		pkgs.protobuf
		pkgs.sqlite
		pkgs.just
		# Compile the SDK's Sapio lifecycle fixture for `just int-sapio`.
		pkgs.wabt
		pkgs.cargo-nextest
		pkgs.git
		pkgs.bash
		pkgs.coreutils
		pkgs.gnugrep
		pkgs.findutils
		# Keep a host RUSTC_WRAPPER=sccache compatible with the Nix libraries.
		pkgs.sccache
	] ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.glibcLocales ];
}
