{
	description = "Sapling client SDK";

	nixConfig = {
		extra-substituters = [ "https://bark.cachix.org" ];
		extra-trusted-public-keys = [ "bark.cachix.org-1:Iaihe4ABbOQz1CHBoYUZS/sHVAcISasJZ+lL3I4gRB0=" ];
	};

	inputs = {
		nixpkgs.url = "nixpkgs/nixos-26.05";
		flake-utils.url = "github:numtide/flake-utils";
		fenix = {
			url = "github:nix-community/fenix";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = { nixpkgs, flake-utils, fenix, ... }:
		flake-utils.lib.eachDefaultSystem (system:
			let
				pkgs = import nixpkgs { inherit system; };
				rustToolchain = fenix.packages.${system}.fromToolchainName {
					name = "1.90.0";
					sha256 = "sha256-SJwZ8g0zF2WrKDVmHrVG3pD2RGoQeo24MEXnNx5FyuI=";
				};
				buildShell = import ./nix/build-shell.nix {
					inherit pkgs rustToolchain;
					lib = pkgs.lib;
				};
			in {
				# Integration fixtures are external; neither shell builds server applications.
				devShells = {
					default = buildShell;
					build = buildShell;
				};
			}
		);
}
