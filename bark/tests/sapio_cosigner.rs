#![cfg(not(target_arch = "wasm32"))]

use bark::Config;
use bitcoin::Network;

/// Legacy hints must not silently fall back to an unrestricted native key.
#[test]
fn legacy_cosigner_configuration_refuses_wallet_key_issuance() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("config.toml");
	for (field, value) in [
		("sapio_cosigner_pubkey", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
		("sapio_endpoint", "http://127.0.0.1:8000"),
		("sapio_program_id", "allow_self"),
	] {
		std::fs::write(&path, format!("{field} = \"{value}\"\n")).unwrap();
		assert!(Config::load(Network::Regtest, &path).is_err());
	}
}
