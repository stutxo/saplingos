//! Opt-in SDK regression support. Server processes and their fixtures are upstream.
#![cfg(feature = "integration")]

pub mod balance;
pub mod context;
pub mod daemon;

pub use context::TestContext;
pub use ark_testing::{btc, sat, secs, signed_btc, signed_sat, Lightningd};
pub use ark_testing::constants;

pub mod util {
	pub use ark_testing::util::{FutureExt, ToAltString, poll_interval};

	/// Match the SDK executor's debug-only reentrancy mode.
	pub fn action_drive_factor() -> usize {
		if std::env::var_os("SAPLING_DOUBLE_DRIVE_ACTIONS").is_some() { 2 } else { 1 }
	}
}
