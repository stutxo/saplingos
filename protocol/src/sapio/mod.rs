//! Portable Sapio program identities and the client–enclave signing protocol.
//!
//! These types do not change captaind's policy or RPC encoding. The enclave
//! evaluates the exact program; Ark sees the ordinary joint client public key.

pub mod program;
pub mod protocol;
