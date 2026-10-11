//! Integration tests of the Sapling SDK, with external upstream service fixtures.
//! Enable `integration` through `just int`; `just int-sapio` additionally requires
//! the real Sapio TEE and evaluator artifacts. No wallet CLI binary is used.

mod arkoor;
mod balance;
mod exit;
mod import;
mod lightning;
mod mailbox;
mod offboard;
mod payment_request;
mod recovery;
mod round;
#[cfg(feature = "sapio-integration")]
mod sapio;
mod vtxo_lock;
