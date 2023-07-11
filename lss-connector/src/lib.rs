pub mod msgs;
mod signer;

pub use msgs::*;
pub use secp256k1;

pub use signer::{handle_lss_msg, LssSigner};

#[cfg(feature = "broker")]
mod broker;

#[cfg(feature = "broker")]
pub use broker::{lss_handle, tokio, LssBroker, LssPersister};

#[cfg(not(feature = "std"))]
mod not_entropy;
