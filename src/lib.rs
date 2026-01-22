pub mod canonical;
pub mod client;
pub mod identity;

pub use canonical::marshal as canonical_marshal;
pub use client::{GatewayClient, TalosError};
pub use identity::Identity;

/// Talos SDK Entry Point
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
