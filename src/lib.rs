pub mod a2a_v1;
pub mod canonical;
pub mod client;
pub mod identity;

pub use a2a_v1::{
    extension_uris, supported_interfaces, supports_extension, supports_talos_attestation,
    supports_talos_compat_jsonrpc, supports_talos_secure_channels, A2AError, A2AJsonRpcClient,
    A2AListTasksOptions, A2AMessageOptions, A2APushNotificationConfigOptions, A2ATaskOptions,
    TALOS_ATTESTATION_EXTENSION, TALOS_COMPAT_JSONRPC_EXTENSION, TALOS_SECURE_CHANNELS_EXTENSION,
};
pub use canonical::marshal as canonical_marshal;
pub use client::{GatewayClient, TalosError};
pub use identity::Identity;

pub const SDK_VERSION: &str = "1.0.0";
pub const SUPPORTED_PROTOCOL_RANGE: (&str, &str) = ("1.0", "1.x");
pub const CONTRACT_MANIFEST_HASH: &str = "3gi_Ti6G17oMQabjDlVUXcfBqOjN4HswNdD4Lu0uyyI";

/// Talos SDK Entry Point
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::{canonical_marshal, CONTRACT_MANIFEST_HASH, SDK_VERSION, SUPPORTED_PROTOCOL_RANGE};
    use base64_url::encode as encode_base64url;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    #[test]
    fn exports_pinned_sdk_version_metadata() {
        assert_eq!(SDK_VERSION, "1.0.0");
        assert_eq!(SUPPORTED_PROTOCOL_RANGE, ("1.0", "1.x"));
    }

    #[test]
    fn pins_the_canonical_contract_manifest_hash() {
        let manifest: Value = serde_json::from_str(include_str!(
            "../../../contracts/sdk/contract_manifest.json"
        ))
        .expect("contract manifest should parse");
        let canonical =
            canonical_marshal(&manifest).expect("contract manifest should canonicalize");
        let digest = Sha256::digest(canonical.as_bytes());
        let expected = encode_base64url(&digest);

        assert_eq!(CONTRACT_MANIFEST_HASH, expected);
        assert!(!CONTRACT_MANIFEST_HASH.contains(':'));
    }
}
