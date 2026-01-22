use crate::signer::{JwsHeader, SignerError};
use base64_url;
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use serde::Serialize;
use serde_jcs;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub struct Ap2MerchantAuthorization;

impl Ap2MerchantAuthorization {
    pub fn verify<T: Serialize>(
        verifying_key: &VerifyingKey,
        payload: &T,
        jws: &str,
    ) -> Result<(), SignerError> {
        // 1. Canonicalize payload using JCS
        let canonical =
            serde_jcs::to_vec(payload).map_err(|e| SignerError::Crypto(e.to_string()))?;

        // 2. Decode detached JWS (header..signature)
        let parts: Vec<&str> = jws.split("..").collect();
        if parts.len() != 2 {
            return Err(SignerError::InvalidFormat);
        }

        let protected_b64 = parts[0];
        let signature_b64 = parts[1];

        // 3. Reconstruct signing input: base64url(protected) + "." + base64url(canonical)
        // Note: For AP2, we use b64=true (default) JWS logic.
        let payload_b64 = base64_url::encode(&canonical);
        let signing_input = format!("{}.{}", protected_b64, payload_b64);

        let sig_bytes =
            base64_url::decode(signature_b64).map_err(|e| SignerError::Crypto(e.to_string()))?;
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|e| SignerError::Crypto(e.to_string()))?;

        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|e| SignerError::Crypto(e.to_string()))?;

        Ok(())
    }
}
