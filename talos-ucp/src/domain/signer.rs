use base64_url;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignerError {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("invalid JWS format")]
    InvalidFormat,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JwsHeader {
    pub alg: String,
    pub kid: String,
    pub b64: bool,
    pub crit: Vec<String>,
}

pub struct HttpBodySigner {
    pub signing_key: SigningKey,
    pub kid: String,
}

impl HttpBodySigner {
    pub fn new(signing_key: SigningKey, kid: String) -> Self {
        Self { signing_key, kid }
    }

    pub fn sign_body(&self, body: &[u8]) -> Result<String, SignerError> {
        sign_body_detached(&self.signing_key, &self.kid, body)
    }
}

pub fn sign_body_detached(
    signing_key: &SigningKey,
    kid: &str,
    body: &[u8],
) -> Result<String, SignerError> {
    let header = JwsHeader {
        alg: "ES256".to_string(),
        kid: kid.to_string(),
        b64: false,
        crit: vec!["b64".to_string()],
    };

    let header_json = serde_json::to_string(&header)?;
    let protected = base64_url::encode(&header_json);

    // Signing input for RFC 7797 b64=false: BASE64URL(UTF8(protected)) + "." + payload
    let mut signing_input = protected.as_bytes().to_vec();
    signing_input.push(b'.');
    signing_input.extend_from_slice(body);

    let signature: Signature = signing_key.sign(&signing_input);
    let sig_bytes = signature.to_bytes();
    let sig_b64 = base64_url::encode(&sig_bytes);

    Ok(format!("{}..{}", protected, sig_b64))
}

pub fn verify_body_detached(
    verifying_key: &VerifyingKey,
    body: &[u8],
    jws: &str,
) -> Result<(), SignerError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(SignerError::InvalidFormat);
    }

    let protected_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    if !payload_b64.is_empty() {
        return Err(SignerError::InvalidFormat);
    }

    let header_json =
        base64_url::decode(protected_b64).map_err(|e| SignerError::Crypto(e.to_string()))?;
    let header: JwsHeader = serde_json::from_slice(&header_json)?;

    if header.alg != "ES256" {
        return Err(SignerError::Crypto("unsupported algorithm".to_string()));
    }
    if !header.b64 && (header.crit.is_empty() || header.crit[0] != "b64") {
        return Err(SignerError::Crypto("invalid crit/b64".to_string()));
    }

    let mut signing_input = protected_b64.as_bytes().to_vec();
    signing_input.push(b'.');
    signing_input.extend_from_slice(body);

    let sig_bytes =
        base64_url::decode(signature_b64).map_err(|e| SignerError::Crypto(e.to_string()))?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| SignerError::Crypto(e.to_string()))?;

    verifying_key
        .verify(&signing_input, &signature)
        .map_err(|e| SignerError::Crypto(e.to_string()))?;

    Ok(())
}
