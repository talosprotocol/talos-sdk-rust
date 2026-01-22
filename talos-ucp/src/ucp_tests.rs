use crate::domain::ap2::Ap2MerchantAuthorization;
use crate::domain::headers::RequestHeaders;
use crate::domain::signer::{sign_body_detached, verify_body_detached};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::thread_rng;
use serde::Serialize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify_body() {
        let signing_key = SigningKey::random(&mut thread_rng());
        let verifying_key = VerifyingKey::from(&signing_key);
        let kid = "test-key-1";
        let body = b"{\"hello\":\"world\"}";

        let jws = sign_body_detached(&signing_key, kid, body).unwrap();

        // detached JWS Verify (split by '.')
        verify_body_detached(&verifying_key, body, &jws.replace("..", ".")).unwrap();

        // Negative: tampered body
        let err = verify_body_detached(&verifying_key, b"tampered", &jws.replace("..", "."));
        assert!(err.is_err());
    }

    #[test]
    fn test_ap2_verify() {
        let signing_key = SigningKey::random(&mut thread_rng());
        let verifying_key = VerifyingKey::from(&signing_key);

        #[derive(Serialize)]
        struct Payload {
            foo: String,
        }
        let payload = Payload {
            foo: "bar".to_string(),
        };

        let canonical = serde_jcs::to_vec(&payload).unwrap();
        let header = crate::domain::signer::JwsHeader {
            alg: "ES256".to_string(),
            kid: "key-1".to_string(),
            b64: true,
            crit: vec![],
        };
        let protected = base64_url::encode(&serde_json::to_string(&header).unwrap());
        let payload_b64 = base64_url::encode(&canonical);
        let signing_input = format!("{}.{}", protected, payload_b64);

        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64_url::encode(&signature.to_bytes());

        let jws = format!("{}..{}", protected, sig_b64);

        Ap2MerchantAuthorization::verify(&verifying_key, &payload, &jws).unwrap();
    }
}
