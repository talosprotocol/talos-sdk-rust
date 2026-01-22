use crate::domain::discovery::VersionInfo;
use crate::domain::signer::SignerError;
use base64_url;
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlatformProfile {
    pub ucp: VersionInfo,
    pub signing_keys: Vec<Jwk>,
    pub services: PlatformServices,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlatformServices {
    #[serde(rename = "dev.ucp.platform")]
    pub platform: PlatformService,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlatformService {
    pub profile: PlatformProfileEndpoint,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlatformProfileEndpoint {
    pub url: String,
}

pub struct PlatformProfileBuilder {
    pub profile_url: String,
    pub signing_keys: Vec<(String, VerifyingKey)>,
}

impl PlatformProfileBuilder {
    pub fn build(&self) -> Result<PlatformProfile, SignerError> {
        let mut keys = Vec::new();
        for (kid, key) in &self.signing_keys {
            let point = key.to_encoded_point(false);
            let x = base64_url::encode(point.x().unwrap());
            let y = base64_url::encode(point.y().unwrap());

            keys.push(Jwk {
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x,
                y,
                kid: kid.clone(),
                r#use: Some("sig".to_string()),
                alg: Some("ES256".to_string()),
            });
        }

        Ok(PlatformProfile {
            ucp: VersionInfo {
                version: "2026-01-11".to_string(),
            },
            signing_keys: keys,
            services: PlatformServices {
                platform: PlatformService {
                    profile: PlatformProfileEndpoint {
                        url: self.profile_url.clone(),
                    },
                },
            },
        })
    }
}
