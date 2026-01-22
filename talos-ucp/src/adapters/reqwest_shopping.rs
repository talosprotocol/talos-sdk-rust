use crate::domain::headers::RequestHeaders;
use crate::domain::profile::PlatformProfile;
use crate::domain::shopping::CreateCheckoutRequest;
use crate::domain::signer::sign_body_detached;
use crate::ports::ShoppingPort;
use anyhow::Result;
use uuid::Uuid;

pub struct ReqwestShoppingAdapter {
    pub signer_key: p256::ecdsa::SigningKey,
    pub signer_kid: String,
    pub platform: PlatformProfile,
}

impl ShoppingPort for ReqwestShoppingAdapter {
    fn create_checkout(
        &self,
        merchant_url: &str,
        req: &CreateCheckoutRequest,
    ) -> Result<serde_json::Value> {
        let body_json = serde_json::to_vec(req)?;
        let signature = sign_body_detached(&self.signer_key, &self.signer_kid, &body_json)
            .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;

        let headers = RequestHeaders {
            request_id: Uuid::now_v7().to_string(),
            idempotency_key: Some(Uuid::now_v7().to_string()),
            signature: Some(signature),
            agent_profile: self.platform.services.platform.profile.url.clone(),
        };

        let header_map = headers
            .to_map()
            .map_err(|e| anyhow::anyhow!("SFV error: {}", e))?;

        // Use blocking client for now to match SDK pattern
        let client = reqwest::blocking::Client::new();
        let mut request = client
            .post(format!(
                "{}/checkout-sessions",
                merchant_url.trim_end_matches('/')
            ))
            .json(req);

        for (k, v) in header_map {
            request = request.header(k, v);
        }

        let resp = request.send()?;

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("Request failed: {}", resp.status()));
        }

        let json = resp.json::<serde_json::Value>()?;
        Ok(json)
    }
}
