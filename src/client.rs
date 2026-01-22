use serde::Deserialize;
use std::time::Duration;
use reqwest::Client;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TalosError {
    #[error("API Error {code}: {message} (request_id: {request_id})")]
    Api {
        code: u16,
        message: String,
        request_id: String,
    },
    #[error("Network Error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Serialization Error: {0}")]
    Serialization(String),
}

#[derive(Deserialize)]
struct ErrorResponse {
    code: u16,
    message: String,
    request_id: Option<String>,
}

pub struct GatewayClient {
    base_url: String,
    http: Client,
}

impl GatewayClient {
    pub fn new(base_url: String) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();
            
        Self { base_url, http }
    }

    pub async fn get_resource(&self, path: &str) -> Result<String, TalosError> {
        let url = format!("{}/{}", self.base_url, path);
        let resp = self.http.get(&url).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let headers = resp.headers().clone();
            
            // Try to parse structured error
            let error_body = resp.json::<ErrorResponse>().await;
            
            return match error_body {
                Ok(err) => Err(TalosError::Api {
                    code: err.code,
                    message: err.message,
                    request_id: err.request_id.unwrap_or_else(|| {
                        headers.get("x-request-id")
                            .and_then(|h| h.to_str().ok())
                            .unwrap_or("unknown")
                            .to_string()
                    }),
                }),
                Err(_) => Err(TalosError::Api {
                    code: status.as_u16(),
                    message: "Unknown/Unparseable Error".to_string(),
                    request_id: "unknown".to_string(),
                }),
            };
        }

        resp.text().await.map_err(TalosError::from)
    }
}

