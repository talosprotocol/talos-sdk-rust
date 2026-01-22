use crate::domain::discovery::MerchantProfile;
use crate::ports::DiscoveryPort;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use std::time::Duration;

pub struct ReqwestDiscoveryAdapter {
    client: Client,
}

impl ReqwestDiscoveryAdapter {
    pub fn new() -> anyhow::Result<Self> {
        let client = Client::builder()
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .timeout(Duration::from_secs(10))
            .redirect(Policy::limited(1))
            .build()?;

        Ok(Self { client })
    }
}

impl DiscoveryPort for ReqwestDiscoveryAdapter {
    fn fetch_profile(&self, merchant_url: &str) -> anyhow::Result<MerchantProfile> {
        if !merchant_url.starts_with("https://") {
            return Err(anyhow::anyhow!("HTTPS required"));
        }

        let url = format!("{}/.well-known/ucp", merchant_url.trim_end_matches('/'));
        let resp = self.client.get(&url).send()?;

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "Discovery failed with status {}",
                resp.status()
            ));
        }

        let profile = resp.json::<MerchantProfile>()?;
        Ok(profile)
    }
}
