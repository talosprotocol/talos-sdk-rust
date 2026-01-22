use crate::domain::discovery::MerchantProfile;
use crate::domain::shopping::CreateCheckoutRequest;
use anyhow::Result;

pub trait DiscoveryPort {
    fn fetch_profile(&self, merchant_url: &str) -> Result<MerchantProfile>;
}

pub trait ShoppingPort {
    fn create_checkout(
        &self,
        merchant_url: &str,
        req: &CreateCheckoutRequest,
    ) -> Result<serde_json::Value>;
}
