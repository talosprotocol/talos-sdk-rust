use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct CreateCheckoutRequest {
    pub line_items: Vec<LineItem>,
}

#[derive(Serialize, Debug, Clone)]
pub struct LineItem {
    pub sku: String,
    pub quantity: u32,
}
