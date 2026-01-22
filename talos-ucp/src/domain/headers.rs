use crate::sfv::{encode_dict, Dict, Item, Value};
use std::collections::HashMap;

pub struct RequestHeaders {
    pub request_id: String,
    pub idempotency_key: Option<String>,
    pub signature: Option<String>,
    pub agent_profile: String,
}

impl RequestHeaders {
    pub fn encode_agent_header(&self) -> Result<String, crate::sfv::SfvError> {
        let mut d = Dict::new();
        d.insert(
            "profile".to_string(),
            Item {
                value: Value::String(self.agent_profile.clone()),
                params: HashMap::new(),
            },
        );
        encode_dict(&d)
    }

    pub fn to_map(&self) -> Result<HashMap<String, String>, crate::sfv::SfvError> {
        let mut m = HashMap::new();
        m.insert("Request-Id".to_string(), self.request_id.clone());
        if let Some(key) = &self.idempotency_key {
            m.insert("Idempotency-Key".to_string(), key.clone());
        }
        if let Some(sig) = &self.signature {
            m.insert("Request-Signature".to_string(), sig.clone());
        }
        m.insert("UCP-Agent".to_string(), self.encode_agent_header()?);
        Ok(m)
    }
}
