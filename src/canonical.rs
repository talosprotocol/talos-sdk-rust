use serde::Serialize;
use talos_core_rs::canonical;

/// Canonicalize a value to RFC 8785 JSON string.
pub fn marshal<T: Serialize>(value: &T) -> Result<String, String> {
    canonical::canonical_json(value).map_err(|e| e.to_string())
}
