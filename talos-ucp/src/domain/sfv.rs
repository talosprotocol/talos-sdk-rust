use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SfvError {
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("unsupported value type")]
    UnsupportedValue,
    #[error("invalid character: {0}")]
    InvalidChar(char),
}

pub type Dict = HashMap<String, Item>;

#[derive(Debug, Clone)]
pub struct Item {
    pub value: Value,
    pub params: HashMap<String, Value>,
}

#[derive(Debug, Clone)]
pub enum Value {
    String(String),
    Boolean(bool),
    Integer(i64),
}

pub fn encode_dict(d: &Dict) -> Result<String, SfvError> {
    let mut parts = Vec::new();

    // For stability in tests, we should sort keys, but standard SFV doesn't require it.
    let mut keys: Vec<_> = d.keys().collect();
    keys.sort();

    for key in keys {
        validate_key(key)?;
        let item = &d[key];
        let mut s = key.clone();

        match &item.value {
            Value::Boolean(true) => {} // skip
            _ => {
                s.push('=');
                s.push_str(&encode_value(&item.value)?);
            }
        }

        let mut p_keys: Vec<_> = item.params.keys().collect();
        p_keys.sort();

        for p_key in p_keys {
            validate_key(p_key)?;
            s.push(';');
            s.push_str(p_key);
            match &item.params[p_key] {
                Value::Boolean(true) => {} // skip
                p_val => {
                    s.push('=');
                    s.push_str(&encode_value(p_val)?);
                }
            }
        }
        parts.push(s);
    }

    Ok(parts.join(", "))
}

fn validate_key(key: &str) -> Result<(), SfvError> {
    if key.is_empty() {
        return Err(SfvError::InvalidKey(key.to_string()));
    }
    let first = key.chars().next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(SfvError::InvalidKey(key.to_string()));
    }
    for c in key.chars() {
        if !(c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '_'
            || c == '-'
            || c == '.'
            || c == '*')
        {
            return Err(SfvError::InvalidKey(key.to_string()));
        }
    }
    Ok(())
}

fn encode_value(v: &Value) -> Result<String, SfvError> {
    match v {
        Value::String(s) => {
            let mut out = String::from("\"");
            for c in s.chars() {
                if c == '"' || c == '\\' {
                    out.push('\\');
                }
                if !(0x20..=0x7E).contains(&(c as u32)) {
                    return Err(SfvError::InvalidChar(c));
                }
                out.push(c);
            }
            out.push('"');
            Ok(out)
        }
        Value::Boolean(b) => Ok(if *b {
            "?1".to_string()
        } else {
            "?0".to_string()
        }),
        Value::Integer(i) => Ok(i.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_dict() {
        let mut d = Dict::new();
        d.insert(
            "profile".to_string(),
            Item {
                value: Value::String("https://example.com".to_string()),
                params: HashMap::new(),
            },
        );

        let got = encode_dict(&d).unwrap();
        assert_eq!(got, "profile=\"https://example.com\"");
    }
}
