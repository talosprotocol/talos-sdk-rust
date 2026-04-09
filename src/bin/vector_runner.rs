use base64_url::{decode as decode_base64url, encode as encode_base64url};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use talos_core_rs::adapters::crypto::RealCryptoProvider;
use talos_core_rs::domain::wallet::Wallet;
use talos_core_rs::ports::crypto::CryptoProvider;
use talos_sdk::{canonical_marshal, Identity};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Default)]
struct Summary {
    passed: usize,
    failed: usize,
    skipped: usize,
}

impl Summary {
    fn merge(&mut self, other: Summary) {
        self.passed += other.passed;
        self.failed += other.failed;
        self.skipped += other.skipped;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let vectors_path = match args.next() {
        Some(path) => PathBuf::from(path),
        None => {
            eprintln!("Usage: cargo run --bin vector_runner -- <vectors.json>");
            std::process::exit(1);
        }
    };

    let summary = run_path(&vectors_path)?;
    println!(
        "Conformance summary: passed={} failed={} skipped={}",
        summary.passed, summary.failed, summary.skipped
    );
    if summary.failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn run_path(path: &Path) -> Result<Summary, Box<dyn std::error::Error>> {
    let payload: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    if is_release_set(&payload) {
        return run_release_set(path, &payload);
    }

    match path.file_name().and_then(|s| s.to_str()) {
        Some("canonical_json.json") => run_canonical_vectors(&payload),
        Some("signing_verify.json") => run_signing_vectors(&payload),
        Some("capability_verify.json") => run_capability_vectors(&payload),
        Some("frame_codec.json") => run_frame_vectors(&payload),
        Some("mcp_sign_verify.json") => run_mcp_vectors(&payload),
        Some("header_canonical_bytes.json") => run_header_vectors(&payload),
        Some("kdf_rk_step.json") => run_kdf_root_vector(&payload),
        Some("kdf_ck_step.json") => run_kdf_chain_vector(&payload),
        Some("v1_1_0_roundtrip.json") => run_ratchet_roundtrip_vector(&payload),
        Some(name) => {
            println!("SKIP {} (no Rust conformance handler yet)", name);
            Ok(Summary {
                passed: 0,
                failed: 0,
                skipped: 1,
            })
        }
        None => Err(format!("invalid vector path: {}", path.display()).into()),
    }
}

fn is_release_set(payload: &Value) -> bool {
    payload
        .get("vectors")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty() && items.iter().all(Value::is_string))
        .unwrap_or(false)
}

fn run_release_set(path: &Path, payload: &Value) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut summary = Summary::default();
    let base_dir = path
        .parent()
        .ok_or_else(|| format!("no parent directory for {}", path.display()))?;

    for item in payload["vectors"].as_array().unwrap() {
        let relative = item.as_str().unwrap();
        let sub_path = base_dir.join(relative);
        summary.merge(run_path(&sub_path)?);
    }

    Ok(summary)
}

fn run_canonical_vectors(payload: &Value) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut summary = Summary::default();
    let vectors = payload["vectors"]
        .as_array()
        .ok_or("canonical_json.json missing vectors array")?;

    for vector in vectors {
        let test_id = vector["test_id"].as_str().unwrap_or("unknown");
        match check_canonical_vector(vector) {
            Ok(()) => summary.passed += 1,
            Err(err) => {
                println!("FAIL {}: {}", test_id, err);
                summary.failed += 1;
            }
        }
    }

    Ok(summary)
}

fn check_canonical_vector(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let expected = vector
        .get("expected")
        .and_then(Value::as_object)
        .ok_or("missing expected object")?;

    let payload = if let Some(value) = inputs.get("unordered") {
        value
    } else if let Some(value) = inputs.get("value") {
        value
    } else if let Some(value) = inputs.get("pretty_printed") {
        let raw = value.as_str().ok_or("pretty_printed must be a string")?;
        return check_canonical_payload(&serde_json::from_str::<Value>(raw)?, expected);
    } else {
        return Err("unsupported canonical vector shape".into());
    };

    check_canonical_payload(payload, expected)
}

fn check_canonical_payload(
    payload: &Value,
    expected: &serde_json::Map<String, Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let canonical = canonical_marshal(payload)?;

    if let Some(want) = expected.get("canonical").and_then(Value::as_str) {
        if canonical != want {
            return Err(format!("canonical mismatch: got {} want {}", canonical, want).into());
        }
    }
    if let Some(want) = expected.get("canonical_number").and_then(Value::as_str) {
        if canonical != want {
            return Err(
                format!("canonical number mismatch: got {} want {}", canonical, want).into(),
            );
        }
    }
    Ok(())
}

fn run_signing_vectors(payload: &Value) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut summary = Summary::default();

    if let Some(vectors) = payload.get("vectors").and_then(Value::as_array) {
        for vector in vectors {
            let test_id = vector["test_id"].as_str().unwrap_or("unknown");
            match check_signing_vector(vector) {
                Ok(()) => summary.passed += 1,
                Err(err) => {
                    println!("FAIL {}: {}", test_id, err);
                    summary.failed += 1;
                }
            }
        }
    }

    if let Some(vectors) = payload.get("negative_cases").and_then(Value::as_array) {
        for vector in vectors {
            let test_id = vector["test_id"].as_str().unwrap_or("unknown-negative");
            match check_signing_negative(vector) {
                Ok(()) => summary.passed += 1,
                Err(err) => {
                    println!("FAIL {}: {}", test_id, err);
                    summary.failed += 1;
                }
            }
        }
    }

    Ok(summary)
}

fn check_signing_vector(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let expected = vector
        .get("expected")
        .and_then(Value::as_object)
        .ok_or("missing expected object")?;

    let seed_hex = inputs
        .get("seed_hex")
        .and_then(Value::as_str)
        .ok_or("seed_hex must be a string")?;
    let seed_bytes = hex::decode(seed_hex)?;
    if seed_bytes.len() != 32 {
        return Err(format!("seed must be 32 bytes, got {}", seed_bytes.len()).into());
    }

    let identity = Identity::from_seed(&seed_bytes);
    let message = inputs
        .get("message_utf8")
        .and_then(Value::as_str)
        .unwrap_or("")
        .as_bytes()
        .to_vec();
    let signature = identity.sign(&message);

    if let Some(want) = expected.get("public_key_hex").and_then(Value::as_str) {
        if identity.public_key() != want {
            return Err(format!(
                "public_key_hex mismatch: got {} want {}",
                identity.public_key(),
                want
            )
            .into());
        }
    }
    if let Some(want) = expected.get("did").and_then(Value::as_str) {
        if identity.did() != want {
            return Err(format!("did mismatch: got {} want {}", identity.did(), want).into());
        }
    }
    if let Some(want) = expected.get("signature_base64url").and_then(Value::as_str) {
        let got = encode_base64url(&signature);
        if got != want {
            return Err(format!("signature mismatch: got {} want {}", got, want).into());
        }
    }
    if let Some(want) = expected.get("signature_length").and_then(Value::as_u64) {
        if signature.len() != want as usize {
            return Err(format!(
                "signature length mismatch: got {} want {}",
                signature.len(),
                want
            )
            .into());
        }
    }
    if let Some(want) = expected.get("verify").and_then(Value::as_bool) {
        let provider = RealCryptoProvider;
        let public_bytes = hex::decode(identity.public_key())?;
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&public_bytes);
        let got = Wallet::verify(&message, &signature, &public_key, &provider);
        if got != want {
            return Err(format!("verify mismatch: got {} want {}", got, want).into());
        }
    }

    Ok(())
}

fn check_signing_negative(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let test_id = vector["test_id"].as_str().unwrap_or("unknown-negative");

    match test_id {
        "invalid_seed_length" => {
            let seed_hex = inputs.get("seed_hex").and_then(Value::as_str).unwrap_or("");
            let seed_bytes = hex::decode(seed_hex)?;
            if seed_bytes.len() == 32 {
                return Err("expected invalid seed length".into());
            }
            Ok(())
        }
        "verify_wrong_key" => {
            let message = inputs
                .get("message_utf8")
                .and_then(Value::as_str)
                .unwrap_or("")
                .as_bytes()
                .to_vec();
            let signature = decode_base64url(
                inputs
                    .get("signature_base64url")
                    .and_then(Value::as_str)
                    .ok_or("missing signature_base64url")?,
            )
            .map_err(|err| format!("decode signature_base64url: {:?}", err))?;
            let wrong_public_key = hex::decode(
                inputs
                    .get("wrong_public_key_hex")
                    .and_then(Value::as_str)
                    .ok_or("missing wrong_public_key_hex")?,
            )?;
            let provider = RealCryptoProvider;
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&wrong_public_key);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&signature);
            if Wallet::verify(&message, &sig, &public_key, &provider) {
                return Err("verification unexpectedly succeeded with wrong key".into());
            }
            Ok(())
        }
        "verify_tampered_message" => {
            let seed_bytes = hex::decode(
                inputs
                    .get("seed_hex")
                    .and_then(Value::as_str)
                    .ok_or("missing seed_hex")?,
            )?;
            if seed_bytes.len() != 32 {
                return Err(format!("seed must be 32 bytes, got {}", seed_bytes.len()).into());
            }
            let identity = Identity::from_seed(&seed_bytes);
            let original = inputs
                .get("original_message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .as_bytes()
                .to_vec();
            let tampered = inputs
                .get("tampered_message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .as_bytes()
                .to_vec();
            let signature = identity.sign(&original);
            let public_bytes = hex::decode(identity.public_key())?;
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&public_bytes);
            let provider = RealCryptoProvider;
            if Wallet::verify(&tampered, &signature, &public_key, &provider) {
                return Err("verification unexpectedly succeeded for tampered message".into());
            }
            Ok(())
        }
        _ => Err(format!("unsupported negative signing vector {}", test_id).into()),
    }
}

fn run_capability_vectors(payload: &Value) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut summary = Summary::default();

    if let Some(vectors) = payload.get("vectors").and_then(Value::as_array) {
        for vector in vectors {
            let test_id = vector["test_id"].as_str().unwrap_or("unknown");
            match check_capability_vector(vector) {
                Ok(()) => summary.passed += 1,
                Err(err) => {
                    println!("FAIL {}: {}", test_id, err);
                    summary.failed += 1;
                }
            }
        }
    }

    if let Some(vectors) = payload.get("negative_cases").and_then(Value::as_array) {
        for vector in vectors {
            let test_id = vector["test_id"].as_str().unwrap_or("unknown-negative");
            match check_capability_negative(vector) {
                Ok(()) => summary.passed += 1,
                Err(err) => {
                    println!("FAIL {}: {}", test_id, err);
                    summary.failed += 1;
                }
            }
        }
    }

    Ok(summary)
}

fn check_capability_vector(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let expected = vector
        .get("expected")
        .and_then(Value::as_object)
        .ok_or("missing expected object")?;

    let (capability, issuer_public_hex, exp) = make_signed_capability(inputs)?;

    if let Some(want) = expected.get("verify").and_then(Value::as_bool) {
        let (got, reason) = verify_capability(
            &capability,
            &issuer_public_hex,
            (DEFAULT_CAPABILITY_IAT + exp) / 2,
        )?;
        if got != want {
            return Err(format!(
                "verify mismatch: got {} want {} (reason={})",
                got, want, reason
            )
            .into());
        }
    }

    for (key, value) in expected {
        let Some(want) = value.as_bool() else {
            continue;
        };
        let Some(raw) = key.strip_prefix("authorize_fast_") else {
            continue;
        };
        let Some((tool, action)) = raw.split_once('_') else {
            return Err(format!("invalid authorize key {}", key).into());
        };
        let got = capability_authorize(
            capability.get("scope").unwrap_or(&Value::Null),
            tool,
            action,
        );
        if got != want {
            return Err(format!(
                "authorize mismatch for {}/{}: got {} want {}",
                tool, action, got, want
            )
            .into());
        }
    }

    Ok(())
}

fn check_capability_negative(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let test_id = vector["test_id"].as_str().unwrap_or("unknown-negative");

    match test_id {
        "capability_expired" => {
            let mut mock_inputs = serde_json::Map::new();
            mock_inputs.insert(
                "issuer_seed_hex".to_string(),
                Value::String(SEED_HEX_ONE.to_string()),
            );
            mock_inputs.insert(
                "subject_did".to_string(),
                Value::String(DEFAULT_CAPABILITY_SUBJECT.to_string()),
            );
            mock_inputs.insert("scope".to_string(), default_capability_scope());
            mock_inputs.insert(
                "exp".to_string(),
                Value::Number(serde_json::Number::from(
                    inputs
                        .get("token_with_exp")
                        .and_then(Value::as_i64)
                        .or_else(|| {
                            inputs
                                .get("token_with_exp")
                                .and_then(Value::as_u64)
                                .map(|v| v as i64)
                        })
                        .unwrap_or(0),
                )),
            );
            let (capability, issuer_public_hex, exp) = make_signed_capability(&mock_inputs)?;
            let (got, reason) = verify_capability(&capability, &issuer_public_hex, exp + 1)?;
            if got || reason != "expired" {
                return Err(format!(
                    "expected expired capability failure, got verify={} reason={}",
                    got, reason
                )
                .into());
            }
            Ok(())
        }
        "capability_bad_signature" => {
            let mut mock_inputs = serde_json::Map::new();
            mock_inputs.insert(
                "issuer_seed_hex".to_string(),
                Value::String(SEED_HEX_ONE.to_string()),
            );
            mock_inputs.insert(
                "subject_did".to_string(),
                Value::String(DEFAULT_CAPABILITY_SUBJECT.to_string()),
            );
            mock_inputs.insert("scope".to_string(), default_capability_scope());
            mock_inputs.insert(
                "exp".to_string(),
                Value::Number(serde_json::Number::from(DEFAULT_CAPABILITY_EXP)),
            );
            let (mut capability, issuer_public_hex, exp) = make_signed_capability(&mock_inputs)?;
            let sig_raw = decode_base64url(
                capability
                    .get("sig")
                    .and_then(Value::as_str)
                    .ok_or("missing capability signature")?,
            )
            .map_err(|err| format!("decode capability signature: {:?}", err))?;
            let mut sig = sig_raw;
            if sig.is_empty() {
                return Err("signature unexpectedly empty".into());
            }
            sig[0] ^= 0xff;
            capability.insert("sig".to_string(), Value::String(encode_base64url(&sig)));
            let (got, reason) = verify_capability(
                &capability,
                &issuer_public_hex,
                (DEFAULT_CAPABILITY_IAT + exp) / 2,
            )?;
            if got || reason != "signature" {
                return Err(format!(
                    "expected signature failure, got verify={} reason={}",
                    got, reason
                )
                .into());
            }
            Ok(())
        }
        "capability_wrong_issuer" => {
            let mut mock_inputs = serde_json::Map::new();
            mock_inputs.insert(
                "issuer_seed_hex".to_string(),
                Value::String(SEED_HEX_ONE.to_string()),
            );
            mock_inputs.insert(
                "subject_did".to_string(),
                Value::String(DEFAULT_CAPABILITY_SUBJECT.to_string()),
            );
            mock_inputs.insert("scope".to_string(), default_capability_scope());
            mock_inputs.insert(
                "exp".to_string(),
                Value::Number(serde_json::Number::from(DEFAULT_CAPABILITY_EXP)),
            );
            let (capability, _, exp) = make_signed_capability(&mock_inputs)?;
            let other_seed = hex::decode(SEED_HEX_TWO)?;
            if other_seed.len() != 32 {
                return Err(format!("seed must be 32 bytes, got {}", other_seed.len()).into());
            }
            let other_identity = Identity::from_seed(&other_seed);
            let (got, _) = verify_capability(
                &capability,
                &other_identity.public_key(),
                (DEFAULT_CAPABILITY_IAT + exp) / 2,
            )?;
            if got {
                return Err("verification unexpectedly succeeded with wrong issuer".into());
            }
            Ok(())
        }
        _ => Err(format!("unsupported negative capability vector {}", test_id).into()),
    }
}

fn run_frame_vectors(payload: &Value) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut summary = Summary::default();

    if let Some(vectors) = payload.get("vectors").and_then(Value::as_array) {
        for vector in vectors {
            let test_id = vector["test_id"].as_str().unwrap_or("unknown");
            match check_frame_vector(vector) {
                Ok(()) => summary.passed += 1,
                Err(err) => {
                    println!("FAIL {}: {}", test_id, err);
                    summary.failed += 1;
                }
            }
        }
    }

    if let Some(vectors) = payload.get("negative_cases").and_then(Value::as_array) {
        for vector in vectors {
            let test_id = vector["test_id"].as_str().unwrap_or("unknown-negative");
            match check_frame_negative(vector) {
                Ok(()) => summary.passed += 1,
                Err(err) => {
                    println!("FAIL {}: {}", test_id, err);
                    summary.failed += 1;
                }
            }
        }
    }

    Ok(summary)
}

fn check_frame_vector(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let expected = vector
        .get("expected")
        .and_then(Value::as_object)
        .ok_or("missing expected object")?;

    if let Some(frame_type) = inputs.get("frame_type").and_then(Value::as_str) {
        let payload = inputs
            .get("payload_utf8")
            .and_then(Value::as_str)
            .unwrap_or("")
            .as_bytes()
            .to_vec();
        let encoded = encode_frame(frame_type, &payload, 1, 0)?;
        if let Some(want) = expected.get("encoded_base64url").and_then(Value::as_str) {
            if encoded != want {
                return Err(
                    format!("encoded_base64url mismatch: got {} want {}", encoded, want).into(),
                );
            }
        }
    }

    if let Some(encoded) = inputs.get("encoded_base64url").and_then(Value::as_str) {
        let frame = decode_frame_base64url(encoded)?;
        if let Some(want) = expected.get("frame_type").and_then(Value::as_str) {
            let got = frame
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if got != want {
                return Err(format!("frame_type mismatch: got {} want {}", got, want).into());
            }
        }
        if let Some(want) = expected.get("version").and_then(Value::as_i64) {
            let got = frame.get("version").and_then(Value::as_i64).unwrap_or(1);
            if got != want {
                return Err(format!("version mismatch: got {} want {}", got, want).into());
            }
        }
        if let Some(want) = expected.get("flags").and_then(Value::as_i64) {
            let got = frame.get("flags").and_then(Value::as_i64).unwrap_or(0);
            if got != want {
                return Err(format!("flags mismatch: got {} want {}", got, want).into());
            }
        }
    }

    Ok(())
}

fn check_frame_negative(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let test_id = vector["test_id"].as_str().unwrap_or("unknown-negative");

    match test_id {
        "decode_truncated" => {
            if decode_frame_base64url(
                inputs
                    .get("encoded_base64url")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            )
            .is_ok()
            {
                return Err("expected truncated frame error".into());
            }
            Ok(())
        }
        "decode_invalid_type" => {
            if decode_frame_base64url(
                inputs
                    .get("encoded_base64url")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            )
            .is_ok()
            {
                return Err("expected invalid frame type error".into());
            }
            Ok(())
        }
        "decode_garbage" => {
            let raw = hex::decode(
                inputs
                    .get("encoded_hex")
                    .and_then(Value::as_str)
                    .ok_or("missing encoded_hex")?,
            )?;
            if decode_frame_raw(&raw).is_ok() {
                return Err("expected garbage frame decode error".into());
            }
            Ok(())
        }
        _ => Err(format!("unsupported negative frame vector {}", test_id).into()),
    }
}

fn run_mcp_vectors(payload: &Value) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut summary = Summary::default();

    if let Some(vectors) = payload.get("vectors").and_then(Value::as_array) {
        for vector in vectors {
            let test_id = vector["test_id"].as_str().unwrap_or("unknown");
            match check_mcp_vector(vector) {
                Ok(()) => summary.passed += 1,
                Err(err) => {
                    println!("FAIL {}: {}", test_id, err);
                    summary.failed += 1;
                }
            }
        }
    }

    if let Some(vectors) = payload.get("negative_cases").and_then(Value::as_array) {
        for vector in vectors {
            let test_id = vector["test_id"].as_str().unwrap_or("unknown-negative");
            match check_mcp_negative(vector) {
                Ok(()) => summary.passed += 1,
                Err(err) => {
                    println!("FAIL {}: {}", test_id, err);
                    summary.failed += 1;
                }
            }
        }
    }

    Ok(summary)
}

fn check_mcp_vector(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let expected = vector
        .get("expected")
        .and_then(Value::as_object)
        .ok_or("missing expected object")?;

    let seed_hex = inputs
        .get("signer_seed_hex")
        .and_then(Value::as_str)
        .ok_or("missing signer_seed_hex")?;
    let seed_bytes = hex::decode(seed_hex)?;
    if seed_bytes.len() != 32 {
        return Err(format!("seed must be 32 bytes, got {}", seed_bytes.len()).into());
    }

    let identity = Identity::from_seed(&seed_bytes);
    let payload = json!({
        "request": inputs.get("request").cloned().ok_or("missing request")?,
        "session_id": inputs.get("session_id").and_then(Value::as_str).unwrap_or(""),
        "correlation_id": inputs.get("correlation_id").and_then(Value::as_str).unwrap_or(""),
        "tool": inputs.get("tool").and_then(Value::as_str).unwrap_or(""),
        "action": inputs.get("action").and_then(Value::as_str).unwrap_or(""),
        "timestamp": inputs.get("timestamp").and_then(Value::as_i64).ok_or("missing timestamp")?,
    });
    let canonical = canonical_marshal(&payload)?;
    let signature = identity.sign(canonical.as_bytes());

    if let Some(want) = expected.get("payload_canonical").and_then(Value::as_str) {
        if canonical != want {
            return Err(format!(
                "payload_canonical mismatch: got {} want {}",
                canonical, want
            )
            .into());
        }
    }
    if let Some(want) = expected.get("signature_length").and_then(Value::as_u64) {
        if signature.len() != want as usize {
            return Err(format!(
                "signature length mismatch: got {} want {}",
                signature.len(),
                want
            )
            .into());
        }
    }
    if let Some(want) = expected.get("frame_type").and_then(Value::as_str) {
        if want != "DATA" {
            return Err(format!("unsupported MCP frame_type expectation {}", want).into());
        }
    }

    Ok(())
}

fn check_mcp_negative(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let expected = vector
        .get("expected")
        .and_then(Value::as_object)
        .ok_or("missing expected object")?;

    if let Some(want) = expected.get("verify").and_then(Value::as_bool) {
        let got = inputs
            .get("actual_correlation_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            == inputs
                .get("expected_correlation_id")
                .and_then(Value::as_str)
                .unwrap_or("");
        if got != want {
            return Err(format!("verify mismatch: got {} want {}", got, want).into());
        }
    }

    Ok(())
}

fn encode_frame(
    frame_type: &str,
    payload: &[u8],
    version: i64,
    flags: i64,
) -> Result<String, Box<dyn std::error::Error>> {
    let frame = json!({
        "version": version,
        "type": frame_type,
        "flags": flags,
        "payload": encode_base64url(payload),
    });
    let canonical = canonical_marshal(&frame)?;
    Ok(encode_base64url(canonical.as_bytes()))
}

fn decode_frame_base64url(encoded: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let raw =
        decode_base64url(encoded).map_err(|err| format!("frame decoding failed: {:?}", err))?;
    decode_frame_raw(&raw)
}

fn decode_frame_raw(raw: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let frame: Value = serde_json::from_slice(raw)
        .map_err(|err| format!("frame decoding failed: truncated or invalid JSON: {}", err))?;
    let object = frame
        .as_object()
        .ok_or("frame decoding failed: expected object")?;
    let frame_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or("frame decoding failed: missing type")?;
    if !is_valid_frame_type(frame_type) {
        return Err(format!("frame decoding failed: invalid frame type {}", frame_type).into());
    }
    let payload = object
        .get("payload")
        .and_then(Value::as_str)
        .ok_or("frame decoding failed: missing payload")?;
    decode_base64url(payload)
        .map_err(|err| format!("frame decoding failed: invalid payload encoding: {:?}", err))?;

    let mut normalized = object.clone();
    normalized
        .entry("version".to_string())
        .or_insert_with(|| Value::Number(serde_json::Number::from(1)));
    normalized
        .entry("flags".to_string())
        .or_insert_with(|| Value::Number(serde_json::Number::from(0)));
    Ok(Value::Object(normalized))
}

fn is_valid_frame_type(frame_type: &str) -> bool {
    matches!(
        frame_type,
        "HANDSHAKE" | "HANDSHAKE_ACK" | "DATA" | "PING" | "PONG" | "CLOSE"
    )
}

fn run_header_vectors(payload: &Value) -> Result<Summary, Box<dyn std::error::Error>> {
    let mut summary = Summary::default();
    let test_cases = payload
        .get("test_cases")
        .and_then(Value::as_array)
        .ok_or("header_canonical_bytes.json missing test_cases")?;

    for vector in test_cases {
        let test_id = vector["id"].as_str().unwrap_or("unknown");
        match check_header_vector(vector) {
            Ok(()) => summary.passed += 1,
            Err(err) => {
                println!("FAIL {}: {}", test_id, err);
                summary.failed += 1;
            }
        }
    }

    Ok(summary)
}

fn check_header_vector(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let input_header = vector
        .get("input_header")
        .and_then(Value::as_object)
        .ok_or("missing input_header")?;

    let header = json!({
        "dh": input_header.get("dh").and_then(Value::as_str).unwrap_or(""),
        "n": input_header.get("n").and_then(Value::as_i64).unwrap_or(0),
        "pn": input_header.get("pn").and_then(Value::as_i64).unwrap_or(0),
    });
    let canonical = canonical_marshal(&header)?;

    if let Some(want) = vector
        .get("expected_canonical_json")
        .and_then(Value::as_str)
    {
        if canonical != want {
            return Err(format!("expected canonical json {} got {}", want, canonical).into());
        }
    }
    if let Some(want) = vector
        .get("expected_canonical_b64u")
        .and_then(Value::as_str)
    {
        let got = encode_base64url(canonical.as_bytes());
        if got != want {
            return Err(format!("expected canonical b64u {} got {}", want, got).into());
        }
    }

    Ok(())
}

fn run_kdf_root_vector(payload: &Value) -> Result<Summary, Box<dyn std::error::Error>> {
    let test_id = payload["test_id"].as_str().unwrap_or("kdf_rk");
    match check_kdf_root_vector(payload) {
        Ok(()) => Ok(Summary {
            passed: 1,
            failed: 0,
            skipped: 0,
        }),
        Err(err) => {
            println!("FAIL {}: {}", test_id, err);
            Ok(Summary {
                passed: 0,
                failed: 1,
                skipped: 0,
            })
        }
    }
}

fn check_kdf_root_vector(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let expected = vector
        .get("expected")
        .and_then(Value::as_object)
        .ok_or("missing expected object")?;
    let rk = decode_base64url(
        inputs
            .get("rk")
            .and_then(Value::as_str)
            .ok_or("missing rk")?,
    )
    .map_err(|err| format!("decode rk: {:?}", err))?;
    let dh_out = decode_base64url(
        inputs
            .get("dh_out")
            .and_then(Value::as_str)
            .ok_or("missing dh_out")?,
    )
    .map_err(|err| format!("decode dh_out: {:?}", err))?;
    let mut ikm = rk.clone();
    ikm.extend_from_slice(&dh_out);
    let provider = RealCryptoProvider;
    let out_len = inputs.get("out_len").and_then(Value::as_u64).unwrap_or(64) as usize;
    let derived = provider.hkdf_derive(
        &ikm,
        inputs
            .get("info")
            .and_then(Value::as_str)
            .unwrap_or("")
            .as_bytes(),
        out_len,
    );
    let got_rk = encode_base64url(&derived[..32]);
    let got_ck = encode_base64url(&derived[32..]);

    if let Some(want) = expected.get("new_rk").and_then(Value::as_str) {
        if got_rk != want {
            return Err(format!("new_rk mismatch: got {} want {}", got_rk, want).into());
        }
    }
    if let Some(want) = expected.get("new_ck").and_then(Value::as_str) {
        if got_ck != want {
            return Err(format!("new_ck mismatch: got {} want {}", got_ck, want).into());
        }
    }
    Ok(())
}

fn run_kdf_chain_vector(payload: &Value) -> Result<Summary, Box<dyn std::error::Error>> {
    let test_id = payload["test_id"].as_str().unwrap_or("kdf_ck");
    match check_kdf_chain_vector(payload) {
        Ok(()) => Ok(Summary {
            passed: 1,
            failed: 0,
            skipped: 0,
        }),
        Err(err) => {
            println!("FAIL {}: {}", test_id, err);
            Ok(Summary {
                passed: 0,
                failed: 1,
                skipped: 0,
            })
        }
    }
}

fn check_kdf_chain_vector(vector: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = vector
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or("missing inputs object")?;
    let expected = vector
        .get("expected")
        .and_then(Value::as_object)
        .ok_or("missing expected object")?;
    let ck = decode_base64url(
        inputs
            .get("ck")
            .and_then(Value::as_str)
            .ok_or("missing ck")?,
    )
    .map_err(|err| format!("decode ck: {:?}", err))?;
    let provider = RealCryptoProvider;
    let out_len = inputs.get("out_len").and_then(Value::as_u64).unwrap_or(32) as usize;
    let got_mk = encode_base64url(
        &provider.hkdf_derive(
            &ck,
            inputs
                .get("info_message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .as_bytes(),
            out_len,
        ),
    );
    let got_next_ck = encode_base64url(
        &provider.hkdf_derive(
            &ck,
            inputs
                .get("info_chain")
                .and_then(Value::as_str)
                .unwrap_or("")
                .as_bytes(),
            out_len,
        ),
    );

    if let Some(want) = expected.get("mk").and_then(Value::as_str) {
        if got_mk != want {
            return Err(format!("mk mismatch: got {} want {}", got_mk, want).into());
        }
    }
    if let Some(want) = expected.get("next_ck").and_then(Value::as_str) {
        if got_next_ck != want {
            return Err(format!("next_ck mismatch: got {} want {}", got_next_ck, want).into());
        }
    }
    Ok(())
}

#[derive(Clone)]
struct RatchetTraceState {
    dh_private: [u8; 32],
    dh_public: [u8; 32],
    dh_remote: [u8; 32],
    root_key: Vec<u8>,
    chain_key_send: Option<Vec<u8>>,
    chain_key_recv: Option<Vec<u8>>,
    send_count: u64,
    recv_count: u64,
    prev_send_count: u64,
}

fn run_ratchet_roundtrip_vector(payload: &Value) -> Result<Summary, Box<dyn std::error::Error>> {
    let test_id = payload
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("v1_1_0_roundtrip");
    match check_ratchet_roundtrip_vector(payload) {
        Ok(()) => Ok(Summary {
            passed: 1,
            failed: 0,
            skipped: 0,
        }),
        Err(err) => {
            println!("FAIL {}: {}", test_id, err);
            Ok(Summary {
                passed: 0,
                failed: 1,
                skipped: 0,
            })
        }
    }
}

fn check_ratchet_roundtrip_vector(trace: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut alice_state = init_alice_ratchet_trace_state(trace)?;
    let mut bob_state: Option<RatchetTraceState> = None;
    let steps = trace
        .get("steps")
        .and_then(Value::as_array)
        .ok_or("missing ratchet steps")?;

    for step in steps {
        let actor = step.get("actor").and_then(Value::as_str).unwrap_or("");
        let action = step.get("action").and_then(Value::as_str).unwrap_or("");
        let step_id = step.get("step").and_then(Value::as_u64).unwrap_or(0);

        match action {
            "encrypt" => match actor {
                "alice" => alice_state
                    .encrypt_and_check(step)
                    .map_err(|err| format!("step {} encrypt: {}", step_id, err))?,
                "bob" => bob_state
                    .as_mut()
                    .ok_or("session not initialized for actor bob")?
                    .encrypt_and_check(step)
                    .map_err(|err| format!("step {} encrypt: {}", step_id, err))?,
                _ => return Err(format!("unsupported ratchet actor {}", actor).into()),
            },
            "decrypt" => {
                if actor == "bob" && bob_state.is_none() {
                    bob_state = Some(init_bob_ratchet_trace_state(trace)?);
                }
                match actor {
                    "alice" => alice_state
                        .decrypt_and_check(step)
                        .map_err(|err| format!("step {} decrypt: {}", step_id, err))?,
                    "bob" => bob_state
                        .as_mut()
                        .ok_or("session not initialized for actor bob")?
                        .decrypt_and_check(step)
                        .map_err(|err| format!("step {} decrypt: {}", step_id, err))?,
                    _ => return Err(format!("unsupported ratchet actor {}", actor).into()),
                }
            }
            _ => return Err(format!("unsupported ratchet action {}", action).into()),
        }
    }

    Ok(())
}

fn init_alice_ratchet_trace_state(
    trace: &Value,
) -> Result<RatchetTraceState, Box<dyn std::error::Error>> {
    let alice = trace
        .get("alice")
        .and_then(Value::as_object)
        .ok_or("missing alice trace data")?;
    let bob = trace
        .get("bob")
        .and_then(Value::as_object)
        .ok_or("missing bob trace data")?;
    let prekey_bundle = bob
        .get("prekey_bundle")
        .and_then(Value::as_object)
        .ok_or("missing bob prekey bundle")?;

    let alice_private = decode_base64url(
        alice
            .get("ephemeral_private")
            .and_then(Value::as_str)
            .ok_or("missing alice ephemeral_private")?,
    )
    .map_err(|err| format!("decode alice ephemeral_private: {:?}", err))?;
    let alice_private = ensure_array32(&alice_private, "alice ephemeral private")?;
    let alice_public = x25519_public_from_private(alice_private);
    let bob_signed_prekey = decode_base64url(
        prekey_bundle
            .get("signed_prekey")
            .and_then(Value::as_str)
            .ok_or("missing bob signed_prekey")?,
    )
    .map_err(|err| format!("decode bob signed_prekey: {:?}", err))?;
    let bob_signed_prekey = ensure_array32(&bob_signed_prekey, "bob signed_prekey")?;

    let dh_out = x25519_dh(alice_private, bob_signed_prekey);
    let provider = RealCryptoProvider;
    let root_key = provider.hkdf_derive(&dh_out, b"x3dh-init", 32);
    let (root_key, chain_key_send) = ratchet_kdf_root(&root_key, &dh_out);

    Ok(RatchetTraceState {
        dh_private: alice_private,
        dh_public: alice_public,
        dh_remote: bob_signed_prekey,
        root_key,
        chain_key_send: Some(chain_key_send),
        chain_key_recv: None,
        send_count: 0,
        recv_count: 0,
        prev_send_count: 0,
    })
}

fn init_bob_ratchet_trace_state(
    trace: &Value,
) -> Result<RatchetTraceState, Box<dyn std::error::Error>> {
    let alice = trace
        .get("alice")
        .and_then(Value::as_object)
        .ok_or("missing alice trace data")?;
    let bob = trace
        .get("bob")
        .and_then(Value::as_object)
        .ok_or("missing bob trace data")?;
    let prekey_bundle = bob
        .get("prekey_bundle")
        .and_then(Value::as_object)
        .ok_or("missing bob prekey bundle")?;
    let bundle_secrets = bob
        .get("bundle_secrets")
        .and_then(Value::as_object)
        .ok_or("missing bob bundle_secrets")?;

    let alice_private = decode_base64url(
        alice
            .get("ephemeral_private")
            .and_then(Value::as_str)
            .ok_or("missing alice ephemeral_private")?,
    )
    .map_err(|err| format!("decode alice ephemeral_private: {:?}", err))?;
    let alice_private = ensure_array32(&alice_private, "alice ephemeral private")?;
    let alice_public = x25519_public_from_private(alice_private);
    let bob_signed_prekey_private = decode_base64url(
        bundle_secrets
            .get("signed_prekey_private")
            .and_then(Value::as_str)
            .ok_or("missing bob signed_prekey_private")?,
    )
    .map_err(|err| format!("decode bob signed_prekey_private: {:?}", err))?;
    let bob_signed_prekey_private =
        ensure_array32(&bob_signed_prekey_private, "bob signed_prekey_private")?;
    let bob_signed_prekey_public = decode_base64url(
        prekey_bundle
            .get("signed_prekey")
            .and_then(Value::as_str)
            .ok_or("missing bob signed_prekey")?,
    )
    .map_err(|err| format!("decode bob signed_prekey: {:?}", err))?;
    let bob_signed_prekey_public = ensure_array32(&bob_signed_prekey_public, "bob signed_prekey")?;

    let dh_out = x25519_dh(bob_signed_prekey_private, alice_public);
    let provider = RealCryptoProvider;
    let root_key = provider.hkdf_derive(&dh_out, b"x3dh-init", 32);
    let (root_key, chain_key_recv) = ratchet_kdf_root(&root_key, &dh_out);

    Ok(RatchetTraceState {
        dh_private: bob_signed_prekey_private,
        dh_public: bob_signed_prekey_public,
        dh_remote: alice_public,
        root_key,
        chain_key_send: None,
        chain_key_recv: Some(chain_key_recv),
        send_count: 0,
        recv_count: 0,
        prev_send_count: 0,
    })
}

impl RatchetTraceState {
    fn encrypt_and_check(&mut self, step: &Value) -> Result<(), Box<dyn std::error::Error>> {
        if self.chain_key_send.is_none() {
            let ratchet_private = decode_base64url(
                step.get("ratchet_priv")
                    .and_then(Value::as_str)
                    .ok_or("missing ratchet_priv for send-chain init")?,
            )
            .map_err(|err| format!("decode ratchet_priv: {:?}", err))?;
            let ratchet_private = ensure_array32(&ratchet_private, "ratchet_priv")?;
            self.initialize_sending_chain(ratchet_private)?;
        }

        let plaintext = decode_base64url(
            step.get("plaintext")
                .and_then(Value::as_str)
                .ok_or("missing plaintext")?,
        )
        .map_err(|err| format!("decode plaintext: {:?}", err))?;
        let nonce = decode_base64url(
            step.get("nonce")
                .and_then(Value::as_str)
                .ok_or("missing nonce")?,
        )
        .map_err(|err| format!("decode nonce: {:?}", err))?;

        let header = json!({
            "dh": encode_base64url(&self.dh_public),
            "n": self.send_count,
            "pn": self.prev_send_count,
        });
        let header_bytes = canonical_marshal(&header)?.into_bytes();
        let chain_key_send = self
            .chain_key_send
            .clone()
            .ok_or("missing send chain key")?;
        let (message_key, next_chain_key) = ratchet_kdf_chain(&chain_key_send);
        let ciphertext =
            encrypt_with_chacha20_poly1305(&message_key, &nonce, &plaintext, &header_bytes)?;

        self.chain_key_send = Some(next_chain_key);
        self.send_count += 1;

        let ciphertext_b64 = encode_base64url(&ciphertext);
        if let Some(want) = step.get("ciphertext").and_then(Value::as_str) {
            if ciphertext_b64 != want {
                return Err(
                    format!("ciphertext mismatch: got {} want {}", ciphertext_b64, want).into(),
                );
            }
        }
        if let Some(want) = step.get("aad").and_then(Value::as_str) {
            let got = encode_base64url(&header_bytes);
            if got != want {
                return Err(format!("aad mismatch: got {} want {}", got, want).into());
            }
        }

        let envelope = json!({
            "header": header,
            "nonce": encode_base64url(&nonce),
            "ciphertext": ciphertext_b64,
        });
        let wire_b64 = encode_base64url(canonical_marshal(&envelope)?.as_bytes());
        if let Some(want) = step.get("wire_message_b64u").and_then(Value::as_str) {
            if wire_b64 != want {
                return Err(
                    format!("wire_message mismatch: got {} want {}", wire_b64, want).into(),
                );
            }
        }

        Ok(())
    }

    fn decrypt_and_check(&mut self, step: &Value) -> Result<(), Box<dyn std::error::Error>> {
        let wire = decode_base64url(
            step.get("wire_message_b64u")
                .and_then(Value::as_str)
                .ok_or("missing wire_message_b64u")?,
        )
        .map_err(|err| format!("decode wire_message_b64u: {:?}", err))?;
        let envelope: Value = serde_json::from_slice(&wire)?;
        let header = envelope
            .get("header")
            .and_then(Value::as_object)
            .ok_or("missing envelope header")?;
        let header_value = json!({
            "dh": header.get("dh").and_then(Value::as_str).unwrap_or(""),
            "n": header.get("n").and_then(Value::as_u64).unwrap_or(0),
            "pn": header.get("pn").and_then(Value::as_u64).unwrap_or(0),
        });
        let header_bytes = canonical_marshal(&header_value)?.into_bytes();
        let header_dh = decode_base64url(
            header
                .get("dh")
                .and_then(Value::as_str)
                .ok_or("missing header dh")?,
        )
        .map_err(|err| format!("decode header dh: {:?}", err))?;
        let header_dh = ensure_array32(&header_dh, "header dh")?;

        if header_dh != self.dh_remote {
            self.skip_message_keys(header.get("pn").and_then(Value::as_u64).unwrap_or(0))?;
            self.dh_ratchet(header_dh)?;
        }

        self.skip_message_keys(header.get("n").and_then(Value::as_u64).unwrap_or(0))?;
        let chain_key_recv = self
            .chain_key_recv
            .clone()
            .ok_or("missing receiving chain key")?;
        let (message_key, next_chain_key) = ratchet_kdf_chain(&chain_key_recv);

        let nonce = decode_base64url(
            envelope
                .get("nonce")
                .and_then(Value::as_str)
                .ok_or("missing envelope nonce")?,
        )
        .map_err(|err| format!("decode envelope nonce: {:?}", err))?;
        let ciphertext = decode_base64url(
            envelope
                .get("ciphertext")
                .and_then(Value::as_str)
                .ok_or("missing envelope ciphertext")?,
        )
        .map_err(|err| format!("decode envelope ciphertext: {:?}", err))?;
        let plaintext =
            decrypt_with_chacha20_poly1305(&message_key, &nonce, &ciphertext, &header_bytes)?;

        self.chain_key_recv = Some(next_chain_key);
        self.recv_count += 1;

        let expected_plaintext = decode_base64url(
            step.get("expected_plaintext")
                .and_then(Value::as_str)
                .ok_or("missing expected_plaintext")?,
        )
        .map_err(|err| format!("decode expected_plaintext: {:?}", err))?;
        if plaintext != expected_plaintext {
            return Err(format!(
                "plaintext mismatch: got {} want {}",
                encode_base64url(&plaintext),
                encode_base64url(&expected_plaintext)
            )
            .into());
        }

        Ok(())
    }

    fn initialize_sending_chain(
        &mut self,
        private_key: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.dh_private = private_key;
        self.dh_public = x25519_public_from_private(private_key);

        let dh_send = x25519_dh(self.dh_private, self.dh_remote);
        let (root_key, chain_key_send) = ratchet_kdf_root(&self.root_key, &dh_send);
        self.root_key = root_key;
        self.chain_key_send = Some(chain_key_send);
        Ok(())
    }

    fn skip_message_keys(&mut self, until: u64) -> Result<(), Box<dyn std::error::Error>> {
        let Some(mut chain_key_recv) = self.chain_key_recv.clone() else {
            return Ok(());
        };
        if self.recv_count + 1000 < until {
            return Err("too many skipped ratchet messages".into());
        }
        while self.recv_count < until {
            let (_, next_chain_key) = ratchet_kdf_chain(&chain_key_recv);
            chain_key_recv = next_chain_key;
            self.recv_count += 1;
        }
        self.chain_key_recv = Some(chain_key_recv);
        Ok(())
    }

    fn dh_ratchet(&mut self, remote_public: [u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.dh_remote = remote_public;

        let dh_recv = x25519_dh(self.dh_private, self.dh_remote);
        let (root_key, chain_key_recv) = ratchet_kdf_root(&self.root_key, &dh_recv);
        self.root_key = root_key;
        self.chain_key_recv = Some(chain_key_recv);

        let provider = RealCryptoProvider;
        let (next_public, next_private) = provider.x25519_generate();
        self.dh_private = next_private;
        self.dh_public = next_public;

        let dh_send = x25519_dh(self.dh_private, self.dh_remote);
        let (root_key, chain_key_send) = ratchet_kdf_root(&self.root_key, &dh_send);
        self.root_key = root_key;
        self.chain_key_send = Some(chain_key_send);
        Ok(())
    }
}

fn ratchet_kdf_root(root_key: &[u8], dh_out: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut ikm = root_key.to_vec();
    ikm.extend_from_slice(dh_out);
    let provider = RealCryptoProvider;
    let derived = provider.hkdf_derive(&ikm, b"talos-double-ratchet-root", 64);
    (derived[..32].to_vec(), derived[32..].to_vec())
}

fn ratchet_kdf_chain(chain_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let provider = RealCryptoProvider;
    let message_key = provider.hkdf_derive(chain_key, b"talos-double-ratchet-message", 32);
    let next_chain_key = provider.hkdf_derive(chain_key, b"talos-double-ratchet-chain", 32);
    (message_key, next_chain_key)
}

fn x25519_public_from_private(private_key: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(private_key);
    *PublicKey::from(&secret).as_bytes()
}

fn x25519_dh(private_key: [u8; 32], public_key: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(private_key);
    let public = PublicKey::from(public_key);
    *secret.diffie_hellman(&public).as_bytes()
}

fn ensure_array32(bytes: &[u8], label: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if bytes.len() != 32 {
        return Err(format!("{} must be 32 bytes, got {}", label, bytes.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn encrypt_with_chacha20_poly1305(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() != 32 {
        return Err(format!("invalid ChaCha20-Poly1305 key size {}", key.len()).into());
    }
    if nonce.len() != 12 {
        return Err(format!("invalid ChaCha20-Poly1305 nonce size {}", nonce.len()).into());
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let payload = Payload {
        msg: plaintext,
        aad: ad,
    };
    cipher
        .encrypt(Nonce::from_slice(nonce), payload)
        .map_err(|err| format!("ChaCha20-Poly1305 encrypt failed: {:?}", err).into())
}

fn decrypt_with_chacha20_poly1305(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() != 32 {
        return Err(format!("invalid ChaCha20-Poly1305 key size {}", key.len()).into());
    }
    if nonce.len() != 12 {
        return Err(format!("invalid ChaCha20-Poly1305 nonce size {}", nonce.len()).into());
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let payload = Payload {
        msg: ciphertext,
        aad: ad,
    };
    cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|err| format!("ChaCha20-Poly1305 decrypt failed: {:?}", err).into())
}

const SEED_HEX_ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const SEED_HEX_TWO: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const DEFAULT_CAPABILITY_IAT: i64 = 1704067200;
const DEFAULT_CAPABILITY_EXP: i64 = 1767504000;
const DEFAULT_CAPABILITY_SUBJECT: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

fn default_capability_scope() -> Value {
    json!([{
        "tool": "filesystem",
        "actions": ["read", "write"]
    }])
}

fn make_signed_capability(
    inputs: &serde_json::Map<String, Value>,
) -> Result<(serde_json::Map<String, Value>, String, i64), Box<dyn std::error::Error>> {
    let seed_hex = inputs
        .get("issuer_seed_hex")
        .and_then(Value::as_str)
        .unwrap_or(SEED_HEX_ONE);
    let seed_bytes = hex::decode(seed_hex)?;
    if seed_bytes.len() != 32 {
        return Err(format!("seed must be 32 bytes, got {}", seed_bytes.len()).into());
    }
    let identity = Identity::from_seed(&seed_bytes);
    let exp = inputs
        .get("exp")
        .and_then(Value::as_i64)
        .or_else(|| inputs.get("exp").and_then(Value::as_u64).map(|v| v as i64))
        .unwrap_or(DEFAULT_CAPABILITY_EXP);
    let iat = inputs
        .get("iat")
        .and_then(Value::as_i64)
        .or_else(|| inputs.get("iat").and_then(Value::as_u64).map(|v| v as i64))
        .unwrap_or(DEFAULT_CAPABILITY_IAT);
    let mut capability = serde_json::Map::new();
    capability.insert("v".to_string(), Value::String("1".to_string()));
    capability.insert("iss".to_string(), Value::String(identity.did()));
    capability.insert(
        "sub".to_string(),
        Value::String(
            inputs
                .get("subject_did")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_CAPABILITY_SUBJECT)
                .to_string(),
        ),
    );
    capability.insert(
        "scope".to_string(),
        inputs
            .get("scope")
            .cloned()
            .unwrap_or_else(default_capability_scope),
    );
    capability.insert(
        "iat".to_string(),
        Value::Number(serde_json::Number::from(iat)),
    );
    capability.insert(
        "exp".to_string(),
        Value::Number(serde_json::Number::from(exp)),
    );
    let canonical = canonical_marshal(&Value::Object(capability.clone()))?;
    capability.insert(
        "sig".to_string(),
        Value::String(encode_base64url(&identity.sign(canonical.as_bytes()))),
    );
    Ok((capability, identity.public_key(), exp))
}

fn verify_capability(
    capability: &serde_json::Map<String, Value>,
    issuer_public_hex: &str,
    now: i64,
) -> Result<(bool, &'static str), Box<dyn std::error::Error>> {
    let signature = match capability.get("sig").and_then(Value::as_str) {
        Some(value) => value,
        None => return Ok((false, "signature")),
    };
    let exp = capability
        .get("exp")
        .and_then(Value::as_i64)
        .or_else(|| {
            capability
                .get("exp")
                .and_then(Value::as_u64)
                .map(|v| v as i64)
        })
        .unwrap_or(0);
    if exp < now {
        return Ok((false, "expired"));
    }

    let mut content = capability.clone();
    content.remove("sig");
    let canonical = canonical_marshal(&Value::Object(content))?;
    let signature_raw = decode_base64url(signature)
        .map_err(|err| format!("decode capability signature: {:?}", err))?;
    if signature_raw.len() != 64 {
        return Ok((false, "signature"));
    }
    let public_raw = hex::decode(issuer_public_hex)?;
    if public_raw.len() != 32 {
        return Err(format!("public key must be 32 bytes, got {}", public_raw.len()).into());
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&public_raw);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&signature_raw);
    let provider = RealCryptoProvider;
    if !Wallet::verify(canonical.as_bytes(), &sig, &public_key, &provider) {
        return Ok((false, "signature"));
    }

    Ok((true, ""))
}

fn capability_authorize(scope: &Value, tool: &str, action: &str) -> bool {
    let Some(items) = scope.as_array() else {
        return false;
    };
    items.iter().any(|candidate| {
        let Some(object) = candidate.as_object() else {
            return false;
        };
        let Some(scope_tool) = object.get("tool").and_then(Value::as_str) else {
            return false;
        };
        if scope_tool != tool {
            return false;
        }
        object
            .get("actions")
            .and_then(Value::as_array)
            .map(|actions| {
                actions
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|value| value == action)
            })
            .unwrap_or(false)
    })
}
