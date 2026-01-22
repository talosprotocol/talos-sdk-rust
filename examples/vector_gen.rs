use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use serde::Serialize;
use talos_sdk::identity::Identity; // Assuming exposed; checking lib.rs earlier showed it is.

#[derive(Serialize)]
struct TestVector {
    test_id: String,
    inputs: HashMap<String, String>,
    expected: HashMap<String, serde_json::Value>,
}

#[derive(Serialize)]
struct VectorFile {
    vectors: Vec<TestVector>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut vectors = Vec::new();

    // Vector 1: Rust Sign
    let seed_hex = "0202020202020202020202020202020202020202020202020202020202020202";
    let seed_bytes = hex::decode(seed_hex)?;
    let id = Identity::from_seed(&seed_bytes);

    let msg = "hello from rust";
    let sig = id.sign(msg.as_bytes());
    let sig_b64 = base64_url::encode(&sig); // Assuming dependency available

    let mut inputs = HashMap::new();
    inputs.insert("seed_hex".to_string(), seed_hex.to_string());
    inputs.insert("message_utf8".to_string(), msg.to_string());

    let mut expected = HashMap::new();
    expected.insert("did".to_string(), serde_json::Value::String(id.did()));
    expected.insert("public_key_hex".to_string(), serde_json::Value::String(id.public_key()));
    expected.insert("signature_base64url".to_string(), serde_json::Value::String(sig_b64));
    expected.insert("verify".to_string(), serde_json::Value::Bool(true));

    vectors.push(TestVector {
        test_id: "rust_sign_1".to_string(),
        inputs,
        expected,
    });

    let vf = VectorFile { vectors };
    let json = serde_json::to_string_pretty(&vf)?;

    let path = "../../interop/rust_vectors.json";
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;

    println!("Generated {}", path);
    Ok(())
}
