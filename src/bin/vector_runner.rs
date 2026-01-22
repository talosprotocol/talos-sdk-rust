use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::BufReader;
use talos_core_rs::adapters::crypto::RealCryptoProvider;
use talos_core_rs::domain::wallet::Wallet;
use talos_sdk::identity::Identity;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<TestVector>,
}

#[derive(Deserialize)]
struct TestVector {
    test_id: String,
    inputs: HashMap<String, String>,
    expected: HashMap<String, serde_json::Value>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let vectors_path = if args.len() > 1 {
        &args[1]
    } else {
        println!("Usage: cargo run --bin vector_runner <vectors.json>");
        return Ok(());
    };

    println!("Running vectors from: {}", vectors_path);
    let file = File::open(vectors_path)?;
    let reader = BufReader::new(file);
    let vf: VectorFile = serde_json::from_reader(reader)?;

    for vec in vf.vectors {
        if vec.test_id.contains("sign") || vec.test_id.contains("verify") {
            run_signing(&vec)?;
        }
    }

    println!("ALL TESTS PASSED");
    Ok(())
}

fn run_signing(vec: &TestVector) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = &vec.inputs;
    let expected = &vec.expected;

    // Check seed in inputs.
    // If not present or empty, try Verify mode.
    let seed_hex = inputs.get("seed_hex").map(|s| s.as_str()).unwrap_or("");

    if !seed_hex.is_empty() {
        let seed_bytes = hex::decode(seed_hex)?;
        let id = Identity::from_seed(&seed_bytes);
        if let Some(msg) = inputs.get("message_utf8") {
            // Sign check
            let sig = id.sign(msg.as_bytes());
            let sig_b64 = base64_url::encode(&sig);

            if let Some(expected_sig) = expected.get("signature_base64url") {
                let expected_sig_str = expected_sig.as_str().unwrap();
                if sig_b64 != expected_sig_str {
                    return Err(format!(
                        "Sign mismatch for {}: got {}, want {}",
                        vec.test_id, sig_b64, expected_sig_str
                    )
                    .into());
                }
            }
        }
    } else {
        // Verify only mode
        if let Some(verify) = expected.get("verify") {
            if verify.as_bool() == Some(true) {
                let msg = inputs.get("message_utf8").unwrap();

                // Get signature string
                let sig_b64_str = if let Some(v) = expected.get("signature_base64url") {
                    v.as_str().unwrap()
                } else if let Some(s) = inputs.get("signature_base64url") {
                    s.as_str()
                } else {
                    return Err(format!("Missing signature for {}", vec.test_id).into());
                };

                let sig_bytes = base64_url::decode(sig_b64_str)
                    .map_err(|e| format!("Base64 Error: {:?}", e))?;
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&sig_bytes);

                // Get public key hex string
                let pub_hex_str = if let Some(v) = expected.get("public_key_hex") {
                    v.as_str()
                } else if let Some(s) = inputs.get("public_key_hex") {
                    Some(s.as_str())
                } else {
                    None
                };

                if let Some(pub_hex) = pub_hex_str {
                    let pub_bytes = hex::decode(pub_hex)?;
                    let mut pub_arr = [0u8; 32];
                    pub_arr.copy_from_slice(&pub_bytes);

                    let provider = RealCryptoProvider;
                    if !Wallet::verify(msg.as_bytes(), &sig_arr, &pub_arr, &provider) {
                        return Err(format!("Verify failed for {}", vec.test_id).into());
                    }
                }
            }
        }
    }
    Ok(())
}
