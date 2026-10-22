//! Creates independently checked Rust + SAS fixtures which the TypeScript
//! SDK must reproduce byte-for-byte in test/differential.test.ts.
#[path = "../hash_parity.rs"]
mod hash_parity;
use sas::SAS;
use serde_json::json;
use soroban_sdk::{Address, Env};

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        value.push_str(&format!("{b:02x}"));
    }
    value
}

fn address(addr: &Address) -> String {
    let text = addr.to_string();
    let mut bytes = vec![0u8; text.len() as usize];
    text.copy_into_slice(&mut bytes);
    String::from_utf8(bytes).expect("address strkey is ASCII")
}

fn main() {
    let env = Env::default();
    env.budget().reset_unlimited();
    let sas_id = env.register_contract(None, SAS);
    for index in 0..128usize {
        let mut seed: Vec<u8> = (0..(index % 113))
            .map(|j| {
                (index as u8)
                    .wrapping_mul(37)
                    .wrapping_add((j as u8).wrapping_mul(3))
            })
            .collect();
        if index % 8 == 0 {
            seed = vec![0u8; index % 113];
        }
        if index % 8 == 1 {
            seed = vec![0xffu8; index % 113];
        }
        if index % 8 == 2 {
            seed = "😃caféمرحبا".as_bytes().to_vec();
        }
        if index % 8 == 3 {
            seed.insert(0, 0x30);
        }
        if index % 8 == 4 {
            seed.insert(0, 0xc1);
        }
        let (a, d) = hash_parity::from_bytes(&env, &sas_id, &seed);
        let hash = hash_parity::assert_parity(&env, &sas_id, &a, &d);
        println!(
            "{}",
            json!({
                "uid": hex(&a.uid.0.to_array()),
                "schemaUid": hex(&a.schema_uid.0.to_array()),
                "refUid": hex(&a.ref_uid.0.to_array()),
                "time": a.time.to_string(),
                "expirationTime": a.expiration_time.to_string(),
                "recipient": address(&a.recipient),
                "attester": address(&a.attester),
                "revocable": a.revocable,
                "data": hex(&{ let mut b=vec![0; a.data.len() as usize]; a.data.copy_into_slice(&mut b); b }),
                "networkId": hex(&d.network_id.to_array()),
                "contract": address(&d.contract),
                "nonce": d.nonce.to_string(),
                "expected": hex(&hash),
            })
        );
    }
}
