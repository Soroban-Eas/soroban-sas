//! W3C VC v1.1 JWT + did:key -> Soroban SAS schema/resolver integration.
//!
//! Run: cargo run --example did_vc_resolver
//! Test: cargo test --example did_vc_resolver
//! No RPC connection, wallet secrets or external JSON-LD resolver is required.
mod resolver;

use ed25519_dalek::{Signer, SigningKey};
use resolver::{binding_hash, did_for_key, DidVcResolver, DidVcResolverClient};
use sas::{SASClient, SAS};
use schema_registry::{SchemaRegistry, SchemaRegistryClient};
use serde_json::{json, Value};
use soroban_sas_common::{attestation_uid, Attestation, UID};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, BytesN, Env, String as SorobanString};

const SCHEMA: &str = "degree String, graduated bool";

/// Small RFC 4648 base64url encoder: JOSE signs the *encoded* header and
/// payload, not their decoded JSON. No padding and no unsafe transformations.
fn base64url(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() >= 2 {
            out.push(ALPHABET[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() == 3 {
            out.push(ALPHABET[(b2 & 63) as usize] as char);
        }
    }
    out
}

fn bytes_to_string(bytes: &Bytes) -> String {
    let mut out = Vec::new();
    for i in 0..bytes.len() {
        out.push(bytes.get(i).unwrap());
    }
    String::from_utf8(out).expect("DID should contain ASCII")
}

/// W3C DID Core shape: the DID subject is self-certifying (did:key), and the
/// assertionMethod explicitly references the issuer's Ed25519 verification key.
/// The multicodec fingerprint is deterministic, not a hard-coded DID literal.
fn did_document(did: &str) -> Value {
    let key_id = format!(
        "{did}#{fingerprint}",
        fingerprint = &did["did:key:".len()..]
    );
    json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": did,
        "verificationMethod": [{
            "id": key_id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": &did["did:key:".len()..]
        }],
        "assertionMethod": [key_id],
        "authentication": [key_id]
    })
}

/// Validate the data-model boundary before offering an attestation to SAS.
/// A Soroban contract cannot safely dereference remote JSON-LD contexts or
/// parse arbitrary JSON, so the client owns JSON-LD/JWT semantic validation.
fn validate_vc(
    doc: &Value,
    issuer_doc: &Value,
    subject_doc: &Value,
    issuer_did: &str,
    subject_did: &str,
    schema_uid: &UID,
) -> Result<(), String> {
    fn valid_doc(doc: &Value, did: &str) -> bool {
        let fingerprint = did.strip_prefix("did:key:").unwrap_or("");
        let expected_key_id = format!("{did}#{fingerprint}");
        doc.get("id").and_then(Value::as_str) == Some(did)
            && doc["verificationMethod"][0]["id"] == expected_key_id
            && doc["verificationMethod"][0]["controller"] == did
            && doc["verificationMethod"][0]["publicKeyMultibase"] == fingerprint
            && doc["assertionMethod"][0] == expected_key_id
            && doc["@context"][0] == "https://www.w3.org/ns/did/v1"
    }
    if !valid_doc(issuer_doc, issuer_did) || !valid_doc(subject_doc, subject_did) {
        return Err("DID document does not bind the declared subject and key".into());
    }
    if doc["@context"][0] != "https://www.w3.org/2018/credentials/v1"
        || doc["type"][0] != "VerifiableCredential"
        || doc["issuer"] != issuer_did
        || doc["credentialSubject"]["id"] != subject_did
        || doc["credentialSubject"]["degree"] != "Computer Science"
        || doc["credentialSubject"]["graduated"] != true
        || doc["credentialSchema"]["id"]
            != format!("urn:sas:schema:{}", hex::encode(schema_uid.0.to_array()))
        || doc["credentialSchema"]["type"] != "SasSchema2026"
        || doc["issuanceDate"].as_str().is_none()
    {
        return Err("VC data does not match issuer, subject or SAS schema".into());
    }
    Ok(())
}

/// Binary envelope consumed by on_attest. We keep JSON-LD in the JWT claim,
/// and put just the signed compact JWT input/proofs/DID identities on-chain.
fn encode_envelope(
    issuer_did: &str,
    subject_did: &str,
    signing_input: &str,
    jwt_sig: &[u8; 64],
    binding_sig: &[u8; 64],
) -> Vec<u8> {
    assert!(issuer_did.len() <= u8::MAX as usize && subject_did.len() <= u8::MAX as usize);
    assert!(signing_input.len() <= 4096);
    let mut bytes = b"SASVC1".to_vec();
    bytes.push(issuer_did.len() as u8);
    bytes.extend_from_slice(issuer_did.as_bytes());
    bytes.push(subject_did.len() as u8);
    bytes.extend_from_slice(subject_did.as_bytes());
    bytes.extend_from_slice(&(signing_input.len() as u16).to_be_bytes());
    bytes.extend_from_slice(signing_input.as_bytes());
    bytes.extend_from_slice(jwt_sig);
    bytes.extend_from_slice(binding_sig);
    bytes
}

/// End-to-end simulation against the real SAS + SchemaRegistry, rather than
/// a fake function which bypasses SAS resolver callbacks.
fn simulate() -> (Value, Value, Value, String, bool) {
    let env = Env::default();
    // Test-only Soroban host: skips account authorization, not Ed25519 proof
    // verification. No real keys or network interaction occur.
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);
    let recipient = Address::generate(&env);

    let registry_id = env.register_contract(None, SchemaRegistry);
    let registry = SchemaRegistryClient::new(&env, &registry_id);
    registry.init(&admin);
    let sas_id = env.register_contract(None, SAS);
    let sas = SASClient::new(&env, &sas_id);
    sas.init(&admin, &registry_id);
    let resolver_id = env.register_contract(None, DidVcResolver);
    let resolver = DidVcResolverClient::new(&env, &resolver_id);

    let issuer_key = SigningKey::from_bytes(&[31; 32]);
    let subject_key = SigningKey::from_bytes(&[52; 32]);
    let issuer_pub = BytesN::from_array(&env, issuer_key.verifying_key().as_bytes());
    let subject_pub = BytesN::from_array(&env, subject_key.verifying_key().as_bytes());
    resolver.bind_controller(&issuer, &issuer_pub);
    resolver.bind_controller(&recipient, &subject_pub);
    let issuer_did = bytes_to_string(&did_for_key(&env, &issuer_pub));
    let subject_did = bytes_to_string(&did_for_key(&env, &subject_pub));
    let issuer_doc = did_document(&issuer_did);
    let subject_doc = did_document(&subject_did);

    let schema = SorobanString::from_str(&env, SCHEMA);
    let schema_uid = registry.register(&issuer, &schema, &resolver_id, &true);

    // W3C VC Data Model v1.1 JSON-LD. credentialSchema references the
    // registered SAS schema; the inline context maps example vocabularies.
    // JWT VC serialization follows VC-JWT 1.1's iss/sub/nbf/jti/vc mapping.
    let vc = json!({
        "@context": ["https://www.w3.org/2018/credentials/v1", {
            "EducationCredential": "https://example.org/vocab#EducationCredential",
            "degree": "https://schema.org/educationalCredentialAwarded",
            "graduated": "https://example.org/vocab#graduated",
            "SasSchema2026": "https://example.org/vocab#SasSchema2026"
        }],
        "id": "urn:uuid:b9bcc734-4266-497e-9d39-d519d1f057cb",
        "type": ["VerifiableCredential", "EducationCredential"],
        "issuer": issuer_did,
        "issuanceDate": "2026-10-21T00:00:00Z",
        "credentialSubject": {
            "id": subject_did, "degree": "Computer Science", "graduated": true
        },
        "credentialSchema": {
            "id": format!("urn:sas:schema:{}", hex::encode(schema_uid.0.to_array())),
            "type": "SasSchema2026"
        }
    });
    validate_vc(
        &vc,
        &issuer_doc,
        &subject_doc,
        &issuer_did,
        &subject_did,
        &schema_uid,
    )
    .expect("invalid DID or VC document");
    let kid = format!("{}#{}", issuer_did, &issuer_did["did:key:".len()..]);
    let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
    let claims = json!({
        "iss": issuer_did, "sub": subject_did,
        "nbf": 1792540800, "jti": vc["id"], "vc": vc,
    });
    let signing_input = format!(
        "{}.{}",
        base64url(header.to_string().as_bytes()),
        base64url(claims.to_string().as_bytes())
    );
    let jwt_signature = issuer_key.sign(signing_input.as_bytes()).to_bytes();

    // On-chain checks bind the same signed JWT to the SAS schema and parties.
    // The second signature prevents an attacker from transplanting a JWT to
    // a different schema/recipient, even though SAS does not parse JSON.
    let mut att = Attestation {
        uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        schema_uid: schema_uid.clone(),
        time: 0,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: issuer.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };
    let signing_bytes = Bytes::from_slice(&env, signing_input.as_bytes());
    let issuer_did_bytes = Bytes::from_slice(&env, issuer_did.as_bytes());
    let subject_did_bytes = Bytes::from_slice(&env, subject_did.as_bytes());
    let bound_hash = binding_hash(
        &env,
        &att,
        &signing_bytes,
        &issuer_did_bytes,
        &subject_did_bytes,
    );
    let bound_signature = issuer_key.sign(&bound_hash.to_array()).to_bytes();
    let envelope = encode_envelope(
        &issuer_did,
        &subject_did,
        &signing_input,
        &jwt_signature,
        &bound_signature,
    );
    att.data = Bytes::from_slice(&env, &envelope);
    att.uid = attestation_uid(&env, &schema_uid, &recipient, &issuer, &att.data);

    // Because the schema names DidVcResolver, SAS invokes on_attest and rejects
    // the entire transaction if a signature/DID check fails.
    let uid = sas.attest(&att);
    let verified = sas.verify_attestation(&uid);

    // Proof is the JWS signature, not a made-up Data Integrity proof suite.
    let jwt = format!("{}.{}", signing_input, base64url(&jwt_signature));
    (issuer_doc, subject_doc, vc, jwt, verified)
}

fn main() {
    if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
        println!("cargo run --example did_vc_resolver\nRun a local DID/VC JWT -> SAS resolver simulation (no network).");
        return;
    }
    let (issuer_doc, subject_doc, vc, jwt, verified) = simulate();
    println!(
        "Issuer DID document:\n{}",
        serde_json::to_string_pretty(&issuer_doc).unwrap()
    );
    println!(
        "Subject DID document:\n{}",
        serde_json::to_string_pretty(&subject_doc).unwrap()
    );
    println!(
        "Verifiable Credential (JSON-LD):\n{}",
        serde_json::to_string_pretty(&vc).unwrap()
    );
    println!("VC-JWT (EdDSA):\n{jwt}");
    println!("SAS on-chain resolver check + attestation verification: {verified}");
    assert!(verified, "attestation should be valid");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_vectors_are_unpadded() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xff, 0xfe]), "__4");
    }

    #[test]
    fn did_document_and_vc_round_trip_through_real_sas() {
        let (issuer, subject, vc, jwt, verified) = simulate();
        assert!(verified);
        assert!(issuer["id"].as_str().unwrap().starts_with("did:key:z"));
        assert!(subject["id"].as_str().unwrap().starts_with("did:key:z"));
        assert_ne!(issuer["id"], subject["id"]);
        assert_eq!(vc["issuer"], issuer["id"]);
        assert!(jwt.starts_with("ey"));
        assert_eq!(jwt.split('.').count(), 3);
    }

    #[test]
    fn rejects_invalid_did_document_and_subject_mapping() {
        let env = Env::default();
        let key = BytesN::from_array(&env, &[3u8; 32]);
        let did = bytes_to_string(&did_for_key(&env, &key));
        let mut doc = did_document(&did);
        doc["verificationMethod"][0]["controller"] = json!("did:key:zWrongKey");
        let uid = UID(BytesN::from_array(&env, &[1u8; 32]));
        let vc = json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"], "issuer": did,
            "credentialSubject": {"id": did, "degree": "Computer Science", "graduated": true},
            "issuanceDate": "2026-10-21T00:00:00Z",
            "credentialSchema": {
                "id": format!("urn:sas:schema:{}", hex::encode(uid.0.to_array())),
                "type": "SasSchema2026"
            }
        });
        assert!(validate_vc(&vc, &doc, &did_document(&did), &did, &did, &uid).is_err());
    }

    #[test]
    fn invalid_issuer_signature_rejected_by_soroban_host() {
        let env = Env::default();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let recipient = Address::generate(&env);
        let resolver_id = env.register_contract(None, DidVcResolver);
        let client = DidVcResolverClient::new(&env, &resolver_id);
        let key = SigningKey::from_bytes(&[12; 32]);
        let pubkey = BytesN::from_array(&env, key.verifying_key().as_bytes());
        client.bind_controller(&issuer, &pubkey);
        client.bind_controller(&recipient, &pubkey);
        let did = bytes_to_string(&did_for_key(&env, &pubkey));
        let input = "eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319";
        let att = Attestation {
            uid: UID(BytesN::from_array(&env, &[0; 32])),
            schema_uid: UID(BytesN::from_array(&env, &[1; 32])),
            time: 0,
            expiration_time: 0,
            revocation_time: 0,
            valid_from: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0; 32])),
            attester: issuer,
            recipient,
            revocable: true,
            data: Bytes::from_slice(
                &env,
                &encode_envelope(&did, &did, input, &[0; 64], &[0; 64]),
            ),
        };
        assert!(client.try_on_attest(&att).is_err());
    }

    #[test]
    fn on_chain_rejects_did_subject_mismatch() {
        let env = Env::default();
        env.mock_all_auths();
        let issuer = Address::generate(&env);
        let recipient = Address::generate(&env);
        let resolver_id = env.register_contract(None, DidVcResolver);
        let client = DidVcResolverClient::new(&env, &resolver_id);
        let key = SigningKey::from_bytes(&[12; 32]);
        let pubkey = BytesN::from_array(&env, key.verifying_key().as_bytes());
        client.bind_controller(&issuer, &pubkey);
        client.bind_controller(&recipient, &pubkey);
        let did = bytes_to_string(&did_for_key(&env, &pubkey));
        let att = Attestation {
            uid: UID(BytesN::from_array(&env, &[0; 32])),
            schema_uid: UID(BytesN::from_array(&env, &[1; 32])),
            time: 0,
            expiration_time: 0,
            revocation_time: 0,
            valid_from: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0; 32])),
            attester: issuer,
            recipient,
            revocable: true,
            data: Bytes::from_slice(
                &env,
                &encode_envelope(&did, "did:key:zFakeSubject", "a.b", &[0; 64], &[0; 64]),
            ),
        };
        assert!(client.try_on_attest(&att).is_err());
    }
}
