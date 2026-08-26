#[cfg(test)]
mod tests {
    #[test]
    fn test_signature_generation() {
        let seed = [1u8; 32];
        let signature = crate::signature::generate_delegated_signature(&seed, b"message");
        assert_eq!(signature.len(), 64);
        assert_ne!(signature, [0u8; 64]);
    }
}

#[test]
fn test_rpc_mock_parsing() {}

#[test]
fn test_schema_builder_constructs_schema_record() {
    let env = soroban_sdk::Env::default();
    let resolver = stellar_strkey::Contract([7u8; 32]).to_string();

    let record = crate::SchemaBuilder::new()
        .with_schema("bool verified")
        .with_resolver(&resolver)
        .with_revocable(true)
        .build(&env)
        .unwrap();

    assert_eq!(
        record.schema,
        soroban_sdk::String::from_str(&env, "bool verified")
    );
    assert!(record.revocable);
}

#[test]
fn test_schema_builder_rejects_empty_schema() {
    let env = soroban_sdk::Env::default();
    let resolver = stellar_strkey::Contract([7u8; 32]).to_string();

    let result = crate::SchemaBuilder::new()
        .with_resolver(&resolver)
        .with_revocable(true)
        .build(&env);

    assert!(matches!(result, Err(crate::errors::SdkError::RpcError(_))));
}
