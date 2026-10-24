use crate::models::{NetworkConfig, SchemaDocItem};

/// Generates integration code snippets (Rust, TypeScript, cURL) for a given schema.
pub struct IntegrationExamples;

impl IntegrationExamples {
    /// Generates a Rust integration snippet using `soroban-sas-sdk`.
    pub fn rust_example(schema: &SchemaDocItem, network: &NetworkConfig) -> String {
        let uid = &schema.uid;
        let mut field_assigns = String::new();

        for field in &schema.fields {
            let _dummy_val = match field.field_type.to_lowercase().as_str() {
                "string" => format!("\"example_{}\".to_string()", field.name),
                "bool" => "true".to_string(),
                "u32" => "100u32".to_string(),
                "u64" => "1700000000u64".to_string(),
                "i128" => "1_000_000_000i128".to_string(),
                "address" => "recipient_addr.clone()".to_string(),
                _ => format!("/* {} */ vec![]", field.field_type),
            };
            field_assigns.push_str(&format!(
                "        // {}: {}\n",
                field.name, field.field_type
            ));
        }

        format!(
            r#"use anyhow::Result;
use soroban_sas_sdk::client::{{SASClient, AttestationArgs}};
use soroban_sas_sdk::rpc::RpcClient;

#[tokio::main]
async fn main() -> Result<()> {{
    // 1. Initialize RPC client and SAS contract client
    let rpc = RpcClient::new("{rpc_url}".to_string());
    let sas_contract_id = std::env::var("SAS_CONTRACT_ID")?;
    let client = SASClient::new(sas_contract_id);

    // 2. Schema UID: {uid}
    let schema_uid_bytes = hex::decode("{uid}")?;
    let mut schema_uid = [0u8; 32];
    schema_uid.copy_from_slice(&schema_uid_bytes);

    // 3. Prepare attestation payload
    // Schema fields: {raw_schema}
{field_assigns}
    println!("Ready to issue attestation under schema {{}}", hex::encode(schema_uid));
    Ok(())
}}
#"#,
            rpc_url = network.rpc_url,
            uid = uid,
            raw_schema = schema.raw_schema,
            field_assigns = field_assigns
        )
    }

    /// Generates a TypeScript integration snippet.
    pub fn typescript_example(schema: &SchemaDocItem, network: &NetworkConfig) -> String {
        let uid = &schema.uid;
        let mut field_obj = String::new();

        for field in &schema.fields {
            let sample_val = match field.field_type.to_lowercase().as_str() {
                "string" => format!("\"sample_{}\"", field.name),
                "bool" => "true".to_string(),
                "u32" | "u64" => "42".to_string(),
                "i128" => "1000000n".to_string(),
                "address" => {
                    "\"GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5\"".to_string()
                }
                _ => "\"0x00\"".to_string(),
            };
            field_obj.push_str(&format!(
                "    {}: {}, // {}\n",
                field.name, sample_val, field.field_type
            ));
        }

        format!(
            r#"import {{ SorobanSASClient, Network }} from "@soroban-eas/sas-sdk";

async function issueAttestation() {{
  const client = new SorobanSASClient({{
    rpcUrl: "{rpc_url}",
    networkPassphrase: "{passphrase}",
    sasContractId: process.env.SAS_CONTRACT_ID!,
  }});

  // Schema UID
  const schemaUid = "{uid}";

  // Structured payload matching schema: {raw_schema}
  const attestationData = {{
{field_obj}  }};

  console.log("Submitting attestation for schema:", schemaUid);
  // const txResult = await client.attest({{
  //   schemaUid,
  //   recipient: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
  //   data: attestationData,
  // }});
}}

issueAttestation().catch(console.error);
"#,
            rpc_url = network.rpc_url,
            passphrase = network.network_passphrase,
            uid = uid,
            raw_schema = schema.raw_schema,
            field_obj = field_obj
        )
    }

    /// Generates a cURL JSON-RPC query example.
    pub fn curl_example(schema: &SchemaDocItem, network: &NetworkConfig) -> String {
        let uid = &schema.uid;
        format!(
            r#"# Query schema details on-chain via Soroban RPC simulateTransaction
curl -X POST "{rpc_url}" \
  -H "Content-Type: application/json" \
  -d '{{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "simulateTransaction",
    "params": {{
      "transaction": "AAAAAgAAAAD... (XDR calling get_schema with UID {uid})",
      "resourceConfig": {{ "instructionLeeway": 10000 }}
    }}
  }}'

# Query schema events by UID topic
curl -X POST "{rpc_url}" \
  -H "Content-Type: application/json" \
  -d '{{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getEvents",
    "params": {{
      "startLedger": 1000,
      "filters": [
        {{
          "type": "contract",
          "topics": [["REGISTER", "{uid}"]]
        }}
      ]
    }}
  }}'
"#,
            rpc_url = network.rpc_url,
            uid = uid
        )
    }
}
