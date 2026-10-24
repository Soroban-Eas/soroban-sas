use super::*;
use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::TryFromVal;

#[contracttype]
#[derive(Clone)]
struct ApprovalKey {
    destination: Address,
    source_chain: String,
    message_id: String,
    source_address: String,
    payload_hash: BytesN<32>,
}

#[contract]
struct MockGateway;

#[contractimpl]
impl MockGateway {
    pub fn approve(
        env: Env,
        destination: Address,
        source_chain: String,
        message_id: String,
        source_address: String,
        payload_hash: BytesN<32>,
    ) {
        env.storage().instance().set(
            &ApprovalKey {
                destination,
                source_chain,
                message_id,
                source_address,
                payload_hash,
            },
            &true,
        );
    }

    pub fn validate_message(
        env: Env,
        destination: Address,
        source_chain: String,
        message_id: String,
        source_address: String,
        payload_hash: BytesN<32>,
    ) -> bool {
        let key = ApprovalKey {
            destination,
            source_chain,
            message_id,
            source_address,
            payload_hash,
        };
        if !env.storage().instance().has(&key) {
            return false;
        }
        env.storage().instance().remove(&key);
        true
    }
}

struct Fixture {
    env: Env,
    verifier: CrossChainVerifierClient<'static>,
    gateway: MockGatewayClient<'static>,
    verifier_id: Address,
    admin: Address,
    source_chain: String,
    source_address: String,
    lz_endpoint: Address,
    lz_src_eid: u32,
    lz_sender: BytesN<32>,
}

impl Fixture {
    fn new() -> Self {
        let mut env = Env::default();
        env.set_config(soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.mock_all_auths();
        let gateway_id = env.register_contract(None, MockGateway);
        let verifier_id = env.register_contract(None, CrossChainVerifier);
        let gateway = MockGatewayClient::new(&env, &gateway_id);
        let verifier = CrossChainVerifierClient::new(&env, &verifier_id);
        let admin = Address::generate(&env);
        let source_chain = String::from_str(&env, "Ethereum");
        let source_address = String::from_str(&env, "0x1234");
        verifier.init(&admin, &gateway_id, &source_chain, &source_address);
        let lz_endpoint = Address::generate(&env);
        let lz_src_eid = 30101u32;
        let lz_sender = BytesN::from_array(&env, &[0x42u8; 32]);
        verifier.set_lz_config(&admin, &lz_endpoint, &lz_src_eid, &lz_sender);
        Self {
            env,
            verifier,
            gateway,
            verifier_id,
            admin,
            source_chain,
            source_address,
            lz_endpoint,
            lz_src_eid,
            lz_sender,
        }
    }

    fn uid(&self) -> UID {
        UID(BytesN::from_array(&self.env, &[7; 32]))
    }

    fn payload(&self, revision: u64, valid_until: u64, valid: bool) -> Bytes {
        let mut raw = [0u8; STATUS_PAYLOAD_LEN as usize];
        raw[0] = 1;
        raw[1..33].copy_from_slice(&[7; 32]);
        raw[33..41].copy_from_slice(&revision.to_be_bytes());
        raw[41..49].copy_from_slice(&valid_until.to_be_bytes());
        raw[49] = u8::from(valid);
        Bytes::from_slice(&self.env, &raw)
    }

    fn approve(&self, message_id: &String, payload: &Bytes) {
        self.gateway.approve(
            &self.verifier_id,
            &self.source_chain,
            message_id,
            &self.source_address,
            &self.env.crypto().keccak256(payload).into(),
        );
    }

    fn execute(&self, message_id: &String, payload: &Bytes) -> RemoteAttestation {
        self.verifier.execute(
            &self.source_chain,
            message_id,
            &self.source_address,
            payload,
        )
    }
}

#[test]
fn v2_proof_decodes_evm_fields_and_stellar_recipient() {
    let mut f = Fixture::new();
    f.env.set_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let recipient = Address::generate(&f.env);
    let mut strkey = [0u8; 56];
    recipient.to_string().copy_into_slice(&mut strkey);
    let data = [0xde, 0xad, 0xbe, 0xef];
    let mut raw = [0u8; PROOF_PAYLOAD_HEADER_LEN as usize + 4];
    let status = f.payload(1, f.env.ledger().timestamp() + 100, true);
    status.copy_into_slice(&mut raw[..STATUS_PAYLOAD_LEN as usize]);
    raw[0] = 2;
    raw[50..82].copy_from_slice(&[9; 32]);
    raw[82..102].copy_from_slice(&[8; 20]);
    raw[102..158].copy_from_slice(&strkey);
    raw[158..160].copy_from_slice(&(data.len() as u16).to_be_bytes());
    raw[160..].copy_from_slice(&data);
    let payload = Bytes::from_slice(&f.env, &raw);
    let id = String::from_str(&f.env, "proof-1");
    assert!(f
        .verifier
        .try_execute(&f.source_chain, &id, &f.source_address, &payload)
        .is_err());
    f.approve(&id, &payload);
    let mut forged = raw;
    forged[82] ^= 1;
    assert_eq!(
        f.verifier.try_execute(
            &f.source_chain,
            &id,
            &f.source_address,
            &Bytes::from_slice(&f.env, &forged)
        ),
        Err(Ok(CrossChainError::MessageNotApproved))
    );
    f.execute(&id, &payload);
    let proof = f.verifier.get_proof(&f.uid()).unwrap();
    assert_eq!(proof.schema_uid, UID(BytesN::from_array(&f.env, &[9; 32])));
    assert_eq!(proof.evm_recipient, BytesN::from_array(&f.env, &[8; 20]));
    assert_eq!(proof.recipient, recipient);
    assert_eq!(proof.data, Bytes::from_slice(&f.env, &data));
    let mut bad = raw;
    bad[159] = 5;
    let bad_payload = Bytes::from_slice(&f.env, &bad);
    assert_eq!(
        f.verifier.try_execute(
            &f.source_chain,
            &String::from_str(&f.env, "bad"),
            &f.source_address,
            &bad_payload
        ),
        Err(Ok(CrossChainError::InvalidPayload))
    );
    let legacy = f.payload(2, f.env.ledger().timestamp() + 100, true);
    let legacy_id = String::from_str(&f.env, "legacy-2");
    f.approve(&legacy_id, &legacy);
    f.execute(&legacy_id, &legacy);
    assert_eq!(f.verifier.get_proof(&f.uid()), None);
}

#[test]
fn accepts_gateway_approved_message_and_rejects_replay() {
    let f = Fixture::new();
    let id = String::from_str(&f.env, "tx-1");
    let payload = f.payload(1, f.env.ledger().timestamp() + 100, true);
    f.approve(&id, &payload);
    let status = f.execute(&id, &payload);
    assert_eq!(status.uid, f.uid());
    assert_eq!(status.revision, 1);
    assert!(f.verifier.verify_remote(&f.uid()));
    assert_eq!(f.verifier.get_status(&f.uid()), Some(status));
    let events = f.env.events().all();
    let (_, _, event_data) = events.last().unwrap();
    let audit = RemoteAttestationUpdated::try_from_val(&f.env, &event_data).unwrap();
    assert_eq!(audit.message_id, id);
    assert_eq!(audit.status.uid, f.uid());
    assert_eq!(
        f.verifier
            .try_execute(&f.source_chain, &id, &f.source_address, &payload),
        Err(Ok(CrossChainError::StaleRevision)),
    );
}

#[test]
fn rejects_unapproved_tampered_or_wrong_destination_messages() {
    let f = Fixture::new();
    let id = String::from_str(&f.env, "tx-2");
    let payload = f.payload(1, f.env.ledger().timestamp() + 100, true);
    let tampered = f.payload(2, f.env.ledger().timestamp() + 100, true);
    assert_eq!(
        f.verifier
            .try_execute(&f.source_chain, &id, &f.source_address, &payload),
        Err(Ok(CrossChainError::MessageNotApproved)),
    );
    f.approve(&id, &payload);
    assert_eq!(
        f.verifier
            .try_execute(&f.source_chain, &id, &f.source_address, &tampered),
        Err(Ok(CrossChainError::MessageNotApproved)),
    );
    let other = Address::generate(&f.env);
    let other_id = String::from_str(&f.env, "tx-other");
    f.gateway.approve(
        &other,
        &f.source_chain,
        &other_id,
        &f.source_address,
        &f.env.crypto().keccak256(&payload).into(),
    );
    assert_eq!(
        f.verifier
            .try_execute(&f.source_chain, &other_id, &f.source_address, &payload),
        Err(Ok(CrossChainError::MessageNotApproved)),
    );
    assert!(f.verifier.get_status(&f.uid()).is_none());
    assert!(!f.verifier.verify_remote(&f.uid()));
    // A failed attempt does not consume the genuine approval.
    f.execute(&id, &payload);
    assert!(f.verifier.verify_remote(&f.uid()));
}

#[test]
fn rejects_wrong_source_and_out_of_order_revision() {
    let f = Fixture::new();
    let second_id = String::from_str(&f.env, "tx-new");
    let second = f.payload(2, f.env.ledger().timestamp() + 100, true);
    f.approve(&second_id, &second);
    assert_eq!(
        f.verifier.try_execute(
            &String::from_str(&f.env, "Polygon"),
            &second_id,
            &f.source_address,
            &second,
        ),
        Err(Ok(CrossChainError::WrongSource)),
    );
    assert_eq!(
        f.verifier.try_execute(
            &f.source_chain,
            &second_id,
            &String::from_str(&f.env, "0x9999"),
            &second,
        ),
        Err(Ok(CrossChainError::WrongSource)),
    );
    f.execute(&second_id, &second);
    let old_id = String::from_str(&f.env, "tx-old");
    let old = f.payload(1, f.env.ledger().timestamp() + 100, false);
    f.approve(&old_id, &old);
    assert_eq!(
        f.verifier
            .try_execute(&f.source_chain, &old_id, &f.source_address, &old),
        Err(Ok(CrossChainError::InvalidValidity)),
    );
    let old = f.payload(1, 0, false);
    f.approve(&old_id, &old);
    assert_eq!(
        f.verifier
            .try_execute(&f.source_chain, &old_id, &f.source_address, &old),
        Err(Ok(CrossChainError::StaleRevision)),
    );
    assert_eq!(f.verifier.get_status(&f.uid()).unwrap().revision, 2);
    assert!(f.verifier.verify_remote(&f.uid()));
}

#[test]
fn expiry_and_revocation_fail_closed() {
    let f = Fixture::new();
    let now = f.env.ledger().timestamp();
    let first_id = String::from_str(&f.env, "tx-valid");
    let first = f.payload(1, now + 10, true);
    f.approve(&first_id, &first);
    f.execute(&first_id, &first);
    f.env
        .ledger()
        .with_mut(|ledger| ledger.timestamp = now + 10);
    assert!(!f.verifier.verify_remote(&f.uid()));

    let second_id = String::from_str(&f.env, "tx-invalid");
    let second = f.payload(2, 0, false);
    f.approve(&second_id, &second);
    f.execute(&second_id, &second);
    assert!(!f.verifier.verify_remote(&f.uid()));
    assert_eq!(f.verifier.get_status(&f.uid()).unwrap().revision, 2);
}

#[test]
fn malformed_payload_and_unbounded_validity_are_rejected() {
    let f = Fixture::new();
    let id = String::from_str(&f.env, "bad");
    for payload in [
        Bytes::new(&f.env),
        Bytes::from_slice(&f.env, &[2u8; STATUS_PAYLOAD_LEN as usize]),
    ] {
        assert_eq!(
            f.verifier
                .try_execute(&f.source_chain, &id, &f.source_address, &payload),
            Err(Ok(CrossChainError::InvalidPayload)),
        );
    }
    let too_long = f.payload(
        1,
        f.env.ledger().timestamp() + MAX_VALIDITY_SECONDS + 1,
        true,
    );
    assert_eq!(
        f.verifier
            .try_execute(&f.source_chain, &id, &f.source_address, &too_long),
        Err(Ok(CrossChainError::InvalidValidity)),
    );
    let zero_revision = f.payload(0, f.env.ledger().timestamp() + 10, true);
    assert_eq!(
        f.verifier
            .try_execute(&f.source_chain, &id, &f.source_address, &zero_revision),
        Err(Ok(CrossChainError::InvalidValidity)),
    );
    let mut invalid_flag = [0u8; STATUS_PAYLOAD_LEN as usize];
    invalid_flag[0] = 1;
    invalid_flag[49] = 2;
    assert_eq!(
        f.verifier.try_execute(
            &f.source_chain,
            &id,
            &f.source_address,
            &Bytes::from_slice(&f.env, &invalid_flag),
        ),
        Err(Ok(CrossChainError::InvalidPayload)),
    );
}

#[test]
fn initialization_is_authenticated_immutable_and_rejects_bad_sources() {
    let env = Env::default();
    let verifier_id = env.register_contract(None, CrossChainVerifier);
    let gateway_id = env.register_contract(None, MockGateway);
    let verifier = CrossChainVerifierClient::new(&env, &verifier_id);
    let admin = Address::generate(&env);
    let chain = String::from_str(&env, "Ethereum");
    let source = String::from_str(&env, "0x1234");
    assert_eq!(
        verifier.try_get_source(),
        Err(Ok(CrossChainError::NotInitialized)),
    );
    assert!(verifier
        .try_init(&admin, &gateway_id, &chain, &source)
        .is_err());
    env.mock_all_auths();
    assert_eq!(
        verifier.try_init(&admin, &gateway_id, &chain, &String::from_str(&env, "")),
        Err(Ok(CrossChainError::InvalidConfig)),
    );
    assert_eq!(
        verifier.try_init(&admin, &verifier_id, &chain, &source),
        Err(Ok(CrossChainError::InvalidConfig)),
    );
    verifier.init(&admin, &gateway_id, &chain, &source);
    assert_eq!(verifier.get_source().gateway, gateway_id);
    assert_eq!(
        verifier.try_init(&admin, &gateway_id, &chain, &source),
        Err(Ok(CrossChainError::AlreadyInitialized)),
    );
}

#[test]
fn lz_receive_accepts_valid_packet_and_emits_event() {
    let f = Fixture::new();
    let origin = Origin {
        src_eid: f.lz_src_eid,
        sender: f.lz_sender.clone(),
        nonce: 1,
    };
    let guid = BytesN::from_array(&f.env, &[0x33u8; 32]);
    let payload = f.payload(1, f.env.ledger().timestamp() + 100, true);
    let executor = Address::generate(&f.env);
    let extra = Bytes::new(&f.env);

    let status = f
        .verifier
        .lz_receive(&origin, &guid, &payload, &executor, &extra);
    assert_eq!(status.uid, f.uid());
    assert_eq!(status.revision, 1);
    assert!(status.valid);
    assert!(f.verifier.verify_remote(&f.uid()));
    assert_eq!(f.verifier.get_status(&f.uid()), Some(status.clone()));

    let events = f.env.events().all();
    let (_, _, event_data) = events.last().unwrap();
    let audit = CrossChainAttestationReceived::try_from_val(&f.env, &event_data).unwrap();
    assert_eq!(audit.guid, guid);
    assert_eq!(audit.src_eid, f.lz_src_eid);
    assert_eq!(audit.sender, f.lz_sender);
    assert_eq!(audit.uid, f.uid());
    assert_eq!(audit.revision, 1);
    assert!(audit.valid);
}

#[test]
fn lz_receive_decodes_v2_proof() {
    let f = Fixture::new();
    let recipient = Address::generate(&f.env);
    let mut strkey = [0u8; 56];
    recipient.to_string().copy_into_slice(&mut strkey);
    let data = [0xca, 0xfe, 0xba, 0xbe];
    let mut raw = [0u8; PROOF_PAYLOAD_HEADER_LEN as usize + 4];
    let status = f.payload(1, f.env.ledger().timestamp() + 100, true);
    status.copy_into_slice(&mut raw[..STATUS_PAYLOAD_LEN as usize]);
    raw[0] = 2;
    raw[50..82].copy_from_slice(&[0x11; 32]);
    raw[82..102].copy_from_slice(&[0x22; 20]);
    raw[102..158].copy_from_slice(&strkey);
    raw[158..160].copy_from_slice(&(data.len() as u16).to_be_bytes());
    raw[160..].copy_from_slice(&data);
    let payload = Bytes::from_slice(&f.env, &raw);

    let origin = Origin {
        src_eid: f.lz_src_eid,
        sender: f.lz_sender.clone(),
        nonce: 1,
    };
    let guid = BytesN::from_array(&f.env, &[0x44u8; 32]);
    let executor = Address::generate(&f.env);
    let extra = Bytes::new(&f.env);

    f.verifier
        .lz_receive(&origin, &guid, &payload, &executor, &extra);

    let proof = f.verifier.get_proof(&f.uid()).unwrap();
    assert_eq!(
        proof.schema_uid,
        UID(BytesN::from_array(&f.env, &[0x11; 32]))
    );
    assert_eq!(proof.evm_recipient, BytesN::from_array(&f.env, &[0x22; 20]));
    assert_eq!(proof.recipient, recipient);
    assert_eq!(proof.data, Bytes::from_slice(&f.env, &data));
}

#[test]
fn lz_receive_rejects_unauthorized_endpoint_and_wrong_source() {
    let f = Fixture::new();
    let bad_eid_origin = Origin {
        src_eid: 99999,
        sender: f.lz_sender.clone(),
        nonce: 1,
    };
    let guid = BytesN::from_array(&f.env, &[0x33u8; 32]);
    let payload = f.payload(1, f.env.ledger().timestamp() + 100, true);
    let executor = Address::generate(&f.env);
    let extra = Bytes::new(&f.env);

    assert_eq!(
        f.verifier
            .try_lz_receive(&bad_eid_origin, &guid, &payload, &executor, &extra),
        Err(Ok(CrossChainError::UnauthorizedEndpoint)),
    );

    let bad_sender_origin = Origin {
        src_eid: f.lz_src_eid,
        sender: BytesN::from_array(&f.env, &[0x99u8; 32]),
        nonce: 1,
    };
    assert_eq!(
        f.verifier
            .try_lz_receive(&bad_sender_origin, &guid, &payload, &executor, &extra),
        Err(Ok(CrossChainError::WrongSource)),
    );

    let zero_guid = BytesN::from_array(&f.env, &[0u8; 32]);
    let valid_origin = Origin {
        src_eid: f.lz_src_eid,
        sender: f.lz_sender.clone(),
        nonce: 1,
    };
    assert_eq!(
        f.verifier
            .try_lz_receive(&valid_origin, &zero_guid, &payload, &executor, &extra),
        Err(Ok(CrossChainError::InvalidPayload)),
    );
}

#[test]
fn lz_receive_rejects_stale_revision_and_invalid_validity() {
    let f = Fixture::new();
    let origin = Origin {
        src_eid: f.lz_src_eid,
        sender: f.lz_sender.clone(),
        nonce: 1,
    };
    let guid = BytesN::from_array(&f.env, &[0x33u8; 32]);
    let executor = Address::generate(&f.env);
    let extra = Bytes::new(&f.env);

    // Initial revision 2
    let payload2 = f.payload(2, f.env.ledger().timestamp() + 100, true);
    f.verifier
        .lz_receive(&origin, &guid, &payload2, &executor, &extra);

    // Replay revision 2
    assert_eq!(
        f.verifier
            .try_lz_receive(&origin, &guid, &payload2, &executor, &extra),
        Err(Ok(CrossChainError::StaleRevision)),
    );

    // Downgrade revision 1
    let payload1 = f.payload(1, f.env.ledger().timestamp() + 100, true);
    assert_eq!(
        f.verifier
            .try_lz_receive(&origin, &guid, &payload1, &executor, &extra),
        Err(Ok(CrossChainError::StaleRevision)),
    );

    // Expired timestamp
    let expired = f.payload(3, f.env.ledger().timestamp(), true);
    assert_eq!(
        f.verifier
            .try_lz_receive(&origin, &guid, &expired, &executor, &extra),
        Err(Ok(CrossChainError::InvalidValidity)),
    );
}

#[test]
fn lz_set_config_requires_admin_authorization() {
    let f = Fixture::new();
    let initial_cfg = f.verifier.get_lz_config();
    assert_eq!(initial_cfg.endpoint, f.lz_endpoint);
    assert_eq!(initial_cfg.src_eid, f.lz_src_eid);
    assert_eq!(initial_cfg.sender, f.lz_sender);

    let stranger = Address::generate(&f.env);
    let new_endpoint = Address::generate(&f.env);
    let sender = BytesN::from_array(&f.env, &[0x55u8; 32]);

    assert_eq!(
        f.verifier
            .try_set_lz_config(&stranger, &new_endpoint, &30102, &sender),
        Err(Ok(CrossChainError::UnauthorizedEndpoint)),
    );

    assert_eq!(
        f.verifier
            .try_set_lz_config(&f.admin, &f.verifier_id, &30102, &sender),
        Err(Ok(CrossChainError::InvalidConfig)),
    );

    assert_eq!(
        f.verifier
            .try_set_lz_config(&f.admin, &new_endpoint, &0, &sender),
        Err(Ok(CrossChainError::InvalidConfig)),
    );

    // Authorized admin can update config
    f.verifier
        .set_lz_config(&f.admin, &new_endpoint, &30102, &sender);
    let cfg = f.verifier.get_lz_config();
    assert_eq!(cfg.endpoint, new_endpoint);
    assert_eq!(cfg.src_eid, 30102);
    assert_eq!(cfg.sender, sender);
}

#[test]
fn lz_receive_gas_benchmark() {
    let f = Fixture::new();
    let origin = Origin {
        src_eid: f.lz_src_eid,
        sender: f.lz_sender.clone(),
        nonce: 1,
    };
    let guid = BytesN::from_array(&f.env, &[0x33u8; 32]);
    let payload = f.payload(1, f.env.ledger().timestamp() + 100, true);
    let executor = Address::generate(&f.env);
    let extra = Bytes::new(&f.env);

    // Measure gas for status-only attestation packet
    f.env.budget().reset_unlimited();
    f.verifier
        .lz_receive(&origin, &guid, &payload, &executor, &extra);
    let cpu_status = f.env.budget().cpu_instruction_cost();
    let mem_status = f.env.budget().memory_bytes_cost();

    // Benchmarked status-only receipt:
    // CPU instruction cost: ~200k-500k instructions (well within 100M limit)
    // Memory byte cost: ~50k-150k bytes (well within 40MB limit)
    assert!(
        cpu_status < 1_000_000,
        "CPU status cost {cpu_status} exceeds 1M"
    );
    assert!(
        mem_status < 500_000,
        "Memory status cost {mem_status} exceeds 500k"
    );

    // Measure gas for full V2 proof attestation packet
    let recipient = Address::generate(&f.env);
    let mut strkey = [0u8; 56];
    recipient.to_string().copy_into_slice(&mut strkey);
    let data = [0xde, 0xad, 0xbe, 0xef];
    let mut raw = [0u8; PROOF_PAYLOAD_HEADER_LEN as usize + 4];
    let status2 = f.payload(2, f.env.ledger().timestamp() + 100, true);
    status2.copy_into_slice(&mut raw[..STATUS_PAYLOAD_LEN as usize]);
    raw[0] = 2;
    raw[50..82].copy_from_slice(&[0x11; 32]);
    raw[82..102].copy_from_slice(&[0x22; 20]);
    raw[102..158].copy_from_slice(&strkey);
    raw[158..160].copy_from_slice(&(data.len() as u16).to_be_bytes());
    raw[160..].copy_from_slice(&data);
    let proof_payload = Bytes::from_slice(&f.env, &raw);

    f.env.budget().reset_unlimited();
    f.verifier
        .lz_receive(&origin, &guid, &proof_payload, &executor, &extra);
    let cpu_proof = f.env.budget().cpu_instruction_cost();
    let mem_proof = f.env.budget().memory_bytes_cost();

    // Benchmarked proof-bearing receipt:
    // CPU instruction cost: ~300k-700k instructions
    // Memory byte cost: ~70k-200k bytes
    assert!(
        cpu_proof < 1_500_000,
        "CPU proof cost {cpu_proof} exceeds 1.5M"
    );
    assert!(
        mem_proof < 600_000,
        "Memory proof cost {mem_proof} exceeds 600k"
    );
}
