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
    source_chain: String,
    source_address: String,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        let gateway_id = env.register_contract(None, MockGateway);
        let verifier_id = env.register_contract(None, CrossChainVerifier);
        let gateway = MockGatewayClient::new(&env, &gateway_id);
        let verifier = CrossChainVerifierClient::new(&env, &verifier_id);
        let source_chain = String::from_str(&env, "Ethereum");
        let source_address = String::from_str(&env, "0x1234");
        verifier.init(
            &Address::generate(&env),
            &gateway_id,
            &source_chain,
            &source_address,
        );
        Self {
            env,
            verifier,
            gateway,
            verifier_id,
            source_chain,
            source_address,
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
