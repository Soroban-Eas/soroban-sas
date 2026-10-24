//! Multi-signature Soroban authorization envelope assembler and tree builder (issue #554).

use soroban_sdk::xdr::{
    BytesM, Hash, InvokeContractArgs, ScAddress, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, StringM, VecM,
};

use crate::errors::SdkError;

/// The supported cryptographic algorithm/curve for a signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerKind {
    /// Ed25519 signature (64 bytes).
    Ed25519,
    /// Secp256k1 ECDSA signature (64 bytes compact r||s or 65 bytes r||s||v).
    Secp256k1,
}

/// A signature collected from a participant for multi-sig authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectedSignature {
    pub signer_kind: SignerKind,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub weight: u32,
}

impl CollectedSignature {
    /// Validates signature length according to its signer kind.
    pub fn validate(&self) -> Result<(), SdkError> {
        match self.signer_kind {
            SignerKind::Ed25519 => {
                if self.public_key.len() != 32 {
                    return Err(SdkError::ValidationError(format!(
                        "Ed25519 public key must be 32 bytes, got {}",
                        self.public_key.len()
                    )));
                }
                if self.signature.len() != 64 {
                    return Err(SdkError::ValidationError(format!(
                        "Ed25519 signature must be 64 bytes, got {}",
                        self.signature.len()
                    )));
                }
            }
            SignerKind::Secp256k1 => {
                if self.public_key.len() != 33 && self.public_key.len() != 65 {
                    return Err(SdkError::ValidationError(format!(
                        "Secp256k1 public key must be 33 (compressed) or 65 (uncompressed) bytes, got {}",
                        self.public_key.len()
                    )));
                }
                if self.signature.len() != 64 && self.signature.len() != 65 {
                    return Err(SdkError::ValidationError(format!(
                        "Secp256k1 signature must be 64 or 65 bytes, got {}",
                        self.signature.len()
                    )));
                }
            }
        }
        if self.weight == 0 {
            return Err(SdkError::ValidationError(
                "signature weight must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Builder for Soroban authorization entries and multi-signature trees.
#[derive(Clone, Debug)]
pub struct AuthEntryBuilder {
    address: Option<ScAddress>,
    nonce: i64,
    signature_expiration_ledger: u32,
    root_invocation: Option<SorobanAuthorizedInvocation>,
    sub_invocations: Vec<SorobanAuthorizedInvocation>,
    signatures: Vec<CollectedSignature>,
    threshold: u32,
}

impl Default for AuthEntryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthEntryBuilder {
    /// Creates a new, empty `AuthEntryBuilder`.
    pub fn new() -> Self {
        Self {
            address: None,
            nonce: 0,
            signature_expiration_ledger: 0,
            root_invocation: None,
            sub_invocations: Vec::new(),
            signatures: Vec::new(),
            threshold: 0,
        }
    }

    /// Sets the target address credentials from an [`ScAddress`].
    pub fn with_address(mut self, address: ScAddress) -> Self {
        self.address = Some(address);
        self
    }

    /// Sets the target address credentials from a Stellar strkey (`G...` account or `C...` contract).
    pub fn with_address_strkey(mut self, address: &str) -> Result<Self, SdkError> {
        if let Ok(account) = stellar_strkey::ed25519::PublicKey::from_string(address) {
            self.address = Some(ScAddress::Account(soroban_sdk::xdr::AccountId(
                soroban_sdk::xdr::PublicKey::PublicKeyTypeEd25519(soroban_sdk::xdr::Uint256(
                    account.0,
                )),
            )));
            Ok(self)
        } else if let Ok(contract) = stellar_strkey::Contract::from_string(address) {
            self.address = Some(ScAddress::Contract(Hash(contract.0)));
            Ok(self)
        } else {
            Err(SdkError::ValidationError(format!(
                "invalid address strkey: {address}"
            )))
        }
    }

    /// Sets the nonce for address credentials.
    pub fn with_nonce(mut self, nonce: i64) -> Self {
        self.nonce = nonce;
        self
    }

    /// Sets the expiration ledger for the authorization.
    pub fn with_signature_expiration_ledger(mut self, ledger: u32) -> Self {
        self.signature_expiration_ledger = ledger;
        self
    }

    /// Sets the required signature threshold (total required weight).
    pub fn with_threshold(mut self, threshold: u32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Sets the root contract invocation.
    pub fn with_root_invocation(
        mut self,
        contract_id: &str,
        function_name: &str,
        args: Vec<ScVal>,
    ) -> Result<Self, SdkError> {
        let contract = stellar_strkey::Contract::from_string(contract_id).map_err(|e| {
            SdkError::DecodingError(format!("invalid contract id {contract_id}: {e:?}"))
        })?;

        let function_name = ScSymbol(
            StringM::try_from(function_name.as_bytes().to_vec())
                .map_err(|e| SdkError::RpcError(format!("invalid function name: {e:?}")))?,
        );

        let args: VecM<ScVal> = args
            .try_into()
            .map_err(|e| SdkError::RpcError(format!("too many arguments: {e:?}")))?;

        let function = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(Hash(contract.0)),
            function_name,
            args,
        });

        self.root_invocation = Some(SorobanAuthorizedInvocation {
            function,
            sub_invocations: VecM::default(),
        });
        Ok(self)
    }

    /// Directly sets the root invocation.
    pub fn with_authorized_invocation(mut self, invocation: SorobanAuthorizedInvocation) -> Self {
        self.root_invocation = Some(invocation);
        self
    }

    /// Appends a sub-invocation to the root invocation tree.
    pub fn add_sub_invocation(mut self, sub_invocation: SorobanAuthorizedInvocation) -> Self {
        self.sub_invocations.push(sub_invocation);
        self
    }

    /// Adds an Ed25519 signature (weight = 1).
    pub fn add_ed25519_signature(
        self,
        public_key: &[u8; 32],
        signature: &[u8],
    ) -> Result<Self, SdkError> {
        self.add_ed25519_signature_with_weight(public_key, signature, 1)
    }

    /// Adds an Ed25519 signature with explicit weight.
    pub fn add_ed25519_signature_with_weight(
        mut self,
        public_key: &[u8; 32],
        signature: &[u8],
        weight: u32,
    ) -> Result<Self, SdkError> {
        let sig = CollectedSignature {
            signer_kind: SignerKind::Ed25519,
            public_key: public_key.to_vec(),
            signature: signature.to_vec(),
            weight,
        };
        sig.validate()?;
        self.signatures.push(sig);
        Ok(self)
    }

    /// Adds a Secp256k1 signature (weight = 1).
    pub fn add_secp256k1_signature(
        self,
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<Self, SdkError> {
        self.add_secp256k1_signature_with_weight(public_key, signature, 1)
    }

    /// Adds a Secp256k1 signature with explicit weight.
    pub fn add_secp256k1_signature_with_weight(
        mut self,
        public_key: &[u8],
        signature: &[u8],
        weight: u32,
    ) -> Result<Self, SdkError> {
        let sig = CollectedSignature {
            signer_kind: SignerKind::Secp256k1,
            public_key: public_key.to_vec(),
            signature: signature.to_vec(),
            weight,
        };
        sig.validate()?;
        self.signatures.push(sig);
        Ok(self)
    }

    /// Adds an arbitrary pre-constructed [`CollectedSignature`].
    pub fn add_signature(mut self, sig: CollectedSignature) -> Result<Self, SdkError> {
        sig.validate()?;
        self.signatures.push(sig);
        Ok(self)
    }

    /// Returns the total weight of all collected signatures.
    pub fn total_weight(&self) -> u32 {
        self.signatures.iter().map(|s| s.weight).sum()
    }

    /// Validates the builder state before assembly.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.address.is_none() {
            return Err(SdkError::ValidationError(
                "missing address credentials".to_string(),
            ));
        }
        if self.root_invocation.is_none() {
            return Err(SdkError::ValidationError(
                "missing root invocation".to_string(),
            ));
        }

        for sig in &self.signatures {
            sig.validate()?;
        }

        if self.threshold > 0 {
            let total = self.total_weight();
            if total < self.threshold {
                return Err(SdkError::ValidationError(format!(
                    "insufficient signatures: collected weight {total} is below required threshold {}",
                    self.threshold
                )));
            }
        }

        Ok(())
    }

    /// Assembles the collected signatures into a single [`ScVal`].
    /// For 1 signature, wraps as `ScVal::Bytes`.
    /// For multi-signature, assembles into a vector of signature payloads.
    fn assemble_signature_scval(&self) -> Result<ScVal, SdkError> {
        if self.signatures.is_empty() {
            return Ok(ScVal::Void);
        }

        if self.signatures.len() == 1 {
            let sig = &self.signatures[0];
            let bytes = BytesM::try_from(sig.signature.clone())
                .map_err(|e| SdkError::DecodingError(format!("signature bytes overflow: {e:?}")))?;
            return Ok(ScVal::Bytes(soroban_sdk::xdr::ScBytes(bytes)));
        }

        let mut sig_vals = Vec::new();
        for sig in &self.signatures {
            let sig_bytes = BytesM::try_from(sig.signature.clone())
                .map_err(|e| SdkError::DecodingError(format!("signature bytes overflow: {e:?}")))?;
            let pk_bytes = BytesM::try_from(sig.public_key.clone()).map_err(|e| {
                SdkError::DecodingError(format!("public key bytes overflow: {e:?}"))
            })?;

            let entry = ScVal::Vec(Some(
                vec![
                    ScVal::Bytes(soroban_sdk::xdr::ScBytes(pk_bytes)),
                    ScVal::Bytes(soroban_sdk::xdr::ScBytes(sig_bytes)),
                ]
                .try_into()
                .map_err(|e| {
                    SdkError::DecodingError(format!("failed to encode sig entry: {e:?}"))
                })?,
            ));
            sig_vals.push(entry);
        }

        let sc_vec: VecM<ScVal> = sig_vals
            .try_into()
            .map_err(|e| SdkError::DecodingError(format!("too many signatures: {e:?}")))?;
        Ok(ScVal::Vec(Some(sc_vec.into())))
    }

    /// Builds the [`SorobanAuthorizationEntry`].
    pub fn build(mut self) -> Result<SorobanAuthorizationEntry, SdkError> {
        self.validate()?;

        let sig_scval = self.assemble_signature_scval()?;
        let address = self.address.take().expect("validated above");

        let credentials = SorobanCredentials::Address(SorobanAddressCredentials {
            address,
            nonce: self.nonce,
            signature_expiration_ledger: self.signature_expiration_ledger,
            signature: sig_scval,
        });

        let mut root_invocation = self.root_invocation.take().expect("validated above");
        if !self.sub_invocations.is_empty() {
            let mut all_subs = root_invocation.sub_invocations.to_vec();
            all_subs.extend(self.sub_invocations);
            root_invocation.sub_invocations = all_subs
                .try_into()
                .map_err(|e| SdkError::RpcError(format!("too many sub-invocations: {e:?}")))?;
        }

        Ok(SorobanAuthorizationEntry {
            credentials,
            root_invocation,
        })
    }

    /// Sorts a slice of [`SorobanAuthorizationEntry`] into the canonical order required by the Soroban host.
    pub fn canonical_sort(entries: &mut [SorobanAuthorizationEntry]) {
        entries.sort();
    }

    /// Checks whether a slice of [`SorobanAuthorizationEntry`] is canonically sorted.
    pub fn is_canonically_sorted(entries: &[SorobanAuthorizationEntry]) -> bool {
        entries.windows(2).all(|w| w[0] <= w[1])
    }

    /// Validates that a slice of [`SorobanAuthorizationEntry`] is strictly in canonical order.
    pub fn validate_canonical_order(entries: &[SorobanAuthorizationEntry]) -> Result<(), SdkError> {
        if !Self::is_canonically_sorted(entries) {
            return Err(SdkError::ValidationError(
                "authorization entries are not in canonical order".to_string(),
            ));
        }
        Ok(())
    }

    /// Assembles, sorts canonically, and validates a set of authorization entries into a `VecM`.
    pub fn assemble_entries(
        mut entries: Vec<SorobanAuthorizationEntry>,
    ) -> Result<VecM<SorobanAuthorizationEntry>, SdkError> {
        Self::canonical_sort(&mut entries);
        Self::validate_canonical_order(&entries)?;
        entries
            .try_into()
            .map_err(|e| SdkError::RpcError(format!("too many authorization entries: {e:?}")))
    }
}
