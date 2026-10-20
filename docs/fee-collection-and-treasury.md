# Fee Collection and Treasury Mechanics

This document provides a comprehensive operational and technical specification for fee collection, treasury routing, and token withdrawal mechanics within the Soroban Attestation Service (SAS) protocol suite, including both the core SAS contract (`contracts/sas`) and the Schema Registry (`contracts/schema-registry`).

---

## 1. Architectural Overview

The protocol charges fees for specific state-creating operations to protect network resources, align incentives, and fund community initiatives or protocol operations:

- **Attestation Fees (`contracts/sas`):** Optional fee levied upon issuing an attestation via `attest_with_value`.
- **Schema Registration Fees (`contracts/schema-registry`):** Optional fee levied upon registering a new attestation schema via `register_with_value`.

The fee mechanics adhere to the following core tenets:
1. **Authenticated On-Chain Configuration:** Callers cannot pick arbitrary tokens or fee amounts. The required token asset and exact amount are configured on-chain by the contract administrator.
2. **Exact Payment Enforcement:** Transactions supplying incorrect token addresses, underpaying, or submitting non-zero fees to fee-free contracts fail atomically before state changes or storage writes occur.
3. **Dedicated Treasury Routing:** Fees are either held in the contract balance or directly routed to a designated `treasury` account, decoupled from administrative privileges.

```
+-----------------------------------------------------------------------------------+
|                               Fee Configuration Flow                              |
+-----------------------------------------------------------------------------------+
       Admin (require_auth)
          |
          +---> set_fee(token, amount)      ---> writes FEE_CONFIG / emits FeeConfigUpdated
          +---> clear_fee()                 ---> removes FEE_CONFIG / emits FeeConfigUpdated
          +---> set_treasury(treasury_addr) ---> writes TREASURY / emits TreasuryUpdated

+-----------------------------------------------------------------------------------+
|                             Attestation Payment Flow                              |
+-----------------------------------------------------------------------------------+
       Attester (require_auth)
          |
          v
  attest_with_value(attestation, token, value)
          |
          +---> Verify contract is NOT paused (SASError::ContractPaused)
          +---> Read FEE_CONFIG:
          |        - If Some(fee_token, fee_amount): require token == fee_token && value == fee_amount
          |        - If None: require value == 0
          |        (On mismatch -> fail with SASError::FeeMismatch)
          +---> Transfer token from attester to SAS contract balance
          +---> Proceed with attest_internal and indexer dispatch

+-----------------------------------------------------------------------------------+
|                          Schema Registration Payment Flow                         |
+-----------------------------------------------------------------------------------+
       Schema Owner (require_auth)
          |
          v
  register_with_value(owner, schema, resolver, revocable, token, value)
          |
          +---> Read SCHEMA_FEE:
          |        - If Some(fee_token, fee_amount): require token == fee_token && value == fee_amount
          |        - If None: require value == 0
          +---> Read TREASURY:
          |        - If None and value > 0: fail with SASError::TreasuryNotSet
          +---> Transfer token from owner directly to treasury address
          +---> Validate schema syntax and register schema
```

---

## 2. Protocol Fee Configuration

Both the SAS contract and the Schema Registry provide administrative entrypoints to configure or clear fees.

### 2.1 Setting Fees
- **SAS Entrypoint:** `set_fee(env: Env, token: Address, amount: i128)`
- **Schema Registry Entrypoint:** `set_fee(env: Env, token: Address, amount: i128)`
- **Authorization:** Requires the current contract administrator's signature (`admin.require_auth()`).
- **Validation:** `amount` must be strictly positive (`amount > 0`). Attempts to set `amount <= 0` abort with `SASError::InvalidValue`.
- **Storage:** Persisted under instance storage key `FEE_CONFIG` (SAS) or `SCHEMA_FEE` (Schema Registry).
- **TTL:** The contract instance TTL is automatically extended upon configuration.

### 2.2 Clearing Fees (Fee-Free Mode)
- **SAS Entrypoint:** `clear_fee(env: Env)`
- **Schema Registry Entrypoint:** `clear_fee(env: Env)`
- **Authorization:** Requires administrator authorization.
- **Behavior:** Removes the fee configuration key from instance storage. Once cleared, `attest_with_value` and `register_with_value` accept only `value == 0`. Supplying any `value > 0` aborts with `SASError::FeeMismatch`.

### 2.3 Inspecting Fee Configuration
- **SAS Entrypoint:** `get_fee(env: Env) -> Option<(Address, i128)>`
- **Schema Registry Entrypoint:** `get_fee(env: Env) -> Option<(Address, i128)>`
- **Return Value:** Returns `Some((token_address, amount))` if fees are currently required, or `None` if the contract is fee-free.
- **SDK Helper:** `SASClient::fetch_fee` provides client applications with pre-flight fee queries to display accurate payment prompts to end-users before signing.

---

## 3. Treasury Mechanics and Direct Routing

The protocol maintains a dedicated `treasury` address that receives protocol revenue and manages withdrawals.

### 3.1 Schema Registry Treasury Routing
In `schema-registry`, fees collected during schema creation are routed immediately to the configured `treasury` address:
1. `set_treasury(env: Env, treasury: Address)` pins the recipient address in instance storage (`TREASURY`) and emits `TreasuryUpdated`.
2. When `register_with_value` is called with `value > 0`, it loads `TREASURY`. If no treasury is set, execution halts immediately with `SASError::TreasuryNotSet`.
3. The Soroban token client transfers `value` directly from `owner` to `treasury`.

### 3.2 SAS Treasury and Token Custody
In `sas`, collected attestation fees are held in the contract's custodial balance until withdrawn by authorized entities:
1. `set_treasury(env: Env, treasury: Address)` configures the designated treasury account.
2. `get_treasury(env: Env) -> Option<Address>` queries the configured treasury address.
3. Attestation payments transfer tokens from the attester into `env.current_contract_address()`.

---

## 4. Withdrawal Mechanics

To safely disburse accrued fees and tokens from contract custody, the SAS contract exposes `withdraw_tokens`:

```rust
pub fn withdraw_tokens(
    env: Env,
    authorizer: Address,
    token: Address,
    amount: i128,
    destination: Address,
)
```

### 4.1 Authorization Matrix
A withdrawal invocation requires `authorizer.require_auth()`. The `authorizer` must match either:
- The contract **Administrator** (`admin`), OR
- The designated **Treasury** (`treasury`).

Any other caller attempting withdrawal is rejected immediately with `SASError::Unauthorized`.

### 4.2 Balance and Parameter Checks
- `amount` must be greater than zero (`amount > 0`). Negative or zero amounts abort with `SASError::InvalidValue`.
- The contract queries the token client balance: `balance(&env.current_contract_address())`. If `balance < amount`, the transaction fails with `SASError::InvalidValue` without initiating a token transfer.

### 4.3 Transfer and Event Publishing
Upon successful validation:
1. The contract transfers `amount` of `token` from `env.current_contract_address()` to `destination`.
2. An event is emitted:
   - **Topics:** `(Symbol::new(&env, "withdraw"), authorizer, token)`
   - **Data:** `(destination, amount)`
3. Contract instance TTL is refreshed.

---

## 5. Event Audit Log

Every fee configuration update, treasury rotation, and withdrawal emits structured Soroban events for real-time indexing and observability:

| Event Topic | Emitter | Payload Fields | Purpose |
| :--- | :--- | :--- | :--- |
| `("fee_updated", admin)` | SAS & Registry | `old_fee: Option<(Address, i128)>`, `new_fee: Option<(Address, i128)>`, `authorizer: Address` | Tracks fee asset and price alterations |
| `("treasury_updated", admin)` | SAS & Registry | `old_treasury: Option<Address>`, `new_treasury: Address`, `authorizer: Address` | Tracks treasury address changes |
| `("withdraw", authorizer, token)` | SAS | `destination: Address`, `amount: i128` | Tracks protocol fee disbursements and outflows |

---

## 6. CLI and SDK Operational Runbook

### 6.1 Setting Protocol Fees (CLI)
Using `stellar-cli`:
```bash
# Configure SAS fee: 100 stroops (0.0000100 XLM)
stellar contract invoke \
  --id <SAS_CONTRACT_ID> \
  --source admin-key \
  --network testnet \
  -- \
  set_fee \
  --token <XLM_TOKEN_ADDRESS> \
  --amount 100

# Configure Schema Registry fee
stellar contract invoke \
  --id <REGISTRY_CONTRACT_ID> \
  --source admin-key \
  --network testnet \
  -- \
  set_fee \
  --token <XLM_TOKEN_ADDRESS> \
  --amount 500
```

### 6.2 Setting Treasury (CLI)
```bash
stellar contract invoke \
  --id <SAS_CONTRACT_ID> \
  --source admin-key \
  --network testnet \
  -- \
  set_treasury \
  --treasury <TREASURY_ACCOUNT_ADDRESS>
```

### 6.3 Withdrawing Accrued Fees (CLI)
```bash
stellar contract invoke \
  --id <SAS_CONTRACT_ID> \
  --source treasury-key \
  --network testnet \
  -- \
  withdraw_tokens \
  --authorizer <TREASURY_ACCOUNT_ADDRESS> \
  --token <XLM_TOKEN_ADDRESS> \
  --amount 10000 \
  --destination <COLD_STORAGE_ADDRESS>
```

---

## 7. Security Best Practices

1. **Multi-Sig Treasury:** The `treasury` account should ideally be configured as a multi-signature account or Stellar multisig smart wallet to prevent single-key compromise from draining protocol funds.
2. **Pre-flight Invariant Checks:** Frontends and integrators should call `get_fee()` and `get_treasury()` immediately prior to crafting transactions to avoid unexpected `FeeMismatch` or `TreasuryNotSet` errors resulting from administrative updates.
3. **Exact Token Matching:** Never attempt to call `attest_with_value` with arbitrary token addresses or guessed fee amounts; queries must always be pinned against authoritative contract state.
