# Schema Lookup Integration Guide

This guide explains how to integrate with the SAS Schema Registry using the Indexer contract to look up and validate schemas.

## Overview

The Soroban Attestation Service (SAS) stores attestation schemas in a Schema Registry contract. The Indexer contract provides efficient query capabilities to look up schemas and their associated attestations. This guide walks through the integration process.

## Schema Registry Contract

The Schema Registry stores schema definitions and maintains their metadata. Each schema has:
- A unique identifier (UID)
- A resolver address (who can update it)
- Context data (metadata about the schema)
- Creation and update timestamps

Two read paths exist for a schema:

| Call | Keyed by | Use when |
| --- | --- | --- |
| `get_schema(uid)` | 32-byte content-addressed `schema_uid` | You already hold the UID (for example, from an attestation). |
| `get_schema_by_content(schema, resolver, revocable)` | The raw definition | You hold the definition and want to avoid re-deriving the UID off-chain. |

`get_schema_by_content` re-derives the UID inside the contract with the same
canonical rules `register` uses — see
[Schema Definitions and Payloads](schemas.md#looking-up-a-schema-by-content) —
so an off-chain byte-encoding mismatch cannot make a registered schema look
missing. It returns `None` for unregistered or deprecated content, and reverts
with `SASError::InvalidSchema` for a malformed schema string.

## Indexer Contract Integration

The Indexer contract maintains indices of attestations organized by:
- **Recipient**: Attestations issued to a specific address
- **Schema**: Attestations for a specific schema UID
- **Attester**: Attestations issued by a specific address

### Query Functions

#### Getting Schema-based Attestations

```rust
// Get all attestations for a schema (active only)
let attestations = indexer_client.get_schema_filtered(
    schema_uid,
    false  // false = active only, true = include revoked
);

// Get one page of a schema's complete history (oldest first)
let attestations = indexer_client.get_atts_by_schema_paginated(
    schema_uid,
    cursor,   // zero-based position to start at
    limit     // maximum number of results
);
```

#### Filtering Attestations

The indexer supports two modes for queries:
- **Active Only** (`include_revoked = false`): Returns only active attestations
- **Historical** (`include_revoked = true`): Returns all attestations including revoked and replaced ones

Replaced attestations remain marked as `Active` but their predecessors become `Replaced`.

#### Status Tracking

Each attestation in the indexer has a status:
```rust
pub enum IndexStatus {
    Active,    // Currently valid
    Revoked,   // Has been revoked
    Replaced,  // Has been superseded by another
}
```

## Integration Steps

### 1. Initialize Contracts

First, ensure both the SAS contract and Indexer are initialized with references to each other:

```rust
// Initialize SAS contract with indexer reference
sas.init(admin, schema_registry, indexer_address);

// Initialize Indexer with SAS reference
indexer.init(indexer_admin, sas_address);
```

### 2. Query Schemas from Registry

To get schema details, query the Schema Registry directly:

```rust
// Get schema details by UID
let schema = registry_client.get_schema(schema_uid)?;
```

### 3. Query Attestations by Schema

Use the Indexer to find all attestations for a schema:

```rust
let attestations = indexer_client.get_schema_filtered(
    schema_uid,
    false  // active only
);

// Process attestations...
for uid in attestations.iter() {
    let attestation = sas_client.get_attestation(uid)?;
    // Use attestation data...
}
```

### 4. Validate Attestations

Validate that retrieved attestations haven't expired:

```rust
let attestation = sas_client.get_attestation(uid)?;

// Check if still valid
let is_valid = sas_client.verify_attestation(uid);
if !is_valid {
    // Attestation is revoked or expired
}
```

## Pagination

For large result sets, use pagination to control memory and performance.
Every lookup dimension has a paginated read with the same contract:
`get_atts_by_recipient_paginated`, `get_atts_by_schema_paginated`, and
`get_atts_by_attester_paginated`, each taking `(key, cursor, limit)`.

- Pages walk the complete, append-only history in insertion order (oldest
  first), including revoked and replaced UIDs. New attestations are only
  appended at the end, so earlier pages never shift while you are paging.
- A page holds exactly `min(limit, count - cursor)` UIDs. Resume at
  `cursor + page.len()`; an empty page means the end was reached.
- `limit == 0` and any `cursor` at or past the end return an empty page,
  never an error.
- `get_count_by_recipient` / `get_count_by_schema` / `get_count_by_attester`
  return `count` for computing page totals.

```rust
let page_size = 50;
let mut cursor = 0;
let mut all_attestations = Vec::new();

loop {
    let page = indexer_client.get_atts_by_schema_paginated(
        &schema_uid,
        &cursor,
        &page_size,
    );

    if page.is_empty() {
        break;
    }

    cursor += page.len();
    all_attestations.extend(page.iter());
}
```

Off-chain, the SDK exposes the same reads as
`IndexerClient::get_attestations_by_{recipient,schema,attester}_paginated`,
and the CLI as `query by-* --cursor N --limit M` (see the README).

## Query Limits

The Indexer enforces a maximum of 1000 queries per ledger sequence to prevent denial-of-service attacks via excessive storage reads. If this limit is exceeded, queries will fail with a `LimitExceeded` error.

### Best Practices to Avoid Limits

1. **Use pagination** to process large datasets in batches
2. **Cache results** locally when possible
3. **Filter early** using schema/recipient/attester indices
4. **Batch queries** in a single transaction when appropriate

## Error Handling

Common errors when querying:

| Error | Cause | Resolution |
|-------|-------|-----------|
| `AttestationNotFound` | UID doesn't exist | Verify UID from indexer results |
| `AlreadyRevoked` | Attestation has been revoked | Check status in indexer |
| `AlreadyExpired` | Attestation expiration time passed | Use active-only filter |
| `LimitExceeded` | Query limit exceeded | Reduce query scope or use pagination |
| `InvalidRecipient` | Invalid recipient address | Verify address format |

## Example: Building an Attestation Verification System

```rust
fn verify_attestations_for_schema(
    indexer: &IndexerClient,
    sas: &SASClient,
    schema_uid: UID,
    recipient: Address,
) -> Result<Vec<Attestation>, Error> {
    // Get active attestations for this schema
    let uids = indexer.get_schema_filtered(schema_uid, false);
    
    // Filter to specific recipient
    let mut valid_attestations = Vec::new();
    for uid in uids.iter() {
        let attestation = sas.get_attestation(uid)?;
        if attestation.recipient == recipient {
            // Double-check still valid
            if sas.verify_attestation(uid) {
                valid_attestations.push(attestation);
            }
        }
    }
    
    Ok(valid_attestations)
}
```

## Performance Considerations

1. **Chunking**: Attestations are stored in chunks of 100 for efficient pagination
2. **TTL Renewal**: Queries automatically renew storage TTLs for accessed entries
3. **Storage Optimization**: Use `extend_ttl` sparingly to maintain performance

## Troubleshooting

### No Results from Queries
- Verify the schema UID is correct
- Check if attestations exist using `get_count_by_schema`
- Ensure using active-only filter if revoked attestations shouldn't appear

### Performance Issues
- Use pagination with smaller page sizes
- Reduce the time range of queries
- Consider filtering by recipient/attester to narrow results

### Query Limits Hit
- Break large operations into multiple transactions
- Cache frequently accessed data
- Use more specific query parameters

## References

- [SAS Contract Documentation](../README.md)
- [Indexer Availability and Fees](./indexer-availability-and-fees.md)
- [Schema Registry Integration](./schemas.md)
