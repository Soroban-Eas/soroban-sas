# Streaming SAS events (issue #461)

The Rust SDK exposes `EventStream` for async delivery of strongly typed
`AttestationIssued` / `AttestationRevoked` notifications:

```rust,no_run
use soroban_sas_sdk::rpc::RpcClient;
use soroban_sas_sdk::stream::EventStream;

# async fn example() -> Result<(), String> {
let rpc = RpcClient::new("https://soroban-testnet.stellar.org");
let mut stream = EventStream::new(rpc, vec!["C...".to_string()], 100)
    .with_checkpoint_file("./.sas-event-cursor.json")
    .subscribe()?;
while let Some(next) = stream.recv().await {
    let event = next?;
    // Persist / process the event in your application here.
    stream.acknowledge(&event)?;
}
# Ok(())
# }
```

`getEvents` is polled using Soroban's opaque `pagingToken` and
`pagination.cursor`. Retry delays double from 1s up to 32s on RPC errors.
Responses are parsed from XDR, rather than matching human-readable strings.
The stream buffers up to 128 notifications, applying backpressure.

A checkpoint is persisted atomically only when you acknowledge an event.
If processing crashes before acknowledgment, the stream resumes from the last
checkpoint; consumers must therefore handle at-least-once delivery and
acknowledge in receive order. Use a different cursor file for each subscription.
Filters by schema UID and attester apply to issuance notifications. Revocations
do not carry a schema UID or attester, so filtered subscriptions omit them
rather than misclassify them.

The contract IDs must be trusted and configured by the application. Use an
authenticated RPC endpoint; this helper is not a substitute for checking the
event's emitting contract and chain context.
