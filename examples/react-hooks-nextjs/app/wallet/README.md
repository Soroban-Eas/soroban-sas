Freighter wallet signing diagnostics are exposed at /wallet while Next.js is running.
They use @stellar/freighter-api v6 and @stellar/stellar-sdk transaction construction to test
a real browser wallet's signature without broadcasting to Stellar.
A connected, funded Testnet Freighter account is required for sequence loading.
All user interaction happens explicitly in the browser. No seed or signature is stored.
Passing this page's local signature test does NOT test SAS contract calls.
