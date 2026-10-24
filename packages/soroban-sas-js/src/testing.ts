// Offline test doubles for dApp frontend component tests (badge displays,
// verification checks, empty/loading/error states) that would otherwise need a
// live Soroban RPC node plus network mocks.
//
// This module is a separate entry point (`@soroban-sas/sdk/testing`) and is
// imported by nothing in `index.ts`, so application builds that import the
// package root never pull it in.
//
// Two deliberate constraints keep the mock usable in every runner the package
// supports — Vitest, Jest, and Cypress (which executes specs in a browser):
//   1. no test-runner API (`vi`/`jest`) is used, and
//   2. no Node-only built-in (`node:crypto`, `Buffer`) is reached: only
//      `Uint8Array`/`setTimeout` and type-only imports of the real client, so
//      nothing from `@stellar/stellar-sdk` is loaded at runtime.

import type { SubmitResult } from "./client.js";
import type { Attestation, DelegatedAttestation, SchemaRecord, UID } from "./types.js";

/**
 * The verdict a verification check reports for a UID.
 *
 * Mirrors `SAS::verify_attestation`, which answers a single boolean: `"valid"`
 * is the only verdict that corresponds to the contract's `true`. The other
 * three exist so a component's distinct UI states (unknown / revoked /
 * expired) can be asserted without inventing timestamps or revocation times.
 */
export type VerificationVerdict = "valid" | "revoked" | "expired" | "unknown";

/** Every call `MockSASProvider` answers, and the units the stubbing knobs target. */
export type MockMethod =
  | "registerSchema"
  | "getSchema"
  | "attest"
  | "attestByDelegation"
  | "revoke"
  | "getAttestation"
  | "verifyAttestation";

/** One recorded call, in the order the mock received it. */
export interface MockCall {
  method: MockMethod;
  /** The arguments exactly as the caller passed them (not copied). */
  args: readonly unknown[];
}

/**
 * The contract surface a component consumes. `SASClient` satisfies it
 * structurally, so a prop typed as `SASClientLike` accepts either the real
 * client or a [`MockSASProvider`].
 */
export interface SASClientLike {
  registerSchema(schema: string, resolver: string, revocable: boolean): Promise<UID>;
  getSchema(uid: UID): Promise<SchemaRecord | null>;
  attest(attestation: Attestation): Promise<SubmitResult>;
  attestByDelegation(delegated: DelegatedAttestation): Promise<SubmitResult>;
  revoke(uid: UID): Promise<SubmitResult>;
  getAttestation(uid: UID): Promise<Attestation | null>;
}

/**
 * The verification check a badge-style component performs. `SASClient` does not
 * wrap `SAS::verify_attestation` yet, so today this interface is implemented by
 * [`MockSASProvider`]; type the component's prop as `SASVerifierLike` to inject
 * it.
 */
export interface SASVerifierLike {
  verifyAttestation(uid: UID): Promise<VerificationVerdict>;
}

export interface MockSASProviderOptions {
  /** Attestations the mock starts with. Equivalent to calling `seedAttestation` on each. */
  attestations?: readonly Attestation[];
  /** Schema records the mock starts with. Equivalent to calling `seedSchema` on each. */
  schemas?: readonly SchemaRecord[];
  /** Verdict overrides the mock starts with. See `seedVerdict`. */
  verdicts?: Readonly<Record<UID, VerificationVerdict>>;
  /** Simulated round-trip latency in milliseconds, added to every call. Defaults to `0`. */
  latencyMs?: number;
  /**
   * Ledger time source, in seconds, used to decide whether an attestation has
   * expired and to stamp simulated revocations. Defaults to wall-clock time;
   * inject a fixed function to keep expiry assertions deterministic.
   */
  now?: () => bigint;
  /**
   * How `registerSchema` derives the UID it returns. Defaults to looking up a
   * seeded schema with the same `(schema, resolver, revocable)` triple. In Node
   * tests, pass `computeSchemaUid` from `@soroban-sas/sdk` to get the real
   * content-addressed UID.
   */
  deriveSchemaUid?: (schema: string, resolver: string, revocable: boolean) => UID;
}

function defaultNow(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}

function toError(error: Error | string | undefined, fallback: string): Error {
  if (error instanceof Error) return error;
  if (typeof error === "string") return new Error(error);
  return new Error(fallback);
}

function cloneAttestation(attestation: Attestation): Attestation {
  return { ...attestation, data: new Uint8Array(attestation.data) };
}

/**
 * In-memory stand-in for `SASClient`: no network, no signing, no crypto — only
 * state.
 *
 * Every call is asynchronous and passes through one gate, so the same knobs
 * shape loading, pending, and failing states for reads and writes alike.
 * Seeded state then evolves exactly like the contract's: `attest` inserts
 * (rejecting a duplicate UID), `revoke` stamps `revocationTime` and rejects a
 * second revocation, and `verifyAttestation` reports the verdict implied by
 * the stored state.
 *
 * Not simulated — do not lean on the mock for these: signature/authorization
 * checks, content-addressing of `uid`, `valid_from` time locks, fee
 * collection, storage TTL/rent, batch entry points, and event emission.
 */
export class MockSASProvider implements SASClientLike, SASVerifierLike {
  private readonly attestations = new Map<UID, Attestation>();
  private readonly schemas = new Map<UID, SchemaRecord>();
  private readonly verdicts = new Map<UID, VerificationVerdict>();
  private readonly callLog: MockCall[] = [];
  private readonly failures: Array<{ method?: MockMethod; error: Error }> = [];
  private readonly holds: Array<{
    method?: MockMethod;
    settled: Promise<void>;
    release: () => void;
    taken: boolean;
  }> = [];
  private networkFailure?: Error;
  private latencyMs: number;
  private readonly now: () => bigint;
  private readonly deriveSchemaUid?: MockSASProviderOptions["deriveSchemaUid"];
  private txCounter = 0;

  constructor(options: MockSASProviderOptions = {}) {
    for (const attestation of options.attestations ?? []) this.seedAttestation(attestation);
    for (const schema of options.schemas ?? []) this.seedSchema(schema);
    for (const [uid, verdict] of Object.entries(options.verdicts ?? {})) this.seedVerdict(uid, verdict);
    this.latencyMs = options.latencyMs ?? 0;
    this.now = options.now ?? defaultNow;
    this.deriveSchemaUid = options.deriveSchemaUid;
  }

  // ---------------------------------------------------------------- seeding

  /** Makes `getAttestation` answer with `attestation` and `verifyAttestation` derive from it. */
  seedAttestation(attestation: Attestation): void {
    this.attestations.set(attestation.uid, cloneAttestation(attestation));
  }

  /** Makes `getSchema` answer with `record`. */
  seedSchema(record: SchemaRecord): void {
    this.schemas.set(record.uid, { ...record });
  }

  /**
   * Pins `verifyAttestation(uid)` to `verdict`, whatever the stored state says.
   *
   * The override is dropped as soon as the state for that UID changes —
   * `attest`, `attestByDelegation`, `revoke`, and `simulateRevocation` all
   * clear it — so a seeded verdict can never mask a later call's effect.
   */
  seedVerdict(uid: UID, verdict: VerificationVerdict): void {
    this.verdicts.set(uid, verdict);
  }

  // ------------------------------------------------- simulation helpers

  /** Delays every subsequent call by `milliseconds` (default `0` = resolve immediately). */
  setLatency(milliseconds: number): void {
    this.latencyMs = milliseconds;
  }

  /**
   * Keeps the next call of `method` (or of any method, when omitted) pending
   * until `releaseHold`, so a test can assert the loading UI.
   *
   * ```ts
   * provider.holdNext("getAttestation");
   * const pending = provider.getAttestation(uid); // stays pending
   * // ...assert the spinner...
   * provider.releaseHold();
   * await pending;
   * ```
   */
  holdNext(method?: MockMethod): void {
    let release!: () => void;
    const settled = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.holds.push({ method, settled, release, taken: false });
  }

  /** Resolves every call currently held by `holdNext`. */
  releaseHold(): void {
    for (const hold of this.holds.splice(0)) hold.release();
  }

  /** Rejects the next call of `method` (or of any method, when omitted) with `error`. */
  failNext(method?: MockMethod, error?: Error | string): void {
    this.failures.push({ method, error: toError(error, "simulated failure (MockSASProvider)") });
  }

  /** Rejects every subsequent call, simulating an unreachable RPC until `clearNetworkFailure`. */
  setNetworkFailure(error?: Error | string): void {
    this.networkFailure = toError(error, "simulated network failure (MockSASProvider)");
  }

  /** Stops the failure installed by `setNetworkFailure`. */
  clearNetworkFailure(): void {
    this.networkFailure = undefined;
  }

  /**
   * Marks a stored attestation revoked *without* calling `revoke` — for a
   * badge that must render an attestation revoked by someone else.
   */
  simulateRevocation(uid: UID, revocationTime?: bigint): void {
    const attestation = this.attestations.get(uid);
    if (!attestation) throw new Error(`MockSASProvider.simulateRevocation: attestation ${uid} not found`);
    attestation.revocationTime = revocationTime ?? this.now();
    this.verdicts.delete(uid);
  }

  /** Drops all state, calls, failures, holds, and latency, returning the mock to its constructed shape. */
  reset(): void {
    this.attestations.clear();
    this.schemas.clear();
    this.verdicts.clear();
    this.callLog.length = 0;
    this.failures.length = 0;
    this.releaseHold();
    this.networkFailure = undefined;
    this.latencyMs = 0;
    this.txCounter = 0;
  }

  /** Every call the mock has received, oldest first. */
  get calls(): readonly MockCall[] {
    return [...this.callLog];
  }

  // ------------------------------------------------------- client surface

  /**
   * Returns the UID for `schema`. With no `deriveSchemaUid` option, answers
   * with the UID of a seeded schema carrying the same `(schema, resolver,
   * revocable)`, so the mock never invents a content address; with no match it
   * rejects and says how to seed one. Either way the record becomes readable
   * through `getSchema`.
   */
  async registerSchema(schema: string, resolver: string, revocable: boolean): Promise<UID> {
    return this.gate("registerSchema", [schema, resolver, revocable], () => {
      const uid = this.deriveSchemaUid
        ? this.deriveSchemaUid(schema, resolver, revocable)
        : this.seededSchemaUid(schema, resolver, revocable);
      if (!uid) {
        throw new Error(
          "MockSASProvider.registerSchema: no seeded schema matches " +
            `(schema: ${JSON.stringify(schema)}, resolver: ${resolver}, revocable: ${revocable}). ` +
            "Seed it with seedSchema({...}) or pass deriveSchemaUid: computeSchemaUid.",
        );
      }
      this.seedSchema({ uid, schema, resolver, revocable });
      return uid;
    });
  }

  async getSchema(uid: UID): Promise<SchemaRecord | null> {
    return this.gate("getSchema", [uid], () => {
      const record = this.schemas.get(uid);
      return record ? { ...record } : null;
    });
  }

  async attest(attestation: Attestation): Promise<SubmitResult> {
    return this.gate("attest", [attestation], () => this.store(attestation));
  }

  async attestByDelegation(delegated: DelegatedAttestation): Promise<SubmitResult> {
    return this.gate("attestByDelegation", [delegated], () => this.store(delegated.attestation));
  }

  async revoke(uid: UID): Promise<SubmitResult> {
    return this.gate("revoke", [uid], () => {
      const attestation = this.attestations.get(uid);
      if (!attestation) throw new Error(`MockSASProvider.revoke: attestation ${uid} not found`);
      if (!attestation.revocable) throw new Error(`MockSASProvider.revoke: attestation ${uid} is not revocable`);
      if (attestation.revocationTime !== 0n) {
        throw new Error(`MockSASProvider.revoke: attestation ${uid} is already revoked`);
      }
      attestation.revocationTime = this.now();
      this.verdicts.delete(uid);
      return { hash: this.nextTxHash() };
    });
  }

  async getAttestation(uid: UID): Promise<Attestation | null> {
    return this.gate("getAttestation", [uid], () => {
      const attestation = this.attestations.get(uid);
      return attestation ? cloneAttestation(attestation) : null;
    });
  }

  /** The verdict `SAS::verify_attestation` would reach for `uid`, as a UI state. */
  async verifyAttestation(uid: UID): Promise<VerificationVerdict> {
    return this.gate("verifyAttestation", [uid], () => {
      const seeded = this.verdicts.get(uid);
      if (seeded) return seeded;
      const attestation = this.attestations.get(uid);
      if (!attestation) return "unknown";
      if (attestation.revocationTime !== 0n) return "revoked";
      if (attestation.expirationTime !== 0n && attestation.expirationTime <= this.now()) return "expired";
      return "valid";
    });
  }

  // -------------------------------------------------------------- internals

  private async gate<T>(method: MockMethod, args: readonly unknown[], run: () => T): Promise<T> {
    this.callLog.push({ method, args });
    if (this.latencyMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.latencyMs));
    }
    const hold = this.holds.find(
      (candidate) =>
        !candidate.taken && (candidate.method === undefined || candidate.method === method),
    );
    if (hold) {
      // Stay in the list (marked as taken) so a later `releaseHold` still
      // resolves this call; it is dropped only when released.
      hold.taken = true;
      await hold.settled;
    }
    if (this.networkFailure) throw this.networkFailure;
    const failure = this.failures.findIndex((candidate) => candidate.method === undefined || candidate.method === method);
    if (failure !== -1) throw this.failures.splice(failure, 1)[0].error;
    return run();
  }

  private store(attestation: Attestation): SubmitResult {
    if (this.attestations.has(attestation.uid)) {
      throw new Error(`MockSASProvider.attest: attestation ${attestation.uid} already exists`);
    }
    this.attestations.set(attestation.uid, cloneAttestation(attestation));
    this.verdicts.delete(attestation.uid);
    return { hash: this.nextTxHash() };
  }

  private seededSchemaUid(schema: string, resolver: string, revocable: boolean): UID | undefined {
    for (const record of this.schemas.values()) {
      if (record.schema === schema && record.resolver === resolver && record.revocable === revocable) {
        return record.uid;
      }
    }
    return undefined;
  }

  /** A synthetic 64-hex transaction hash — shaped like a real one so format checks pass. */
  private nextTxHash(): string {
    this.txCounter += 1;
    return this.txCounter.toString(16).padStart(64, "0");
  }
}
