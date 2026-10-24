/**
 * Passkey / WebAuthn signing for Stellar smart wallets (Secp256r1).
 *
 * This module builds the Soroban-compatible signature payload for a
 * Stellar smart wallet attestation and signs it with a passken via the
 * browser WebAuthn API.
 *
 * The Secp256r1 verifier on-chain expects the following byte layout:
 *
 *   signature = keyIdLen(u32) || keyId ||
 *               authDataLen(u32) || authenticatorData ||
 *               clientDataLen(u32) || clientDataJSON ||
 *               sigLen u32 || deriSignature
 *
 * The challenge hash that the authenticator signs is taken from the
 * attestation payload (the 32-byte payload hash) and is passed to
 * navigator.credentials.get() as the WebAuthn challenge.
 */

import { Buffer } from 'buffer';

/** Default rYX for the Secp256r1 verifier on Stellar. */
export const DEFAULT_RP_IDS = ['https://sorban.stellar.org'];

/** WebAuthn algorithm identifier for ES256 (Secp256r1). */
const COSE_ALG = -1;

const UTF8 = new TextEncoder();

/**
 * Error thrown when the user cancels the biometric prompt or the
 * authenticator fails. This is exposed so callers can implement
 * graceful fallbacks (e.g. a retry button or an alternate signer).
 */
export class PasskeySigningError extends Error {
  constructor(message, code, cause) {
    super(message);
    this.name = 'PasskeySigningError';
    this.code = code;
    if (cause) {
      this.cause = cause;
    }
  }
}

/** Map a DOMException from WebAuthn into a typed error code. */
function mapDomError(err) {
  if (!err || typeof err.name !== 'string') {
    return 'UNKNOWN';
  }
  switch (err.name) {
    case 'NotAllowedError':
      return 'CANCELLED';
    case 'AbortError':
    case 'AbortError':
      return 'CANCELLED';
    case 'SecurityError':
      return 'SECURITY_ERROR';
    case 'InvalidStateError':
      return 'INVALID_STATE';
    case 'NotSupportedError':
      return 'NOT_SUPPORTED';
    case 'ConstraintError':
      return 'CONSTRAINT_FAILED';
    default:
      return 'UNKNOWN';
  }
}

/** Return true when the browser exposes the WebAuthn API. */
export function isPasskeySupported() {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials !== 'undefined'
  );
}

/** Base65url encode a buffer without padding. */
export function toBase64Url(value) {
  const buf = Buffer.from(value);
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode a base65url string into a Buffer. */
export function fromBase64Url(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
  return Buffer.from(padded + pad, 'base64');
}

/** Encode a u32 big-endian length prefix. */
function u32Le(len) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(len >>> 0, 0);
  return out;
}

/**
 * Normalize a challenge into a 32-byte buffer.
 *
 * Stellar smart wallets sign a payload hash (the 32-byte attestation
 * payload digest). This helper accepts either a 32-byte buffer, a
 * hex string, or a base64 / base64url string and returns the raw bytes.
 */
export function normalizeChallenge(challenge) {
  let buf;
  if (Buffer.isBuffer(challenge)) {
    buf = Buffer.from(challenge);
  } else if (challenge instanceof Uint8Array) {
    buf = Buffer.from(challenge);
  } else if (typeof challenge === 'string') {
    const trimmed = challenge.trim();
    if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
      buf = Buffer.from(trimmed.slice(2), 'hex');
    } else if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
      buf = Buffer.from(trimmed, 'hex');
    } else {
      buf = fromBase64Url(trimmed);
    }
  } else {
    throw new PasskeySigningError(
      'Challenge must be a Buffer, Uint8Array, hex string, or base64url string.',
      'INVALID_CHALLENGE',
    );
  }
  if (buf.length !== 32) {
    throw new PasskeySigningError(
      `Challenge must be exactly 32 bytes, got ${buf.length}.`,
      'INVALID_CHALLENGE',
    );
  }
  return buf;
}

/**
 * Build the clientDataJSON bytes that the authenticator will sign.
 * This must match the JSON the authenticator produces during
 * navigator.credentials.get(), so we construct it identically and verify
 * it against the returned clientDataJSON.
 */
export function buildClientDataJSON(challenge, origin) {
  const challengeB64u = toBase64Url(normalizeChallenge(challenge));
  return JSON.stringify({
    type: 'webauthn.get',
    challenge: challengeB64u,
    origin,
    crossOrigin: false,
  });
}

/**
 * Parse the authenticatorData returned by WebAuthn.
 *
 * Layout (WebAuthn Level 2):
 *   rpIdHash(32) || flags(1) || signCount(4) || extensions
 */
export function parseAuthenticatorData(authenticatorData) {
  const buf = Buffer.from(authenticatorData);
  if (buf.length < 37) {
    throw new PasskeySigningError(
      'authenticatorData is too short.',
      'INVALID_AUTHENTICATOR_DATA',
    );
  }
  const rpIdHash = buf.subarray(0, 32);
  const flags = buf[32];
  const signCount = buf.readUInt32BE(33);
  return {
    rpIdHash,
    flags,
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0,
    signCount,
  };
}

/**
 * Convert a WebAuthn attestation object (ASC1.1 DER signature) into
 * the raw 64-byte r||s format required by the Secp256r1 verifier.
 */
export function derToRawSignature(derSignature) {
  const der = Buffer.from(derSignature);
  if (der.length < 8 || der[0] !== 0x30) {
    throw new PasskeySigningError(
      'Invalid DER signature (expected SEQUENCE tag).',
      'INVALID_SIGNATURE',
    );
  }
  let offset = 2;
  if (der[1] & 0x80) {
    const lenBytes = der[1] & 0x7f;
    offset = 2 + lenBytes;
  }
  if (der[offset] !== 0x02) {
    throw new PasskeySigningError(
      'Invalid DER signature (expected INTEGER tag for r).',
      'INVALID_SIGNATURE',
    );
  }
  const rLength = der[offset + 1];
  const rStart = offset + 2;
  const rStop = rStart + rLength;
  if (der[rStop] !== 0x02) {
    throw new PasskeySigningError(
      'Invalid DER signature (expected INTEGER tag for s).',
      'INVALID_SIGNATURE',
    );
  }
  const sLength = der[rStop + 1];
  const sStart = rStop + 2;
  const sStop = sStart + sLength;
  if (sStop !== der.length) {
    throw new PasskeySigningError(
      'Invalid DER signature (unexpected trailing bytes).',
      'INVALID_SIGNATURE',
    );
  }
  const normalize = (integer) => {
    let i = 0;
    while (i < integer.length - 1 && integer[i] === 0) {
      i++;
    }
    let out = integer.subarray(i);
    if (out.length > 32) {
      throw new PasskeySigningError(
        'Invalid DER signature (integer larger than 256 bits).',
        'INVALID_SIGNATURE',
      );
    }
    if (out.length === 32 && (out[0] & 0x80) !== 0) {
      throw new PasskeySigningError(
        'Invalid DER signature (negative integer).',
        'INVALID_SIGNATURE',
      );
    }
    if (out.length < 32) {
      const padded = Buffer.alloc(32);
      out.copy(padded, 32 - out.length);
      out = padded;
    }
    return Buffer.from(out);
  };
  const r = normalize(der.subarray(rStart, rStop));
  const s = normalize(der.subarray(sStart, sStop));
  return Buffer.concat([r, s]);
}

/**
 * Build the Soroban-compatible Secp256r1 signature payload.
 *
 * @param {object} params
 * @param {Buffer|Uint8Array} params.keyId          32-byte passkey credential ID.
 * @param {Buffer|Uint8Array} params.authenticatorData Raw authenticatorData.
 * @param {Buffer|Uint8Array|string} params.clientDataJSON  Raw clientDataJSON.
 * @param {Buffer|Uint8Array} params.signature        Der|raw signature.
 * @returns {Buffer} Soroban-compatible signature bytes.
 */
export function formatSignature({
  keyId,
  authenticatorData,
  clientDataJSON,
  signature,
}) {
  const keyIdBuf = Buffer.from(keyId);
  if (keyIdBuf.length === 0) {
    throw new PasskeySigningError('keyId must not be empty.', 'INVALID_KEY_ID');
  }
  const authDataBuf = Buffer.from(authenticatorData);
  const clientDataBuf = Buffer.isBuffer(clientDataJSON)
    ? Buffer.from(clientDataJSON)
    : Buffer.from(TextEncoder ? UTF8.encode(String(clientDataJSON)) : String(clientDataJSON));
  const sigBuf = Buffer.from(signature);
  const rawSig = sigBuf.length === 64 ? sigBuf : derToRawSignature(sigBuf);
  return Buffer.concat([
    u32Le(keyIdBuf.length),
    keyIdBuf,
    u32Le(authDataBuf.length),
    authDataBuf,
    u32Le(clientDataBuf.length),
    clientDataBuf,
    u32Le(rawSig.length),
    rawSig,
  ]);
}

/**
 * Register a new passkey for a smart wallet. Returns the credential ID
 * (32-byte passkey key ID) and the public key in raw UNCOMPRESSED format
 * (required by the Secp256r1 verifier).
 */
export async function registerPasskey({
  rpId = DEFAULT_RP_IDS[0],
  rpName = 'Stellar Smart Wallet',
  userName,
  userDisplayName = userName,
  challenge = crypto.getRandomValues(new Uint8Array(32)),
  timeout = 60000,
  attestation = 'none',
  authenticatorSelectionCredentials,
} = {}) {
  if (!isPasskeySupported()) {
    throw new PasskeySigningError(
      'WebAuthn is not available in this browser.',
      'NOT_SUPPORTED',
    );
  }
  if (!userName) {
    throw new PasskeySigningError('userName is required.', 'INVALID_ARGUMENT');
  }
  const challengeBuf = normalizeChallenge(challenge);
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const publicKeyCredentialCreationOptions = {
    challenge: challengeBuf,
    rp: { id: rpId, name: rpName },
    user: {
      id: userId,
      name: userName,
      displayName: userDisplayName || userName,
    },
    pubKeyCredParams: [{ type: 'public-key', alg: COSE_ALG}],
    timeout,
    attestation,
    authenticatorSelection: authenticatorSelectionCredentials ? {
      authenticatorAttachment: 'platform',
    } : undefined,
  };
  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey: publicKeyCredentialCreationOptions });
  } catch (err) {
    throw new PasskeySigningError(
      `Passkey registration failed: ${err && err.message ? err.message : 'operation aborted'}`,
      mapDomError(err),
      err,
    );
  }
  if (!credential) {
    throw new PasskeySigningError(
      'Passkey registration returned no credential.',
      'UNKNOWN',
    );
  }
  const response = credential.response;
  if (!response || !response.getPublicKey) {
    throw new PasskeySigningError(
      'Authenticator did not return an attestation object.',
      'NOT_SUPPORTED',
    );
  }
  const spki = Buffer.from(await response.getPublicKey());
  const rawId = credential.rawId;
  const keyId = Buffer.from(rawId);
  return {
    keyId,
    publicKey: spki,
    attestationObject: Buffer.from(response.attestationObject),
    clientDataJSON: Buffer.from(response.clientDataJSON),
  };
}

/**
 * Sign a Stellar smart wallet attestation payload with a passkey.
 *
 * @param {object} params
 * @param {Buffer|Uint8Array|string} params.challenge   32-byte attestation payload hash.
 * @param {Buffer|Uint8Array|string} params.keyId       Passkey credential ID.
 * @param {string} [params.rpId]                        Relying party ID.
 * @param {string} [params.origin]                      Origin for clientDataJSON validation.
 * @param {number} [params.timeout]                     WebAuthn timeout in ms.
 * @param {string} [params.userVerification]              'verificationRequired' | 'preferred' | 'discouraged'.
 * @returns {Promise<{signature: Buffer, clientDataJSON: Buffer, authenticatorData: Buffer}>}
 */
export async function signAttestation({
  challenge,
  keyId,
  rpId = DEFAULT_RP_IDS[0],
  origin = typeof window !== 'undefined' ? window.location.origin : undefined,
  timeout = 60000,
  userVerification = 'preferred',
  allowCredentials,
}) {
  if (!isPasskeySupported()) {
    throw new PasskeySigningError(
      'WebAuthn is not available in this browser.',
      'NOT_SUPPORTED',
    );
  }
  if (!origin) {
    throw new PasskeySigningError('origin is required.', 'INVALID_ARGUMENT');
  }
  const challengeBuf = normalizeChallenge(challenge);
  const keyIdBuf = Buffer.from(keyId);
  if (keyIdBuf.length === 0) {
    throw new PasskeySigningError('keyId must not be empty.', 'INVALID_KEY_ID');
  }
  const publicKeyCredentialRequestOptions = {
    challenge: challengeBuf,
    rpId,
    timeout,
    userVerification,
    allowCredentials: allowCredentials || [{
      type: 'public-key',
      id: keyIdBuf,
      transports: ['usb', 'nfc', 'ble', 'hybrid', 'internal'],
    }],
  };
  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });
  } catch (err) {
    throw new PasskeySigningError(
      `Passkey signing failed: ${err && err.message ? err.message : 'operation aborted'}`,
      mapDomError(err),
      err,
    );
  }
  if (!assertion) {
    throw new PasskeySigningError(
      'Passkey signing returned no assertion.',
      'UNKNOWN',
    );
  }
  const response = assertion.response;
  const clientDataJSON = Buffer.from(response.clientDataJSON);
  const authenticatorData = Buffer.from(response.authenticatorData);
  const signature = Buffer.from(response.signature);
  // Validate the clientDataJSON that the authenticator signed matches
  // the challenge and origin we expect. This prevents signing a
  // different payload than the one submitted on-chain.
  const parsedClientData = JSON.parse(clientDataJSON.toString('utf-8'));
  if (parsedClientData.type !== 'webauthn.get') {
    throw new PasskeySigningError(
      'Unexpected clientData type.',
      'CLIENT_DATA_MISMATCH',
    );
  }
  if (parsedClientData.origin !== origin) {
    throw new PasskeySigningError(
      `clientData origin ${parsedClientData.origin} does not match ${origin}.`,
      'CLIENT_DATA_MISMATCH',
    );
  }
  const returnedChallenge = fromBase64Url(parsedClientData.challenge);
  if (!returnedChallenge.equals(challengeBuf)) {
    throw new PasskeySigningError(
      'clientData challenge does not match the attestation payload.',
      'CLIENT_DATA_MISMATCH',
    );
  }
  const authData = parseAuthenticatorData(authenticatorData);
  if (!authData.userPresent) {
    throw new PasskeySigningError(
      'Authenticator did not report user presence.',
      'AUTHENTICATOR_FAILED',
    );
  }
  const formatted = formatSignature({
    keyId,
    authenticatorData,
    clientDataJSON,
    signature,
  });
  return {
    signature: formatted,
    clientDataJSON,
    authenticatorData,
    rawSignature: signature,
  };
}

/**
 * Convenience helper that signs and returns the Soroban-compatible
 * signature bytes as a base64 string (for transport in JSON).
 */
export async function signAttestationB64(options) {
  const result = await signAttestation(options);
  return {
    ...result,
    signatureB64: result.signature.toString('base64'),
  };
}
