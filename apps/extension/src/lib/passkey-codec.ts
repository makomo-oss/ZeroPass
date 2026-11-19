// WebAuthn binary/base64url helpers, clientDataJSON construction, option
// serialization, and PublicKeyCredential response construction (docs/spec/passkey.md).

export const COSE_ALG_ES256 = -7;
export const COSE_ALG_EDDSA = -8;

export interface SerializedCreateRequest {
  rpId: string;
  rpName: string;
  userHandle: string;
  userName: string;
  userDisplayName: string;
  challenge: string;
  algorithms: number[];
  excludeCredentialIds: string[];
}

export interface SerializedGetRequest {
  rpId: string;
  challenge: string;
  allowCredentialIds: string[];
}

export interface RegistrationPayload {
  credentialId: string;
  clientDataJson: string;
  attestationObject: string;
  authenticatorData: string;
  publicKeySpki: string;
  coseAlgorithm: number;
}

export interface AssertionPayload {
  credentialId: string;
  clientDataJson: string;
  authenticatorData: string;
  signature: string;
  userHandle: string;
}

/** Extracts a standalone Uint8Array view from any BufferSource. */
export function bufferToBytes(input: BufferSource): Uint8Array {
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input);
  }
  return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
}

/** Encodes bytes as unpadded base64url (RFC 4648 §5). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decodes unpadded (or padded) base64url into bytes. */
export function base64UrlToBytes(text: string): Uint8Array {
  if (text.length === 0) return new Uint8Array(0);
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4 === 0 ? "" : "=".repeat(4 - (base64.length % 4));
  const binary = atob(base64 + pad);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/** Decodes base64url into a fresh ArrayBuffer. */
export function base64UrlToArrayBuffer(text: string): ArrayBuffer {
  const bytes = base64UrlToBytes(text);
  const buf = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buf).set(bytes);
  return buf;
}

/**
 * Builds WebAuthn CollectedClientData JSON bytes using the browser-verified
 * origin (`sender`) and returns both UTF-8 bytes and base64url form.
 */
export function buildClientDataJson(
  type: "webauthn.create" | "webauthn.get",
  challengeB64Url: string,
  origin: string,
  crossOrigin: boolean,
): { jsonBytes: Uint8Array; jsonB64: string } {
  const json = JSON.stringify({
    type,
    challenge: challengeB64Url,
    origin,
    crossOrigin,
  });
  const jsonBytes = new TextEncoder().encode(json);
  return { jsonBytes, jsonB64: bytesToBase64Url(jsonBytes) };
}

/** Computes SHA-256 of `bytes` and returns unpadded base64url. */
export async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy);
  return bytesToBase64Url(new Uint8Array(digest));
}

/** Whether at least one requested algorithm is supported by ZeroPass (ES256 or EdDSA). */
export function hasSupportedAlgorithm(algorithms: readonly number[]): boolean {
  // WebAuthn Level 3: an empty pubKeyCredParams defaults to [ES256 (-7), RS256 (-257)].
  if (algorithms.length === 0) return true;
  return algorithms.includes(COSE_ALG_ES256) || algorithms.includes(COSE_ALG_EDDSA);
}

/** Serializes PublicKeyCredentialCreationOptions for transport to the isolated world. */
export function serializeCreateOptions(pk: PublicKeyCredentialCreationOptions): SerializedCreateRequest {
  const rawAlgs = (pk.pubKeyCredParams ?? [])
    .filter((p) => p.type === "public-key" && typeof p.alg === "number")
    .map((p) => p.alg);
  const algorithms = rawAlgs.length === 0 ? [COSE_ALG_ES256, -257] : rawAlgs;
  const excludeCredentialIds = (pk.excludeCredentials ?? [])
    .filter((c) => c.type === "public-key" && c.id)
    .map((c) => bytesToBase64Url(bufferToBytes(c.id)));
  return {
    rpId: pk.rp?.id ?? "",
    rpName: pk.rp?.name ?? "",
    userHandle: bytesToBase64Url(bufferToBytes(pk.user.id)),
    userName: pk.user?.name ?? "",
    userDisplayName: pk.user?.displayName ?? "",
    challenge: bytesToBase64Url(bufferToBytes(pk.challenge)),
    algorithms,
    excludeCredentialIds,
  };
}

/** Serializes PublicKeyCredentialRequestOptions for transport to the isolated world. */
export function serializeGetOptions(pk: PublicKeyCredentialRequestOptions): SerializedGetRequest {
  const allowCredentialIds = (pk.allowCredentials ?? [])
    .filter((c) => c.type === "public-key" && c.id)
    .map((c) => bytesToBase64Url(bufferToBytes(c.id)));
  return {
    rpId: pk.rpId ?? "",
    challenge: bytesToBase64Url(bufferToBytes(pk.challenge)),
    allowCredentialIds,
  };
}

/**
 * Constructs a WebAuthn Level 3 compliant `PublicKeyCredential` for registration
 * (`navigator.credentials.create`), preserving `instanceof` checks and `toJSON()`.
 */
export function buildRegistrationCredential(payload: RegistrationPayload): PublicKeyCredential {
  const rawId = base64UrlToArrayBuffer(payload.credentialId);
  const clientDataJSON = base64UrlToArrayBuffer(payload.clientDataJson);
  const attestationObject = base64UrlToArrayBuffer(payload.attestationObject);
  const authenticatorData = base64UrlToArrayBuffer(payload.authenticatorData);
  const publicKey = base64UrlToArrayBuffer(payload.publicKeySpki);
  const transports: AuthenticatorTransport[] = ["internal", "hybrid"];

  const responseProto =
    typeof AuthenticatorAttestationResponse !== "undefined"
      ? AuthenticatorAttestationResponse.prototype
      : Object.prototype;
  const response = Object.create(responseProto);
  Object.defineProperties(response, {
    clientDataJSON: { value: clientDataJSON, enumerable: true },
    attestationObject: { value: attestationObject, enumerable: true },
    getTransports: { value: () => transports.slice(), enumerable: true },
    getAuthenticatorData: { value: () => authenticatorData.slice(0), enumerable: true },
    getPublicKey: { value: () => publicKey.slice(0), enumerable: true },
    getPublicKeyAlgorithm: { value: () => payload.coseAlgorithm, enumerable: true },
  });

  const credProto =
    typeof PublicKeyCredential !== "undefined" ? PublicKeyCredential.prototype : Object.prototype;
  const credential = Object.create(credProto);
  const extResults = { credProps: { rk: true } };
  Object.defineProperties(credential, {
    id: { value: payload.credentialId, enumerable: true },
    rawId: { value: rawId, enumerable: true },
    type: { value: "public-key", enumerable: true },
    authenticatorAttachment: { value: "platform", enumerable: true },
    response: { value: response, enumerable: true },
    getClientExtensionResults: { value: () => extResults, enumerable: true },
    toJSON: {
      value: () => ({
        id: payload.credentialId,
        rawId: payload.credentialId,
        type: "public-key",
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: payload.clientDataJson,
          attestationObject: payload.attestationObject,
          authenticatorData: payload.authenticatorData,
          publicKey: payload.publicKeySpki,
          publicKeyAlgorithm: payload.coseAlgorithm,
          transports: transports.slice(),
        },
        clientExtensionResults: extResults,
      }),
      enumerable: true,
    },
  });
  return credential as PublicKeyCredential;
}

/**
 * Constructs a WebAuthn Level 3 compliant `PublicKeyCredential` for authentication
 * (`navigator.credentials.get`), preserving `instanceof` checks and `toJSON()`.
 */
export function buildAssertionCredential(payload: AssertionPayload): PublicKeyCredential {
  const rawId = base64UrlToArrayBuffer(payload.credentialId);
  const clientDataJSON = base64UrlToArrayBuffer(payload.clientDataJson);
  const authenticatorData = base64UrlToArrayBuffer(payload.authenticatorData);
  const signature = base64UrlToArrayBuffer(payload.signature);
  const userHandle =
    payload.userHandle.length > 0 ? base64UrlToArrayBuffer(payload.userHandle) : null;

  const responseProto =
    typeof AuthenticatorAssertionResponse !== "undefined"
      ? AuthenticatorAssertionResponse.prototype
      : Object.prototype;
  const response = Object.create(responseProto);
  Object.defineProperties(response, {
    clientDataJSON: { value: clientDataJSON, enumerable: true },
    authenticatorData: { value: authenticatorData, enumerable: true },
    signature: { value: signature, enumerable: true },
    userHandle: { value: userHandle, enumerable: true },
  });

  const credProto =
    typeof PublicKeyCredential !== "undefined" ? PublicKeyCredential.prototype : Object.prototype;
  const credential = Object.create(credProto);
  Object.defineProperties(credential, {
    id: { value: payload.credentialId, enumerable: true },
    rawId: { value: rawId, enumerable: true },
    type: { value: "public-key", enumerable: true },
    authenticatorAttachment: { value: "platform", enumerable: true },
    response: { value: response, enumerable: true },
    getClientExtensionResults: { value: () => ({}), enumerable: true },
    toJSON: {
      value: () => ({
        id: payload.credentialId,
        rawId: payload.credentialId,
        type: "public-key",
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: payload.clientDataJson,
          authenticatorData: payload.authenticatorData,
          signature: payload.signature,
          ...(payload.userHandle.length > 0 ? { userHandle: payload.userHandle } : {}),
        },
        clientExtensionResults: {},
      }),
      enumerable: true,
    },
  });
  return credential as PublicKeyCredential;
}
