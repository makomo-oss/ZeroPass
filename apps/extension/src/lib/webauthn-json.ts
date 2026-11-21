// What the page script (in the page's world) and the content script say to
// each other about a WebAuthn request (docs/spec/extension.md §11), and
// the base64url encoding WebAuthn's JSON forms use. Nothing here is secret:
// a passkey's private key never leaves the vault daemon.

/** Marks the window messages of ZeroPass. */
export const CHANNEL = "zeropass-webauthn";

/** `navigator.credentials.create`, as the page script read it. Bytes are base64url. */
export interface CreateRequest {
  rpId: string;
  rpName: string;
  userId: string;
  userName: string;
  userDisplayName: string;
  challenge: string;
  /** The COSE algorithms of `pubKeyCredParams`, most preferred first. */
  algorithms: number[];
  /** The identifiers of `excludeCredentials`. */
  exclude: string[];
  /** `authenticatorSelection.authenticatorAttachment`, or "". */
  attachment: string;
  /** Whether the `credProps` extension was asked for. */
  credProps: boolean;
}

/** `navigator.credentials.get`, as the page script read it. Bytes are base64url. */
export interface GetRequest {
  rpId: string;
  challenge: string;
  /** The identifiers of `allowCredentials`. */
  allow: string[];
}

export type PageRequest = { kind: "create"; request: CreateRequest } | { kind: "get"; request: GetRequest };

/** A new passkey, as the page receives it. Bytes are base64url. */
export interface CreatedCredential {
  credentialId: string;
  clientDataJSON: string;
  attestationObject: string;
  authenticatorData: string;
  publicKey: string;
  algorithm: number;
}

/** An assertion, as the page receives it. Bytes are base64url. */
export interface AssertedCredential {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle: string;
}

/** How a request ended, for the page script. */
export type PageAnswer =
  | { outcome: "created"; credential: CreatedCredential }
  | { outcome: "asserted"; credential: AssertedCredential }
  /** The browser's own WebAuthn is to answer (the user chose it, or ZeroPass cannot). */
  | { outcome: "native" }
  /** The `DOMException` to reject with. */
  | { outcome: "error"; name: string; message: string };

export type WindowMessage =
  | { channel: typeof CHANNEL; type: "request"; id: string; ask: PageRequest }
  /** The content script has the request: it answers, however long the user takes. */
  | { channel: typeof CHANNEL; type: "ack"; id: string }
  | { channel: typeof CHANNEL; type: "abort"; id: string }
  | { channel: typeof CHANNEL; type: "answer"; id: string; answer: PageAnswer };

export function isWindowMessage(data: unknown): data is WindowMessage {
  return (
    typeof data === "object" &&
    data !== null &&
    (data as { channel?: unknown }).channel === CHANNEL &&
    typeof (data as { id?: unknown }).id === "string" &&
    typeof (data as { type?: unknown }).type === "string"
  );
}

/** Base64url without padding (RFC 4648 §5). */
export function toBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Reads base64url, with or without padding. Throws on anything else. */
export function fromBase64url(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(text)) throw new TypeError("not base64url");
  const base64 = text.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "===".slice((base64.length + 3) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/** The bytes of a `BufferSource`, copied. */
export function bytesOf(source: unknown): Uint8Array {
  if (source instanceof ArrayBuffer) return new Uint8Array(source.slice(0));
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(source.buffer.slice(source.byteOffset, source.byteOffset + source.byteLength));
  }
  throw new TypeError("not a BufferSource");
}

/** The COSE algorithms ZeroPass makes passkeys with (docs/spec/passkey.md §2). */
export const SUPPORTED_ALGORITHMS = [-7, -8];

/** Reads `PublicKeyCredentialCreationOptions` into a request. Throws on what is malformed. */
export function readCreation(options: PublicKeyCredentialCreationOptions): CreateRequest {
  const params = Array.from(options.pubKeyCredParams ?? []);
  return {
    rpId: String(options.rp?.id ?? ""),
    rpName: String(options.rp?.name ?? ""),
    userId: toBase64url(bytesOf(options.user.id)),
    userName: String(options.user.name ?? ""),
    userDisplayName: String(options.user.displayName ?? ""),
    challenge: toBase64url(bytesOf(options.challenge)),
    algorithms: params.filter((param) => param.type === "public-key").map((param) => Number(param.alg)),
    exclude: Array.from(options.excludeCredentials ?? []).map((credential) => toBase64url(bytesOf(credential.id))),
    attachment: String(options.authenticatorSelection?.authenticatorAttachment ?? ""),
    credProps: Boolean((options.extensions as { credProps?: unknown } | undefined)?.credProps),
  };
}

/** Reads `PublicKeyCredentialRequestOptions` into a request. Throws on what is malformed. */
export function readRequest(options: PublicKeyCredentialRequestOptions): GetRequest {
  return {
    rpId: String(options.rpId ?? ""),
    challenge: toBase64url(bytesOf(options.challenge)),
    allow: Array.from(options.allowCredentials ?? []).map((credential) => toBase64url(bytesOf(credential.id))),
  };
}

/**
 * Whether ZeroPass can serve a creation at all; otherwise the browser's own
 * WebAuthn answers without ZeroPass showing anything.
 */
export function canCreate(request: CreateRequest): boolean {
  if (request.attachment === "cross-platform") return false;
  return request.algorithms.length === 0 || request.algorithms.some((alg) => SUPPORTED_ALGORITHMS.includes(alg));
}
