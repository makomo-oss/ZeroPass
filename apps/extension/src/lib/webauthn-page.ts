// Runs in the page's own world, before the page's scripts: answers
// `navigator.credentials.create` and `.get` for passkeys through ZeroPass
// when the user wants it, and leaves everything else to the browser
// (docs/spec/extension.md §11). It holds no secret and talks only to the
// extension's content script of the same frame, through window messages.

import {
  CHANNEL,
  fromBase64url,
  isWindowMessage,
  readCreation,
  readRequest,
  type AssertedCredential,
  type CreatedCredential,
  type PageAnswer,
  type PageRequest,
  type WindowMessage,
} from "./webauthn-json";

/** How long to wait for the content script to take a request before the browser answers instead. */
const ACK_MS = 2000;

type Win = Window & typeof globalThis;

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("The operation was aborted.", "AbortError");
}

/** A fresh `ArrayBuffer` with `text`'s bytes. */
function buffer(text: string): ArrayBuffer {
  return fromBase64url(text).buffer;
}

/** Own, read-only properties: they hide the prototype's getters, which work only on the browser's own objects. */
function own(values: Record<string, unknown>): PropertyDescriptorMap {
  const descriptors: PropertyDescriptorMap = {};
  for (const [name, value] of Object.entries(values)) {
    descriptors[name] = { value, enumerable: typeof value !== "function", configurable: true };
  }
  return descriptors;
}

/** The `PublicKeyCredential` of a new passkey, as the browser would make it. */
export function createdCredential(win: Win, made: CreatedCredential, credProps: boolean): PublicKeyCredential {
  const transports = ["internal"];
  const extensions = credProps ? { credProps: { rk: true } } : {};
  const response = Object.create(
    win.AuthenticatorAttestationResponse.prototype,
    own({
      clientDataJSON: buffer(made.clientDataJSON),
      attestationObject: buffer(made.attestationObject),
      getTransports: () => [...transports],
      getAuthenticatorData: () => buffer(made.authenticatorData),
      getPublicKey: () => buffer(made.publicKey),
      getPublicKeyAlgorithm: () => made.algorithm,
    }),
  ) as AuthenticatorAttestationResponse;
  return Object.create(
    win.PublicKeyCredential.prototype,
    own({
      id: made.credentialId,
      rawId: buffer(made.credentialId),
      type: "public-key",
      response,
      authenticatorAttachment: "platform",
      getClientExtensionResults: () => ({ ...extensions }),
      toJSON: () => ({
        id: made.credentialId,
        rawId: made.credentialId,
        type: "public-key",
        response: {
          clientDataJSON: made.clientDataJSON,
          attestationObject: made.attestationObject,
          authenticatorData: made.authenticatorData,
          transports: [...transports],
          publicKey: made.publicKey,
          publicKeyAlgorithm: made.algorithm,
        },
        authenticatorAttachment: "platform",
        clientExtensionResults: { ...extensions },
      }),
    }),
  ) as PublicKeyCredential;
}

/** The `PublicKeyCredential` of an assertion, as the browser would make it. */
export function assertedCredential(win: Win, signed: AssertedCredential): PublicKeyCredential {
  const response = Object.create(
    win.AuthenticatorAssertionResponse.prototype,
    own({
      clientDataJSON: buffer(signed.clientDataJSON),
      authenticatorData: buffer(signed.authenticatorData),
      signature: buffer(signed.signature),
      userHandle: signed.userHandle === "" ? null : buffer(signed.userHandle),
    }),
  ) as AuthenticatorAssertionResponse;
  return Object.create(
    win.PublicKeyCredential.prototype,
    own({
      id: signed.credentialId,
      rawId: buffer(signed.credentialId),
      type: "public-key",
      response,
      authenticatorAttachment: "platform",
      getClientExtensionResults: () => ({}),
      toJSON: () => ({
        id: signed.credentialId,
        rawId: signed.credentialId,
        type: "public-key",
        response: {
          clientDataJSON: signed.clientDataJSON,
          authenticatorData: signed.authenticatorData,
          signature: signed.signature,
          ...(signed.userHandle === "" ? {} : { userHandle: signed.userHandle }),
        },
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
      }),
    }),
  ) as PublicKeyCredential;
}

/** Replaces `navigator.credentials.create` and `.get` in `win`. */
export function install(win: Win): void {
  const container = win.CredentialsContainer?.prototype;
  if (!container || !win.PublicKeyCredential || !win.isSecureContext) return;
  const nativeCreate = container.create;
  const nativeGet = container.get;
  const post = win.postMessage.bind(win);
  const waiting = new Map<string, { ack: () => void; answer: (answer: PageAnswer) => void }>();
  let next = 0;

  win.addEventListener("message", (event: MessageEvent) => {
    // Only the content script of this frame (or this page itself).
    if (event.source !== win || !isWindowMessage(event.data)) return;
    const message = event.data;
    const pending = waiting.get(message.id);
    if (!pending) return;
    if (message.type === "ack") pending.ack();
    if (message.type === "answer") {
      waiting.delete(message.id);
      pending.answer(message.answer);
    }
  });

  /** Hands the request to ZeroPass; `native` if nobody takes it. */
  function ask(request: PageRequest, signal: AbortSignal | null | undefined): Promise<PageAnswer> {
    const id = `${Date.now().toString(36)}-${(next++).toString(36)}-${Math.random().toString(36).slice(2)}`;
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (action: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        waiting.delete(id);
        action();
      };
      const onAbort = () => {
        post({ channel: CHANNEL, type: "abort", id } satisfies WindowMessage, "*");
        finish(() => reject(abortReason(signal as AbortSignal)));
      };
      const timer = setTimeout(() => finish(() => resolve({ outcome: "native" })), ACK_MS);
      signal?.addEventListener("abort", onAbort, { once: true });
      waiting.set(id, {
        ack: () => clearTimeout(timer),
        answer: (answer) => finish(() => resolve(answer)),
      });
      post({ channel: CHANNEL, type: "request", id, ask: request } satisfies WindowMessage, "*");
    });
  }

  function settle(answer: PageAnswer, native: () => Promise<Credential | null>, credProps: boolean) {
    switch (answer.outcome) {
      case "native":
        return native();
      case "created":
        return createdCredential(win, answer.credential, credProps);
      case "asserted":
        return assertedCredential(win, answer.credential);
      case "error":
        throw new DOMException(answer.message, answer.name);
    }
  }

  async function create(this: CredentialsContainer, options?: CredentialCreationOptions): Promise<Credential | null> {
    const native = () => nativeCreate.call(this, options);
    const publicKey = options?.publicKey;
    if (!publicKey) return native();
    if (options.signal?.aborted) throw abortReason(options.signal);
    let request;
    try {
      request = readCreation(publicKey);
    } catch {
      // Malformed: the browser says how.
      return native();
    }
    const answer = await ask({ kind: "create", request }, options.signal);
    return settle(answer, native, request.credProps);
  }

  async function get(this: CredentialsContainer, options?: CredentialRequestOptions): Promise<Credential | null> {
    const native = () => nativeGet.call(this, options);
    const publicKey = options?.publicKey;
    // Passkey autofill (conditional mediation) and silent requests stay
    // with the browser.
    if (!publicKey || (options.mediation !== undefined && options.mediation !== "optional" && options.mediation !== "required")) {
      return native();
    }
    if (options.signal?.aborted) throw abortReason(options.signal);
    let request;
    try {
      request = readRequest(publicKey);
    } catch {
      return native();
    }
    const answer = await ask({ kind: "get", request }, options.signal);
    return settle(answer, native, false);
  }

  for (const [name, value] of [
    ["create", create],
    ["get", get],
  ] as const) {
    Object.defineProperty(container, name, { value, writable: true, configurable: true, enumerable: true });
  }
}
