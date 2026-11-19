// Runs in the page's MAIN world at document_start to mediate WebAuthn
// `navigator.credentials.create` / `get` calls (docs/spec/passkey.md §6).
// Holds no secrets and performs no UI: it forwards serialized public options
// to the isolated content script, which shows a closed shadow DOM prompt and
// verifies everything through the background and vault daemon.

import { defineContentScript } from "wxt/utils/define-content-script";

import {
  buildAssertionCredential,
  buildRegistrationCredential,
  serializeCreateOptions,
  serializeGetOptions,
  type AssertionPayload,
  type RegistrationPayload,
} from "../lib/passkey-codec";

const REQ_EVENT = "zeropass:passkey:req";
const RES_EVENT = "zeropass:passkey:res";
const ACK_EVENT = "zeropass:passkey:ack";
const CANCEL_EVENT = "zeropass:passkey:cancel";

type BridgeOutcome =
  | { action: "ok"; kind: "create"; payload: RegistrationPayload }
  | { action: "ok"; kind: "get"; payload: AssertionPayload }
  | { action: "fallback" }
  | { action: "error"; name: string; message: string };

const PASSKEY_MATCHES = ["https://*/*", "http://localhost/*", "http://127.0.0.1/*", "http://[::1]/*"];

export default defineContentScript({
  matches: PASSKEY_MATCHES,
  allFrames: true,
  runAt: "document_start",
  world: "MAIN",
  main() {
    if (typeof navigator === "undefined" || !navigator.credentials || typeof window === "undefined") {
      return;
    }
    const creds = navigator.credentials;
    const origCreate = creds.create.bind(creds);
    const origGet = creds.get.bind(creds);

    function callBridge(detail: Record<string, unknown>, signal?: AbortSignal): Promise<BridgeOutcome> {
      if (signal?.aborted) {
        return Promise.reject(new DOMException("The operation was aborted.", "AbortError"));
      }
      return new Promise((resolve, reject) => {
        const id =
          typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
        let acked = false;
        let settled = false;

        const cleanup = () => {
          window.removeEventListener(RES_EVENT, onResponse as EventListener);
          window.removeEventListener(ACK_EVENT, onAck as EventListener);
          signal?.removeEventListener("abort", onAbort);
          clearTimeout(ackTimer);
        };

        const onAck = (event: CustomEvent<{ id?: string }>) => {
          if (event.detail?.id === id) {
            acked = true;
            clearTimeout(ackTimer);
          }
        };

        const onResponse = (event: CustomEvent<{ id?: string; outcome?: BridgeOutcome }>) => {
          if (settled || event.detail?.id !== id || !event.detail.outcome) return;
          settled = true;
          cleanup();
          resolve(event.detail.outcome);
        };

        const onAbort = () => {
          if (settled) return;
          settled = true;
          cleanup();
          window.dispatchEvent(new CustomEvent(CANCEL_EVENT, { detail: { id } }));
          reject(new DOMException("The operation was aborted.", "AbortError"));
        };

        // If the isolated content script did not acknowledge (e.g. extension reloaded),
        // fall back seamlessly to the browser's own WebAuthn implementation.
        const ackTimer = setTimeout(() => {
          if (settled || acked) return;
          settled = true;
          cleanup();
          resolve({ action: "fallback" });
        }, 600);

        window.addEventListener(ACK_EVENT, onAck as EventListener);
        window.addEventListener(RES_EVENT, onResponse as EventListener);
        signal?.addEventListener("abort", onAbort, { once: true });

        window.dispatchEvent(new CustomEvent(REQ_EVENT, { detail: { ...detail, id } }));
      });
    }

    async function mediatedCreate(options?: CredentialCreationOptions): Promise<Credential | null> {
      if (!options?.publicKey) {
        return origCreate(options);
      }
      const serialized = serializeCreateOptions(options.publicKey);
      const outcome = await callBridge({ kind: "create", request: serialized }, options.signal);
      if (outcome.action === "fallback") {
        return origCreate(options);
      }
      if (outcome.action === "error") {
        throw new DOMException(outcome.message, outcome.name);
      }
      if (outcome.kind !== "create") {
        return origCreate(options);
      }
      return buildRegistrationCredential(outcome.payload);
    }

    async function mediatedGet(options?: CredentialRequestOptions): Promise<Credential | null> {
      if (!options?.publicKey || options.mediation === "conditional") {
        return origGet(options);
      }
      const serialized = serializeGetOptions(options.publicKey);
      const outcome = await callBridge({ kind: "get", request: serialized }, options.signal);
      if (outcome.action === "fallback") {
        return origGet(options);
      }
      if (outcome.action === "error") {
        throw new DOMException(outcome.message, outcome.name);
      }
      if (outcome.kind !== "get") {
        return origGet(options);
      }
      return buildAssertionCredential(outcome.payload);
    }

    try {
      Object.defineProperty(creds, "create", {
        value: mediatedCreate,
        configurable: true,
        writable: true,
      });
      Object.defineProperty(creds, "get", {
        value: mediatedGet,
        configurable: true,
        writable: true,
      });
    } catch {
      // Frozen credentials object: leave untouched.
    }
  },
});
