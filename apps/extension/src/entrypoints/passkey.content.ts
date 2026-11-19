// Runs in the ISOLATED world at document_start to bridge WebAuthn requests from
// `passkey-main.content.ts` to the background service worker and show trusted
// closed shadow DOM confirmation / account selection prompts
// (docs/spec/passkey.md §6).

import { browser } from "wxt/browser";
import { defineContentScript } from "wxt/utils/define-content-script";

import {
  hasSupportedAlgorithm,
  type AssertionPayload,
  type RegistrationPayload,
  type SerializedCreateRequest,
  type SerializedGetRequest,
} from "../lib/passkey-codec";
import { cancelPasskeyPrompt, promptPasskeyCreate, promptPasskeyGet } from "../lib/passkey-prompt";
import type { Ask, PasskeyCreateAnswer, PasskeyGetAnswer, PasskeyListAnswer } from "../lib/protocol";

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

const FALLBACK_CODES = new Set(["NotRunning", "NoVault", "DomainUnavailable", "HardwareUnavailable"]);

function ask<T>(message: Ask): Promise<T> {
  return browser.runtime.sendMessage(message) as Promise<T>;
}

function mapError(code: string, message: string): BridgeOutcome {
  if (FALLBACK_CODES.has(code)) {
    return { action: "fallback" };
  }
  switch (code) {
    case "CredentialExcluded":
      return { action: "error", name: "InvalidStateError", message };
    case "UnsupportedAlgorithm":
      return { action: "fallback" };
    case "Denied":
      return { action: "error", name: "SecurityError", message };
    case "BadRequest":
    case "InvalidInput":
      return { action: "error", name: "TypeError", message };
    case "UserCancelled":
    default:
      return { action: "error", name: "NotAllowedError", message: message || "The operation was not allowed." };
  }
}

async function handleCreate(req: SerializedCreateRequest): Promise<BridgeOutcome> {
  if (!hasSupportedAlgorithm(req.algorithms)) {
    return { action: "fallback" };
  }
  // Probe whether ZeroPass is running, has a passkey domain, and accepts this origin/RP ID.
  const probe = await ask<PasskeyListAnswer>({
    kind: "passkey_list",
    rpId: req.rpId,
    allowCredentialIds: [],
  });
  if (!probe.ok && probe.code !== "Locked") {
    return mapError(probe.code, probe.message);
  }

  const rpLabel = req.rpId || window.location.hostname;
  const decision = await promptPasskeyCreate({
    rpId: rpLabel,
    rpName: req.rpName || rpLabel,
    userName: req.userName,
    userDisplayName: req.userDisplayName,
  });
  if (decision === "fallback") return { action: "fallback" };
  if (decision === "cancel") {
    return { action: "error", name: "NotAllowedError", message: "The user cancelled passkey creation." };
  }

  const created = await ask<PasskeyCreateAnswer>({
    kind: "passkey_create",
    rpId: req.rpId,
    rpName: req.rpName,
    userHandle: req.userHandle,
    userName: req.userName,
    userDisplayName: req.userDisplayName,
    challenge: req.challenge,
    algorithms: req.algorithms,
    excludeCredentialIds: req.excludeCredentialIds,
  });
  if (!created.ok) {
    return mapError(created.code, created.message);
  }
  return {
    action: "ok",
    kind: "create",
    payload: {
      credentialId: created.credentialId,
      clientDataJson: created.clientDataJson,
      attestationObject: created.attestationObject,
      authenticatorData: created.authenticatorData,
      publicKeySpki: created.publicKeySpki,
      coseAlgorithm: created.coseAlgorithm,
    },
  };
}

async function handleGet(req: SerializedGetRequest): Promise<BridgeOutcome> {
  const rpLabel = req.rpId || window.location.hostname;
  const listed = await ask<PasskeyListAnswer>({
    kind: "passkey_list",
    rpId: req.rpId,
    allowCredentialIds: req.allowCredentialIds,
  });

  let chosenCredentialId: string | null = null;
  if (listed.ok) {
    if (listed.candidates.length === 0) {
      return { action: "fallback" };
    }
    const decision = await promptPasskeyGet({ rpId: rpLabel, candidates: listed.candidates });
    if (decision.action === "fallback") return { action: "fallback" };
    if (decision.action === "cancel") {
      return { action: "error", name: "NotAllowedError", message: "The user cancelled passkey sign-in." };
    }
    if (decision.action === "pick") {
      chosenCredentialId = decision.credentialId;
    }
  } else if (listed.code === "Locked") {
    const decision = await promptPasskeyGet({ rpId: rpLabel, locked: true });
    if (decision.action === "fallback") return { action: "fallback" };
    if (decision.action === "cancel") {
      return { action: "error", name: "NotAllowedError", message: "The user cancelled passkey sign-in." };
    }
    chosenCredentialId = "";
  } else {
    return mapError(listed.code, listed.message);
  }

  const first = await ask<PasskeyGetAnswer>({
    kind: "passkey_get",
    rpId: req.rpId,
    challenge: req.challenge,
    allowCredentialIds: req.allowCredentialIds,
    credentialId: chosenCredentialId ?? "",
  });
  if (!first.ok) {
    if (first.code === "ItemNotFound") {
      return { action: "fallback" };
    }
    return mapError(first.code, first.message);
  }
  if (first.kind === "assertion") {
    return {
      action: "ok",
      kind: "get",
      payload: {
        credentialId: first.credentialId,
        clientDataJson: first.clientDataJson,
        authenticatorData: first.authenticatorData,
        signature: first.signature,
        userHandle: first.userHandle,
      },
    };
  }

  // Multiple passkeys matched after unlocking: let the user pick one and sign.
  if (first.candidates.length === 0) {
    return { action: "fallback" };
  }
  const picked = await promptPasskeyGet({ rpId: rpLabel, candidates: first.candidates });
  if (picked.action === "fallback") return { action: "fallback" };
  if (picked.action !== "pick") {
    return { action: "error", name: "NotAllowedError", message: "The user cancelled passkey sign-in." };
  }
  const second = await ask<PasskeyGetAnswer>({
    kind: "passkey_get",
    rpId: req.rpId,
    challenge: req.challenge,
    allowCredentialIds: req.allowCredentialIds,
    credentialId: picked.credentialId,
  });
  if (!second.ok) {
    return mapError(second.code, second.message);
  }
  if (second.kind !== "assertion") {
    return { action: "error", name: "NotAllowedError", message: "Could not select passkey." };
  }
  return {
    action: "ok",
    kind: "get",
    payload: {
      credentialId: second.credentialId,
      clientDataJson: second.clientDataJson,
      authenticatorData: second.authenticatorData,
      signature: second.signature,
      userHandle: second.userHandle,
    },
  };
}

export default defineContentScript({
  matches: PASSKEY_MATCHES,
  allFrames: true,
  runAt: "document_start",
  main() {
    let activeId: string | null = null;

    window.addEventListener(CANCEL_EVENT, ((event: CustomEvent<{ id?: string }>) => {
      if (event.detail?.id && event.detail.id === activeId) {
        activeId = null;
        cancelPasskeyPrompt();
      }
    }) as EventListener);

    window.addEventListener(REQ_EVENT, ((event: CustomEvent) => {
      const detail = event.detail as
        | { id?: string; kind?: "create"; request?: SerializedCreateRequest }
        | { id?: string; kind?: "get"; request?: SerializedGetRequest }
        | undefined;
      if (!detail?.id || !detail.kind || !detail.request) return;
      const id = detail.id;
      activeId = id;
      window.dispatchEvent(new CustomEvent(ACK_EVENT, { detail: { id } }));

      const run =
        detail.kind === "create"
          ? handleCreate(detail.request as SerializedCreateRequest)
          : handleGet(detail.request as SerializedGetRequest);

      void run
        .catch(() => ({ action: "fallback" }) as BridgeOutcome)
        .then((outcome) => {
          if (activeId === id) activeId = null;
          window.dispatchEvent(new CustomEvent(RES_EVENT, { detail: { id, outcome } }));
        });
    }) as EventListener);
  },
});
