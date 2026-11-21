// The extension's side of a passkey request (docs/spec/extension.md §11):
// takes the request the page script hands over, asks the user whether to use
// ZeroPass, has the background ask the vault daemon (Windows Hello asks
// there), lets the user choose among several accounts, and answers the page
// script. Holds nothing after a request ends.

import { PasskeyDialog, type DialogState } from "./passkey-dialog";
import type { Ask, PasskeyReply, PasskeyStatus } from "./protocol";
import { CHANNEL, canCreate, isWindowMessage, type PageAnswer, type PageRequest, type WindowMessage } from "./webauthn-json";

type AskBackground = <T>(message: Ask) => Promise<T>;

type Decision = { kind: "zeropass" } | { kind: "native" } | { kind: "cancel" } | { kind: "choose"; id: string };

interface Run {
  id: string;
  aborted: boolean;
}

function notAllowed(message: string): PageAnswer {
  return { outcome: "error", name: "NotAllowedError", message };
}

/** Whether the frame is of another origin than the tab's top frame. */
function crossOriginFrame(win: Window): boolean {
  if (win.top === win) return false;
  try {
    return win.top?.location.origin !== win.location.origin;
  } catch {
    return true;
  }
}

/** Serves the passkey requests of the page script of `win`. */
export function servePasskeys(win: Window, ask: AskBackground): void {
  let current: Run | null = null;
  let decide: ((decision: Decision) => void) | null = null;
  const dialog = new PasskeyDialog({
    onZeroPass: () => decide?.({ kind: "zeropass" }),
    onNative: () => decide?.({ kind: "native" }),
    onCancel: () => decide?.({ kind: "cancel" }),
    onChoose: (id) => decide?.({ kind: "choose", id }),
  });
  const post = (message: WindowMessage) => win.postMessage(message, "*");

  /** Shows `state` and waits for the user's answer. */
  function userDecides(state: DialogState): Promise<Decision> {
    return new Promise((resolve) => {
      decide = (decision) => {
        decide = null;
        resolve(decision);
      };
      dialog.show(state);
    });
  }

  async function failure(code: string, message: string, site: string, kind: PageRequest["kind"]): Promise<PageAnswer> {
    switch (code) {
      case "UserCancelled":
        return notAllowed("The user cancelled.");
      case "Denied":
        return { outcome: "error", name: "SecurityError", message: "This page may not use that relying party." };
      case "CredentialExcluded":
        await userDecides({ step: "message", text: `ZeroPass already keeps a passkey of this account for ${site}.`, native: false });
        return { outcome: "error", name: "InvalidStateError", message: "The authenticator already holds a credential of this account." };
      case "ItemNotFound": {
        const decision = await userDecides({ step: "message", text: `ZeroPass has no passkey for ${site}.`, native: true });
        return decision.kind === "native" ? { outcome: "native" } : notAllowed("No passkey was chosen.");
      }
      default: {
        const what = kind === "create" ? "save the passkey" : "sign in";
        const decision = await userDecides({ step: "message", text: `ZeroPass could not ${what}: ${message}`, native: true });
        return decision.kind === "native" ? { outcome: "native" } : notAllowed(message);
      }
    }
  }

  async function ceremony(page: PageRequest, run: Run): Promise<PageAnswer> {
    if (page.kind === "create" && !canCreate(page.request)) return { outcome: "native" };
    // Like logins, only for the page itself (docs/spec/extension.md §7).
    if (crossOriginFrame(win)) return { outcome: "native" };
    const status = await ask<PasskeyStatus>({ kind: "passkey_status" }).catch(() => ({ available: false }));
    if (!status.available || run.aborted) return { outcome: "native" };

    const site = page.request.rpId || win.location.hostname;
    const account = page.kind === "create" ? page.request.userName || page.request.userDisplayName : "";
    const first = await userDecides({ step: "offer", kind: page.kind, site, account });
    if (first.kind === "native") return { outcome: "native" };
    if (first.kind !== "zeropass") return notAllowed("The user cancelled.");

    let chosen = "";
    for (;;) {
      dialog.show({ step: "waiting", kind: page.kind, site });
      const reply =
        page.kind === "create"
          ? await ask<PasskeyReply>({ kind: "passkey_create", request: page.request })
          : await ask<PasskeyReply>({ kind: "passkey_get", request: page.request, chosen });
      if (run.aborted) return notAllowed("The request was aborted.");
      if (!reply.ok) return failure(reply.code, reply.message, site, page.kind);
      if (reply.created) return { outcome: "created", credential: reply.created };
      if (reply.asserted) return { outcome: "asserted", credential: reply.asserted };
      const choices = reply.choices ?? [];
      const picked = await userDecides({ step: "choose", site, choices });
      if (picked.kind !== "choose") return notAllowed("The user cancelled.");
      chosen = picked.id;
    }
  }

  win.addEventListener("message", (event: MessageEvent) => {
    // The page script of this frame only: not another frame or window.
    if (event.source !== win || !isWindowMessage(event.data)) return;
    const message = event.data;
    if (message.type === "abort" && current?.id === message.id) {
      current.aborted = true;
      dialog.hide();
      decide?.({ kind: "cancel" });
      return;
    }
    if (message.type !== "request") return;
    post({ channel: CHANNEL, type: "ack", id: message.id });
    if (current) {
      const answer = notAllowed("Another passkey request is waiting for the user.");
      post({ channel: CHANNEL, type: "answer", id: message.id, answer });
      return;
    }
    const run: Run = { id: message.id, aborted: false };
    current = run;
    void ceremony(message.ask, run)
      .catch((error: unknown) => notAllowed(String(error)))
      .then((answer) => {
        if (!run.aborted) post({ channel: CHANNEL, type: "answer", id: run.id, answer });
      })
      .finally(() => {
        if (current === run) {
          current = null;
          decide = null;
          dialog.hide();
        }
      });
  });
}
