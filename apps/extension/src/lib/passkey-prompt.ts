// Closed shadow DOM prompt for WebAuthn passkey registration and sign-in
// (docs/spec/passkey.md §6). Only trusted user clicks (`event.isTrusted`) are
// accepted so the web page cannot approve a passkey ceremony on its own.

import type { PasskeyCandidate } from "./protocol";

const STYLE = `
:host { all: initial; }
.card {
  position: fixed; z-index: 2147483647; top: 16px; right: 16px; width: 356px;
  max-width: calc(100vw - 32px);
  display: flex; flex-direction: column; gap: 10px; padding: 14px 16px;
  font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #0f172a;
  background: #fff; border: 1px solid #cbd5e1; border-radius: 12px;
  box-shadow: 0 12px 32px rgb(15 23 42 / 24%);
}
.head { display: flex; align-items: center; gap: 7px; font-size: 11px; font-weight: 600; color: #475569; }
.logo { width: 12px; height: 12px; border-radius: 3px; background: linear-gradient(135deg, #1e40af, #0e7490); }
.title { font-size: 14px; font-weight: 600; }
.detail { font-size: 12px; color: #475569; word-break: break-word; }
.list { display: flex; flex-direction: column; gap: 6px; max-height: 220px; overflow-y: auto; }
button {
  padding: 7px 12px; border-radius: 7px; font: inherit; cursor: pointer;
  border: 1px solid #cbd5e1; background: #fff; color: inherit; text-align: left;
}
button:hover { background: #f1f5f9; }
button.primary {
  border-color: #1d4ed8; background: #1d4ed8; color: #fff; font-weight: 600; text-align: center;
}
button.primary:hover { background: #1e40af; }
button.secondary { text-align: center; }
.account { display: flex; flex-direction: column; gap: 2px; }
.account-name { font-weight: 600; }
.account-sub { font-size: 11px; color: #475569; }
.actions { display: flex; flex-direction: column; gap: 6px; }
.row { display: flex; gap: 6px; }
.row button { flex: 1; }
@media (prefers-color-scheme: dark) {
  .card { background: #162033; color: #e6ebf5; border-color: #2c3b55; }
  .head, .detail, .account-sub { color: #b4c0d4; }
  button { background: #1d2a40; border-color: #2c3b55; }
  button:hover { background: #24344f; }
}
`;

let activeHost: HTMLElement | null = null;
let activeCancel: (() => void) | null = null;

/** Dismisses any open passkey prompt. */
export function hidePasskeyPrompt(): void {
  activeCancel = null;
  activeHost?.remove();
  activeHost = null;
}

/** Cancels the currently displayed passkey prompt (e.g. on AbortSignal). */
export function cancelPasskeyPrompt(): void {
  const cancel = activeCancel;
  hidePasskeyPrompt();
  cancel?.();
}

function mountPrompt(build: (card: HTMLDivElement, finish: () => void) => void, onCancel: () => void): void {
  cancelPasskeyPrompt();
  const host = document.createElement("zeropass-passkey-prompt");
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = STYLE;
  const card = document.createElement("div");
  card.className = "card";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");
  const head = document.createElement("div");
  head.className = "head";
  const logo = document.createElement("span");
  logo.className = "logo";
  head.append(logo, "ZeroPass Passkey");
  card.append(head);

  const onKey = (event: KeyboardEvent) => {
    if (event.key === "Escape" && event.isTrusted) {
      cleanup();
      onCancel();
    }
  };
  const cleanup = () => {
    document.removeEventListener("keydown", onKey, true);
    if (activeHost === host) {
      activeHost = null;
      activeCancel = null;
    }
    host.remove();
  };
  activeHost = host;
  activeCancel = () => {
    document.removeEventListener("keydown", onKey, true);
    onCancel();
  };
  document.addEventListener("keydown", onKey, true);
  build(card, cleanup);
  shadow.append(style, card);
  (document.documentElement || document.body).append(host);
}

export type CreateDecision = "zeropass" | "fallback" | "cancel";

/** Asks the user whether to save a new passkey in ZeroPass or fall back to the browser. */
export function promptPasskeyCreate(
  info: { rpName: string; rpId: string; userName: string; userDisplayName: string },
): Promise<CreateDecision> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (decision: CreateDecision) => {
      if (settled) return;
      settled = true;
      resolve(decision);
    };
    mountPrompt(
      (card, cleanup) => {
        const title = document.createElement("div");
        title.className = "title";
        title.textContent = `Save a passkey for ${info.rpId || info.rpName}?`;
        const detail = document.createElement("div");
        detail.className = "detail";
        const account = info.userName || info.userDisplayName || "this account";
        detail.textContent = `Account: ${account}. Windows Hello will verify you before saving.`;

        const actions = document.createElement("div");
        actions.className = "actions";
        const save = document.createElement("button");
        save.type = "button";
        save.className = "primary save";
        save.textContent = "Save in ZeroPass";
        save.addEventListener("click", (event) => {
          if (!event.isTrusted) return;
          cleanup();
          done("zeropass");
        });

        const row = document.createElement("div");
        row.className = "row";
        const fallback = document.createElement("button");
        fallback.type = "button";
        fallback.className = "secondary fallback";
        fallback.textContent = "Use browser";
        fallback.addEventListener("click", (event) => {
          if (!event.isTrusted) return;
          cleanup();
          done("fallback");
        });
        const cancel = document.createElement("button");
        cancel.type = "button";
        cancel.className = "secondary cancel";
        cancel.textContent = "Cancel";
        cancel.addEventListener("click", (event) => {
          if (!event.isTrusted) return;
          cleanup();
          done("cancel");
        });
        row.append(fallback, cancel);
        actions.append(save, row);
        card.append(title, detail, actions);
      },
      () => done("cancel"),
    );
  });
}

export type GetDecision =
  | { action: "pick"; credentialId: string }
  | { action: "unlock" }
  | { action: "fallback" }
  | { action: "cancel" };

/** Asks the user to pick a passkey (or unlock ZeroPass with Windows Hello) or fall back. */
export function promptPasskeyGet(info: {
  rpId: string;
  candidates?: PasskeyCandidate[];
  locked?: boolean;
}): Promise<GetDecision> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (decision: GetDecision) => {
      if (settled) return;
      settled = true;
      resolve(decision);
    };
    mountPrompt(
      (card, cleanup) => {
        const title = document.createElement("div");
        title.className = "title";
        title.textContent = `Sign in to ${info.rpId} with a passkey`;
        card.append(title);

        if (info.locked) {
          const detail = document.createElement("div");
          detail.className = "detail";
          detail.textContent = "Verify with Windows Hello to sign in with ZeroPass.";
          const unlock = document.createElement("button");
          unlock.type = "button";
          unlock.className = "primary unlock";
          unlock.textContent = "Sign in with ZeroPass";
          unlock.addEventListener("click", (event) => {
            if (!event.isTrusted) return;
            cleanup();
            done({ action: "unlock" });
          });
          card.append(detail, unlock);
        } else if (info.candidates && info.candidates.length > 0) {
          const detail = document.createElement("div");
          detail.className = "detail";
          detail.textContent = "Choose a passkey (Windows Hello will verify you):";
          const list = document.createElement("div");
          list.className = "list";
          for (const candidate of info.candidates) {
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "account candidate";
            const name = document.createElement("span");
            name.className = "account-name";
            name.textContent = candidate.user_name || candidate.user_display_name || candidate.rp_id;
            const sub = document.createElement("span");
            sub.className = "account-sub";
            sub.textContent =
              candidate.user_display_name && candidate.user_display_name !== candidate.user_name
                ? `${candidate.user_display_name} · ${candidate.rp_id}`
                : candidate.rp_id;
            btn.append(name, sub);
            btn.addEventListener("click", (event) => {
              if (!event.isTrusted) return;
              cleanup();
              done({ action: "pick", credentialId: candidate.credential_id });
            });
            list.append(btn);
          }
          card.append(detail, list);
        }

        const row = document.createElement("div");
        row.className = "row";
        const fallback = document.createElement("button");
        fallback.type = "button";
        fallback.className = "secondary fallback";
        fallback.textContent = "Use browser";
        fallback.addEventListener("click", (event) => {
          if (!event.isTrusted) return;
          cleanup();
          done({ action: "fallback" });
        });
        const cancel = document.createElement("button");
        cancel.type = "button";
        cancel.className = "secondary cancel";
        cancel.textContent = "Cancel";
        cancel.addEventListener("click", (event) => {
          if (!event.isTrusted) return;
          cleanup();
          done({ action: "cancel" });
        });
        row.append(fallback, cancel);
        card.append(row);
      },
      () => done({ action: "cancel" }),
    );
  });
}
