// The dialog of a passkey request (docs/spec/extension.md §11): whether to
// use ZeroPass or the browser, the wait for Windows Hello, the choice of an
// account, what went wrong. In a closed shadow root, answered only by the
// user's own clicks: the page can neither read it nor press it.

export interface PasskeyChoiceView {
  id: string;
  name: string;
  displayName: string;
}

export type DialogState =
  /** Use ZeroPass, the browser, or neither. */
  | { step: "offer"; kind: "create" | "get"; site: string; account: string }
  /** Windows Hello is asking. */
  | { step: "waiting"; kind: "create" | "get"; site: string }
  /** Several passkeys: which one. */
  | { step: "choose"; site: string; choices: PasskeyChoiceView[] }
  /** Something to say; `native`: the browser may still try. */
  | { step: "message"; text: string; native: boolean };

export interface DialogHandlers {
  /** Use ZeroPass. */
  onZeroPass: () => void;
  /** Let the browser answer (another passkey provider, a security key, a phone). */
  onNative: () => void;
  /** Close without a passkey. */
  onCancel: () => void;
  /** The user picked a passkey. */
  onChoose: (id: string) => void;
}

const STYLE = `
:host { all: initial; }
.box {
  position: fixed; z-index: 2147483647; top: 12px; right: 12px; width: 360px;
  display: flex; flex-direction: column; gap: 10px; padding: 14px 16px;
  font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #0f172a;
  background: #fff; border: 1px solid #cbd5e1; border-radius: 10px;
  box-shadow: 0 8px 28px rgb(15 23 42 / 22%);
}
.head { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #475569; }
.logo { width: 12px; height: 12px; border-radius: 3px; background: linear-gradient(135deg, #1e40af, #0e7490); }
.title { font-size: 14px; font-weight: 600; }
.sub { color: #475569; overflow-wrap: anywhere; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; }
button { padding: 6px 12px; border-radius: 6px; font: inherit; cursor: pointer;
  border: 1px solid #cbd5e1; background: #fff; color: inherit; }
button.primary { border-color: #1d4ed8; background: #1d4ed8; color: #fff; font-weight: 600; }
button.account { display: flex; flex-direction: column; align-items: flex-start; width: 100%; text-align: left; }
button.account:hover, button.account:focus-visible { background: #dbe6ff; outline: none; }
.name { font-weight: 600; }
.list { display: flex; flex-direction: column; gap: 6px; max-height: 260px; overflow: auto; }
.spinner { width: 14px; height: 14px; border: 2px solid #cbd5e1; border-top-color: #1d4ed8;
  border-radius: 50%; animation: spin 0.8s linear infinite; display: inline-block; vertical-align: -2px; margin-right: 6px; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-color-scheme: dark) {
  .box { background: #162033; color: #e6ebf5; border-color: #2c3b55; }
  .head, .sub { color: #b4c0d4; }
  button { background: #1d2a40; border-color: #2c3b55; }
  button.account:hover, button.account:focus-visible { background: #1f3366; }
}
`;

function element<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = ""): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

/** One dialog per frame, re-drawn for each step. */
export class PasskeyDialog {
  private host: HTMLElement | null = null;
  private box: HTMLDivElement | null = null;

  constructor(private readonly handlers: DialogHandlers) {}

  /** Whether `node` is the dialog itself. */
  contains(node: EventTarget | null): boolean {
    return node !== null && node === this.host;
  }

  hide(): void {
    this.host?.remove();
    this.host = null;
    this.box = null;
  }

  /** A button that acts only on the user's own click. `name` says what it does (`data-action`). */
  private button(name: string, label: string, className: string, action: () => void): HTMLButtonElement {
    const button = element("button", className, label);
    button.type = "button";
    button.dataset.action = name;
    button.addEventListener("click", (event) => {
      if (!event.isTrusted || this.box === null || !button.isConnected) return;
      event.stopPropagation();
      action();
    });
    return button;
  }

  show(state: DialogState): void {
    if (!this.box) {
      const host = document.createElement("zeropass-passkey");
      const shadow = host.attachShadow({ mode: "closed" });
      const style = document.createElement("style");
      style.textContent = STYLE;
      const box = element("div", "box");
      box.setAttribute("role", "dialog");
      box.setAttribute("aria-label", "ZeroPass passkey");
      shadow.append(style, box);
      document.documentElement.append(host);
      this.host = host;
      this.box = box;
    }
    const box = this.box;
    const head = element("div", "head");
    head.append(element("span", "logo"), "ZeroPass");
    const parts: HTMLElement[] = [head];
    const actions = element("div", "actions");
    const native = () => this.button("native", "Use another device or key", "", this.handlers.onNative);
    const cancel = (label = "Cancel") => this.button("cancel", label, "", this.handlers.onCancel);
    switch (state.step) {
      case "offer": {
        const create = state.kind === "create";
        parts.push(element("div", "title", create ? `Save a passkey for ${state.site}?` : `Sign in to ${state.site} with a passkey?`));
        if (state.account) parts.push(element("div", "sub", state.account));
        parts.push(element("div", "sub", "Windows Hello confirms it is you."));
        actions.append(this.button("zeropass", create ? "Save in ZeroPass" : "Use ZeroPass", "primary", this.handlers.onZeroPass), native(), cancel());
        break;
      }
      case "waiting": {
        const title = element("div", "title");
        title.append(element("span", "spinner"), "Confirm with Windows Hello");
        // No way out here but Windows Hello's own: what the user approves
        // there must reach the page.
        parts.push(title, element("div", "sub", state.kind === "create" ? `Saving a passkey for ${state.site}` : `Signing in to ${state.site}`));
        break;
      }
      case "choose": {
        parts.push(element("div", "title", `Which account for ${state.site}?`));
        const list = element("div", "list");
        for (const choice of state.choices) {
          const item = this.button("choose", "", "account", () => this.handlers.onChoose(choice.id));
          item.dataset.name = choice.name;
          item.append(element("span", "name", choice.name || choice.displayName || "(no name)"));
          if (choice.displayName && choice.displayName !== choice.name) item.append(element("span", "sub", choice.displayName));
          list.append(item);
        }
        parts.push(list);
        actions.append(cancel());
        break;
      }
      case "message": {
        parts.push(element("div", "", state.text));
        if (state.native) actions.append(native());
        actions.append(cancel(state.native ? "Cancel" : "Close"));
        break;
      }
    }
    parts.push(actions);
    box.replaceChildren(...parts);
  }
}
