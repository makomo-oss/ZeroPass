// The list of matching logins under a field (docs/spec/extension.md §7). It
// lives in a closed shadow root, apart from the page: the page can neither
// read it nor press it (a click it fakes is not `isTrusted`).

import type { Login, PageState } from "./protocol";

export interface SuggestionHandlers {
  /** The user chose a login. */
  onPick: (login: Login) => void;
  /** The user asked to open ZeroPass (to unlock it). */
  onOpenApp: () => void;
}

const STYLE = `
:host { all: initial; }
.box {
  position: fixed; z-index: 2147483647; min-width: 240px; max-width: 360px;
  font: 13px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif; color: #0f172a;
  background: #fff; border: 1px solid #cbd5e1; border-radius: 8px;
  box-shadow: 0 6px 24px rgb(15 23 42 / 18%); overflow: hidden;
}
.head { display: flex; align-items: center; gap: 6px; padding: 6px 10px; font-size: 11px;
  color: #475569; background: #f1f5f9; border-bottom: 1px solid #e2e8f0; }
.logo { width: 12px; height: 12px; border-radius: 3px; background: linear-gradient(135deg, #1e40af, #0e7490); }
button.item { display: flex; flex-direction: column; align-items: flex-start; width: 100%;
  padding: 8px 10px; border: 0; background: none; text-align: left; cursor: pointer; font: inherit; color: inherit; }
button.item:hover, button.item:focus-visible { background: #dbe6ff; outline: none; }
.title { font-weight: 600; }
.sub { color: #64748b; font-size: 12px; }
.note { padding: 10px; }
button.open { margin-top: 8px; padding: 4px 10px; border: 1px solid #1d4ed8; border-radius: 6px;
  background: #1d4ed8; color: #fff; font: inherit; cursor: pointer; }
@media (prefers-color-scheme: dark) {
  .box { background: #162033; color: #e6ebf5; border-color: #2c3b55; }
  .head { background: #1d2a40; color: #b4c0d4; border-color: #2c3b55; }
  button.item:hover, button.item:focus-visible { background: #1f3366; }
  .sub { color: #8a98b0; }
}
`;

/** Shows and hides the list. One per frame. */
export class Suggestions {
  private host: HTMLElement | null = null;
  private box: HTMLDivElement | null = null;
  private anchor: HTMLElement | null = null;
  private readonly reposition = () => this.place();

  constructor(private readonly handlers: SuggestionHandlers) {}

  /** Whether the list is showing. */
  get open(): boolean {
    return this.host !== null;
  }

  /** Whether `node` is the list itself (focus moving into it). */
  contains(node: EventTarget | null): boolean {
    return node !== null && node === this.host;
  }

  show(anchor: HTMLElement, state: PageState, logins: Login[]): void {
    this.hide();
    const message = messageFor(state);
    if (state === "ok" && logins.length === 0) return;
    if (state !== "ok" && message === null) return;

    const host = document.createElement("zeropass-suggestions");
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    const box = document.createElement("div");
    box.className = "box";
    box.setAttribute("role", "listbox");
    const head = document.createElement("div");
    head.className = "head";
    const logo = document.createElement("span");
    logo.className = "logo";
    head.append(logo, "ZeroPass");
    box.append(head);

    if (state === "ok") {
      for (const login of logins.slice(0, 8)) {
        const item = document.createElement("button");
        item.className = "item";
        item.type = "button";
        item.setAttribute("role", "option");
        const title = document.createElement("span");
        title.className = "title";
        title.textContent = login.title || login.username || "(no title)";
        const sub = document.createElement("span");
        sub.className = "sub";
        sub.textContent = login.username;
        item.append(title, sub);
        // Keep the focus in the field while the list is pressed.
        item.addEventListener("mousedown", (event) => event.preventDefault());
        item.addEventListener("click", (event) => {
          // Only the user's own click: not one the page made up.
          if (!event.isTrusted) return;
          this.hide();
          this.handlers.onPick(login);
        });
        box.append(item);
      }
    } else {
      const note = document.createElement("div");
      note.className = "note";
      note.textContent = message;
      if (state === "locked" || state === "not_running") {
        const open = document.createElement("button");
        open.className = "open";
        open.type = "button";
        open.textContent = "Open ZeroPass";
        open.addEventListener("mousedown", (event) => event.preventDefault());
        open.addEventListener("click", (event) => {
          if (!event.isTrusted) return;
          this.hide();
          this.handlers.onOpenApp();
        });
        note.append(document.createElement("br"), open);
      }
      box.append(note);
    }
    shadow.append(style, box);
    document.documentElement.append(host);
    this.host = host;
    this.box = box;
    this.anchor = anchor;
    this.place();
    window.addEventListener("scroll", this.reposition, true);
    window.addEventListener("resize", this.reposition);
  }

  hide(): void {
    this.host?.remove();
    this.host = null;
    this.box = null;
    this.anchor = null;
    window.removeEventListener("scroll", this.reposition, true);
    window.removeEventListener("resize", this.reposition);
  }

  private place(): void {
    if (!this.box || !this.anchor) return;
    const rect = this.anchor.getBoundingClientRect();
    const below = rect.bottom + 4;
    const height = this.box.offsetHeight;
    const top = below + height > window.innerHeight && rect.top > height ? rect.top - height - 4 : below;
    this.box.style.top = `${Math.round(top)}px`;
    this.box.style.left = `${Math.round(Math.max(4, Math.min(rect.left, window.innerWidth - 244)))}px`;
    this.box.style.width = `${Math.round(Math.max(240, Math.min(rect.width, 360)))}px`;
  }
}

/** What to say instead of the list, if anything. */
function messageFor(state: PageState): string | null {
  switch (state) {
    case "locked":
      return "ZeroPass is locked.";
    case "not_running":
      return "ZeroPass is not running.";
    case "no_vault":
      return "ZeroPass has no vault yet.";
    case "unavailable":
      return "The ZeroPass desktop application is not installed, or its bridge is not registered.";
    default:
      return null;
  }
}
