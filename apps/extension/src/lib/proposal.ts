// The offer to save or update a login after the user signed in
// (docs/spec/extension.md §8): a bar at the top of the page, in a closed
// shadow root, answered only by the user's own clicks.

import type { Proposal } from "./protocol";

const STYLE = `
:host { all: initial; }
.bar {
  position: fixed; z-index: 2147483647; top: 12px; right: 12px; width: 340px;
  display: flex; flex-direction: column; gap: 10px; padding: 12px 14px;
  font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #0f172a;
  background: #fff; border: 1px solid #cbd5e1; border-radius: 10px;
  box-shadow: 0 8px 28px rgb(15 23 42 / 22%);
}
.head { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #475569; }
.logo { width: 12px; height: 12px; border-radius: 3px; background: linear-gradient(135deg, #1e40af, #0e7490); }
.actions { display: flex; gap: 8px; }
button { padding: 5px 12px; border-radius: 6px; font: inherit; cursor: pointer;
  border: 1px solid #cbd5e1; background: #fff; color: inherit; }
button.yes { border-color: #1d4ed8; background: #1d4ed8; color: #fff; font-weight: 600; }
@media (prefers-color-scheme: dark) {
  .bar { background: #162033; color: #e6ebf5; border-color: #2c3b55; }
  .head { color: #b4c0d4; }
  button { background: #1d2a40; border-color: #2c3b55; }
}
`;

let shown: HTMLElement | null = null;

export function hideProposal(): void {
  shown?.remove();
  shown = null;
}

/** Shows the offer; `onAnswer` gets the user's answer once. */
export function showProposal(proposal: Proposal, onAnswer: (accept: boolean) => void): void {
  hideProposal();
  const host = document.createElement("zeropass-proposal");
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = STYLE;
  const bar = document.createElement("div");
  bar.className = "bar";
  bar.setAttribute("role", "dialog");
  const head = document.createElement("div");
  head.className = "head";
  const logo = document.createElement("span");
  logo.className = "logo";
  head.append(logo, "ZeroPass");
  const text = document.createElement("div");
  const who = proposal.username ? ` (${proposal.username})` : "";
  text.textContent =
    proposal.kind === "save"
      ? `Save the login for ${proposal.host}${who} in ZeroPass?`
      : `Update the password of ${proposal.username || "this login"} for ${proposal.host} in ZeroPass?`;
  const actions = document.createElement("div");
  actions.className = "actions";
  const yes = document.createElement("button");
  yes.className = "yes";
  yes.type = "button";
  yes.textContent = proposal.kind === "save" ? "Save" : "Update";
  const no = document.createElement("button");
  no.type = "button";
  no.textContent = "Not now";
  let answered = false;
  const answer = (accept: boolean) => (event: MouseEvent) => {
    // Only the user's own click, not one the page made up.
    if (!event.isTrusted || answered) return;
    answered = true;
    hideProposal();
    onAnswer(accept);
  };
  yes.addEventListener("click", answer(true));
  no.addEventListener("click", answer(false));
  actions.append(yes, no);
  bar.append(head, text, actions);
  shadow.append(style, bar);
  document.documentElement.append(host);
  shown = host;
}
