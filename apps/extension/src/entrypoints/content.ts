// In every frame of every page: finds login fields, offers the matching
// logins under the field the user is in, and fills the one the user picks
// (docs/spec/extension.md §7); fills one-time codes the same way (§9); after
// the user signs in, offers to save or update the login (§8). It never fills
// by itself and keeps nothing.

import { browser } from "wxt/browser";
import { defineContentScript } from "wxt/utils/define-content-script";

import { fieldsOf, findLoginFields, isPasswordField, otpField, type LoginFields } from "../lib/detect";
import { fillLogin, setValue } from "../lib/fill";
import { hideProposal, showProposal } from "../lib/proposal";
import type { Ask, FillAnswer, FindAnswer, Login, Order, Proposal, TotpAnswer } from "../lib/protocol";
import { Suggestions } from "../lib/suggestions";
import { isVisible } from "../lib/visible";

/** How long the logins found for this frame are reused. */
const CACHE_MS = 15_000;
/** One sign-in is reported once, however many events it causes. */
const SUBMIT_DEBOUNCE_MS = 2000;

/** Words of buttons that show or hide the password, rather than sign in. */
const TOGGLE_WORDS = /show|hide|reveal|unmask|display|toggle|表示|非表示|見る/i;

/** Whether a button only shows or hides what was typed. */
function isToggle(button: Element): boolean {
  const words = [
    button.textContent ?? "",
    button.getAttribute("aria-label") ?? "",
    button.getAttribute("title") ?? "",
    button.getAttribute("data-testid") ?? "",
  ].join(" ");
  return TOGGLE_WORDS.test(words) && !/sign|log ?in|ログイン|次へ|next|continue/i.test(words);
}

function ask<T>(message: Ask): Promise<T> {
  return browser.runtime.sendMessage(message) as Promise<T>;
}

export default defineContentScript({
  matches: ["<all_urls>"],
  allFrames: true,
  runAt: "document_idle",
  main() {
    /** The field the list is under, and what picking a login does there. */
    let anchor: HTMLInputElement | null = null;
    let anchorKind: "login" | "code" = "login";
    let cached: { at: number; answer: FindAnswer } | null = null;
    let lastSubmit = 0;
    const isTop = window.top === window;

    async function found(): Promise<FindAnswer> {
      if (cached && Date.now() - cached.at < CACHE_MS && cached.answer.state === "ok") {
        return cached.answer;
      }
      const answer = await ask<FindAnswer>({ kind: "find" });
      cached = { at: Date.now(), answer };
      return answer;
    }

    async function fillInto(fields: LoginFields, item: string): Promise<void> {
      const answer = await ask<FillAnswer>({ kind: "fill", item });
      if (!answer.ok) {
        const field = fields.username ?? fields.password;
        if (field) suggestions.show(field, answer.state, [], "ZeroPass", answer.message);
        return;
      }
      fillLogin(fields, answer.username, answer.password);
      // The answer goes out of reach here; nothing keeps it.
    }

    async function fillCode(field: HTMLInputElement, item: string): Promise<void> {
      const answer = await ask<TotpAnswer>({ kind: "totp", item });
      if (!answer.ok) {
        suggestions.show(field, answer.state, [], "One-time code", answer.message);
        return;
      }
      setValue(field, answer.code);
    }

    const suggestions = new Suggestions({
      onPick: (login: Login) => {
        const field = anchor;
        if (!field) return;
        if (anchorKind === "code") {
          void fillCode(field, login.id);
          return;
        }
        const fields = fieldsOf(field, document, isVisible);
        if (fields) void fillInto(fields, login.id);
      },
      onOpenApp: () => {
        cached = null;
        void ask({ kind: "open_app" });
      },
    });

    async function offer(field: HTMLInputElement): Promise<void> {
      const code = otpField(field, isVisible);
      if (!code && !fieldsOf(field, document, isVisible)) {
        suggestions.hide();
        return;
      }
      anchor = field;
      anchorKind = code ? "code" : "login";
      const answer = await found();
      // The user may have moved on while ZeroPass answered.
      if (anchor !== field || !isFocused(field)) return;
      suggestions.show(field, answer.state, answer.logins, code ? "One-time code (Windows Hello asks)" : "ZeroPass");
    }

    function isFocused(field: HTMLInputElement): boolean {
      let active: Element | null = document.activeElement;
      while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
      return active === field;
    }

    function inputOf(event: Event): HTMLInputElement | null {
      const target = event.composedPath()[0];
      return target instanceof HTMLInputElement ? target : null;
    }

    /**
     * The user is signing in: report what was typed, so that ZeroPass can
     * offer to save or update it. A user-name step without a password is
     * reported as a user name only.
     */
    function signingIn(): void {
      if (Date.now() - lastSubmit < SUBMIT_DEBOUNCE_MS) return;
      const forms = findLoginFields(document, isVisible);
      const withPassword = forms.find((fields) => fields.password && fields.password.value !== "");
      if (withPassword?.password) {
        lastSubmit = Date.now();
        const username = withPassword.username?.value ?? "";
        void ask<Proposal | null>({ kind: "submitted", username, password: withPassword.password.value }).then(
          (proposal) => {
            if (proposal && isTop) propose(proposal);
          },
        );
        return;
      }
      const usernameOnly = forms.find((fields) => !fields.password && fields.username?.value);
      if (usernameOnly?.username) {
        void ask({ kind: "typed_username", username: usernameOnly.username.value });
      }
    }

    function propose(proposal: Proposal): void {
      showProposal(proposal, (accept) => void ask({ kind: "answer", accept }));
    }

    document.addEventListener(
      "focusin",
      (event) => {
        const field = inputOf(event);
        if (field) void offer(field);
        else if (!suggestions.contains(event.target)) suggestions.hide();
      },
      true,
    );
    // A click into a field that already has the focus, or on what signs in.
    document.addEventListener(
      "click",
      (event) => {
        if (!event.isTrusted) return;
        const field = inputOf(event);
        if (field && !suggestions.open) {
          void offer(field);
          return;
        }
        const target = event.composedPath()[0];
        const button = target instanceof Element ? target.closest("button, [type=submit], [role=button]") : null;
        if (button && !isToggle(button)) signingIn();
      },
      true,
    );
    document.addEventListener("submit", (event) => event.isTrusted && signingIn(), true);
    document.addEventListener(
      "focusout",
      (event) => {
        const next = (event as FocusEvent).relatedTarget;
        if (!suggestions.contains(next)) {
          // Let a click on the list land first.
          setTimeout(() => {
            if (anchor && !isFocused(anchor)) suggestions.hide();
          }, 150);
        }
      },
      true,
    );
    document.addEventListener(
      "keydown",
      (event) => {
        if (event.key === "Escape") {
          suggestions.hide();
          hideProposal();
        }
        const field = inputOf(event);
        if (event.key === "Enter" && event.isTrusted && field && (isPasswordField(field) || field.value)) signingIn();
      },
      true,
    );

    if (isTop) {
      // From the popup, through the background, to the top frame only.
      browser.runtime.onMessage.addListener((message: unknown) => {
        const order = message as Order;
        if (order?.kind === "find_now") return found();
        if (order?.kind !== "fill_now") return undefined;
        const fields = findLoginFields(document, isVisible)[0];
        if (!fields) return Promise.resolve(false);
        return fillInto(fields, order.item).then(() => true);
      });
      // A sign-in that led here (a new page) may still wait for an answer.
      void ask<Proposal | null>({ kind: "pending" }).then((proposal) => {
        if (proposal) propose(proposal);
      });
    }
  },
});
