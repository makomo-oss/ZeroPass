// In every frame of every page: finds login fields, offers the matching
// logins under the field the user is in, and fills the one the user picks
// (docs/spec/extension.md §7). It never fills by itself and keeps nothing.

import { browser } from "wxt/browser";
import { defineContentScript } from "wxt/utils/define-content-script";

import { fieldsOf, findLoginFields, type LoginFields } from "../lib/detect";
import { fillLogin } from "../lib/fill";
import type { Ask, FillAnswer, FindAnswer, Login, Order } from "../lib/protocol";
import { Suggestions } from "../lib/suggestions";
import { isVisible } from "../lib/visible";

/** How long the logins found for this frame are reused. */
const CACHE_MS = 15_000;

function ask<T>(message: Ask): Promise<T> {
  return browser.runtime.sendMessage(message) as Promise<T>;
}

export default defineContentScript({
  matches: ["<all_urls>"],
  allFrames: true,
  runAt: "document_idle",
  main() {
    let anchor: HTMLInputElement | null = null;
    let cached: { at: number; answer: FindAnswer } | null = null;

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
        if (fields.username ?? fields.password) {
          suggestions.show((fields.username ?? fields.password) as HTMLInputElement, answer.state, []);
        }
        return;
      }
      fillLogin(fields, answer.username, answer.password);
      // The answer goes out of reach here; nothing keeps it.
    }

    const suggestions = new Suggestions({
      onPick: (login: Login) => {
        const field = anchor;
        if (!field) return;
        const fields = fieldsOf(field, document, isVisible);
        if (fields) void fillInto(fields, login.id);
      },
      onOpenApp: () => {
        cached = null;
        void ask({ kind: "open_app" });
      },
    });

    async function offer(field: HTMLInputElement): Promise<void> {
      if (!fieldsOf(field, document, isVisible)) {
        suggestions.hide();
        return;
      }
      anchor = field;
      const answer = await found();
      // The user may have moved on while ZeroPass answered.
      if (anchor !== field || !isFocused(field)) return;
      suggestions.show(field, answer.state, answer.logins);
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

    document.addEventListener(
      "focusin",
      (event) => {
        const field = inputOf(event);
        if (field) void offer(field);
        else if (!suggestions.contains(event.target)) suggestions.hide();
      },
      true,
    );
    // A click into a field that already has the focus.
    document.addEventListener(
      "click",
      (event) => {
        const field = inputOf(event);
        if (field && event.isTrusted && !suggestions.open) void offer(field);
      },
      true,
    );
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
        if (event.key === "Escape") suggestions.hide();
      },
      true,
    );

    // From the popup, through the background, to the top frame only.
    if (window.top === window) {
      browser.runtime.onMessage.addListener((message: unknown) => {
        const order = message as Order;
        if (order?.kind !== "fill_now") return undefined;
        const fields = findLoginFields(document, isVisible)[0];
        if (!fields) return Promise.resolve(false);
        return fillInto(fields, order.item).then(() => true);
      });
    }
  },
});
