// The background: the only part of the extension that talks to ZeroPass. It
// takes the origin of a request from the browser (`sender`), never from the
// request (docs/spec/extension.md §1, §6).

import { browser } from "wxt/browser";
import { defineBackground } from "wxt/utils/define-background";

import { Bridge } from "../lib/bridge";
import { originsOf, webOrigin, type Sender } from "../lib/origins";
import {
  stateOf,
  type Ask,
  type BridgeError,
  type FillAnswer,
  type FindAnswer,
  type Login,
  type Order,
} from "../lib/protocol";

const bridge = new Bridge();

function failed(error: unknown): BridgeError {
  if (typeof error === "object" && error !== null && "code" in error) {
    return error as BridgeError;
  }
  return { code: "Internal", message: String(error) };
}

async function find(origin: string, top: string): Promise<FindAnswer> {
  try {
    const reply = await bridge.ask({ type: "find", origin, top });
    return { state: "ok", logins: (reply.logins as Login[]) ?? [] };
  } catch (error) {
    const { code, message } = failed(error);
    return { state: stateOf(code), logins: [], message };
  }
}

async function fill(origin: string, top: string, item: string): Promise<FillAnswer> {
  try {
    const reply = await bridge.ask({ type: "fill", origin, top, item });
    return { ok: true, username: String(reply.username ?? ""), password: String(reply.password ?? "") };
  } catch (error) {
    const { code, message } = failed(error);
    return { ok: false, state: stateOf(code), message };
  }
}

/** Whether a message comes from the extension's own pages (the popup). */
function fromExtension(sender: Sender & { id?: string }): boolean {
  return sender.id === browser.runtime.id && !sender.tab && (sender.url ?? "").startsWith(browser.runtime.getURL("/"));
}

async function handle(ask: Ask, sender: Sender & { id?: string }): Promise<unknown> {
  switch (ask.kind) {
    // From a page's content script: about that frame, as the browser says.
    case "find": {
      const origins = sender.tab ? originsOf(sender) : null;
      if (!origins) return { state: "unsupported", logins: [] } satisfies FindAnswer;
      return find(origins.origin, origins.top);
    }
    case "fill": {
      const origins = sender.tab ? originsOf(sender) : null;
      if (!origins) return { ok: false, state: "unsupported", message: "not a web page" } satisfies FillAnswer;
      return fill(origins.origin, origins.top, ask.item);
    }
    case "open_app":
      return bridge.ask({ type: "open_app" }).catch(failed);
    // From the popup only.
    case "status":
      if (!fromExtension(sender)) return null;
      return bridge.ask({ type: "status" }).catch(failed);
    case "find_for_tab": {
      if (!fromExtension(sender)) return null;
      const tab = await browser.tabs.get(ask.tab);
      const origin = webOrigin(tab.url);
      if (!origin) return { state: "unsupported", logins: [] } satisfies FindAnswer;
      return find(origin, origin);
    }
    case "fill_tab": {
      if (!fromExtension(sender)) return null;
      // The page's top frame asks for the login itself, so that the origin
      // is again the browser's.
      const order: Order = { kind: "fill_now", item: ask.item };
      return browser.tabs.sendMessage(ask.tab, order, { frameId: 0 });
    }
  }
}

export default defineBackground(() => {
  browser.runtime.onMessage.addListener((message: unknown, sender) => {
    if (typeof message !== "object" || message === null || !("kind" in message)) return undefined;
    return handle(message as Ask, sender as Sender & { id?: string });
  });
});
