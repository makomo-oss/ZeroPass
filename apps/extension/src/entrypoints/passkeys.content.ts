// In every frame, from the start: the extension's side of passkey requests
// (docs/spec/extension.md §11). The page script (webauthn.content.ts) hands
// them over; the background asks ZeroPass.

import { browser } from "wxt/browser";
import { defineContentScript } from "wxt/utils/define-content-script";

import { servePasskeys } from "../lib/passkeys";
import type { Ask } from "../lib/protocol";

export default defineContentScript({
  matches: ["<all_urls>"],
  allFrames: true,
  runAt: "document_start",
  main() {
    servePasskeys(window, <T>(message: Ask) => browser.runtime.sendMessage(message) as Promise<T>);
  },
});
