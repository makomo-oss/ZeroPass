// In the page's own world, before its scripts: passkeys through ZeroPass
// (docs/spec/extension.md §11). Keeps nothing; talks to the content script
// of the same frame only.

import { defineContentScript } from "wxt/utils/define-content-script";

import { install } from "../lib/webauthn-page";

export default defineContentScript({
  matches: ["<all_urls>"],
  allFrames: true,
  runAt: "document_start",
  world: "MAIN",
  main() {
    install(window);
  },
});
