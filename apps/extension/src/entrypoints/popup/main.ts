// The toolbar popup: where ZeroPass stands, and the logins of the current
// tab's page, to fill with one click.

import { browser } from "wxt/browser";

import type { Ask, BridgeStatus, FindAnswer } from "../../lib/protocol";

const main = document.getElementById("main") as HTMLElement;

function ask<T>(message: Ask): Promise<T> {
  return browser.runtime.sendMessage(message) as Promise<T>;
}

function paragraph(text: string, muted = false): HTMLParagraphElement {
  const p = document.createElement("p");
  p.textContent = text;
  if (muted) p.className = "muted";
  return p;
}

function openButton(): HTMLButtonElement {
  const button = document.createElement("button");
  button.className = "primary";
  button.textContent = "Open ZeroPass";
  button.addEventListener("click", () => {
    void ask({ kind: "open_app" });
    window.close();
  });
  return button;
}

async function show(): Promise<void> {
  const status = await ask<BridgeStatus | { code: string; message: string }>({ kind: "status" });
  main.replaceChildren();
  if ("code" in status) {
    main.append(
      paragraph(
        status.code === "Unavailable"
          ? "The ZeroPass desktop application is not installed, or its bridge is not registered."
          : status.message,
      ),
    );
    return;
  }
  if (!status.vault) {
    main.append(paragraph("ZeroPass has no vault yet."), openButton());
    return;
  }
  if (!status.running) {
    main.append(paragraph("ZeroPass is not running."), openButton());
    return;
  }
  if (!status.unlocked) {
    main.append(paragraph("ZeroPass is locked."), openButton());
    return;
  }
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) {
    main.append(paragraph("No page.", true));
    return;
  }
  const found = await ask<FindAnswer>({ kind: "find_for_tab", tab: tab.id });
  if (found.state === "unsupported") {
    main.append(paragraph("ZeroPass fills web pages (https and http) only.", true));
    return;
  }
  if (found.logins.length === 0) {
    main.append(paragraph("No login of this vault belongs to this page.", true));
    return;
  }
  main.append(paragraph("Fill into this page:", true));
  const list = document.createElement("ul");
  for (const login of found.logins) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    const title = document.createElement("span");
    title.className = "title";
    title.textContent = login.title || login.username || "(no title)";
    const sub = document.createElement("span");
    sub.className = "sub";
    sub.textContent = login.match === "exact" ? login.username : `${login.username} · same site`;
    button.append(title, sub);
    button.addEventListener("click", () => {
      void ask({ kind: "fill_tab", tab: tab.id as number, item: login.id }).finally(() => window.close());
    });
    item.append(button);
    list.append(item);
  }
  main.append(list);
}

void show().catch((error: unknown) => {
  main.replaceChildren(paragraph(String(error)));
});
