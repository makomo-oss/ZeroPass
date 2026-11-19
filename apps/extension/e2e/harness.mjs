// What the extension's end-to-end tests share: a vault made with the real
// zp-cli and served by the real vault daemon, the real bridge zp-nmh
// registered for the test browser, and Chromium with the built extension.
// Windows only (the bridge is registered in the registry).
//
// Build first:
//   cd apps/extension && npm run build
//   cargo build -p zp-nmh -p zp-vaultd -p zp-cli

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { chromium } from "playwright";

export const EXTENSION_ID = "gehobienihkbhglhnibeobdkgeinamdn";
export const NATIVE_HOST = "io.github.makomo_oss.zeropass";
export const PASSWORD = "correct horse battery staple";

const root = resolve(import.meta.dirname, "..", "..", "..");
const profile = process.argv.includes("--release") ? "release" : "debug";
export const bin = (name) => join(root, "target", profile, `${name}.exe`);
export const extensionDir = join(root, "apps", "extension", ".output", "chrome-mv3");

/**
 * Where the test browser looks for native messaging hosts, per user: the
 * Chromium of Playwright reads one of these, depending on its build.
 */
export const HOST_KEYS = [
  `HKCU\\Software\\Chromium\\NativeMessagingHosts\\${NATIVE_HOST}`,
  `HKCU\\Software\\Google\\Chrome for Testing\\NativeMessagingHosts\\${NATIVE_HOST}`,
];

let failures = 0;

export async function step(name, run, onFailure) {
  try {
    await run();
    console.log(`ok: ${name}`);
  } catch (error) {
    failures += 1;
    await onFailure?.().catch(() => {});
    console.log(`FAILED: ${name}\n  ${String(error).split("\n").join("\n  ")}`);
    throw error;
  }
}

export function expect(condition, message) {
  if (!condition) throw new Error(message);
}

export function finish() {
  if (failures > 0) {
    console.log(`${failures} step(s) failed`);
    process.exit(1);
  }
  console.log("all steps passed");
}

export function failed(error) {
  if (failures === 0 && error) console.log(`FAILED: ${error}`);
  failures = Math.max(failures, 1);
}

/** This process's environment, without a vault named by it. */
export function withoutVault() {
  const env = { ...process.env };
  delete env.ZEROPASS_VAULT;
  return env;
}

/** Runs zp-cli on the test vault; each of `input` answers one prompt. */
export function cli(vault, args, input = []) {
  // The development key store stands in for Windows Hello: no prompt.
  const result = spawnSync(bin("zp-cli"), ["--vault", vault, "--insecure-software-keystore", ...args], {
    input: input.map((line) => `${line}\n`).join(""),
    encoding: "utf8",
    env: withoutVault(),
  });
  if (result.status !== 0) {
    throw new Error(`zp-cli ${args.join(" ")}: ${result.stdout}${result.stderr}`);
  }
  return result.stdout;
}

/** Adds a login and returns its identifier. */
export function addLogin(vault, title, username, password, url) {
  const out = cli(vault, ["add", "login", "--title", title, "--username", username, "--url", url], [password]);
  return /added ([0-9a-f]{32})/.exec(out)?.[1];
}

/**
 * A new vault, unlocked, in a temporary directory, and the bridge
 * registered for the test browser. `close` undoes all of it.
 */
export function setUp() {
  const dir = mkdtempSync(join(tmpdir(), "zeropass-extension-"));
  const vault = join(dir, "extension.zpvault");
  cli(vault, ["init"], [PASSWORD, PASSWORD]);
  cli(vault, ["unlock"], [PASSWORD]);
  const manifest = join(dir, "zp-nmh-chrome.json");
  writeFileSync(
    manifest,
    JSON.stringify({
      name: NATIVE_HOST,
      description: "ZeroPass (test)",
      path: bin("zp-nmh"),
      type: "stdio",
      allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
    }),
  );
  for (const key of HOST_KEYS) {
    execFileSync("reg", ["add", key, "/ve", "/t", "REG_SZ", "/d", manifest, "/f"], { stdio: "ignore" });
  }
  return {
    dir,
    vault,
    close() {
      for (const key of HOST_KEYS) {
        spawnSync("reg", ["delete", key, "/f"], { stdio: "ignore" });
      }
      spawnSync(bin("zp-cli"), ["--vault", vault, "daemon", "stop"], { stdio: "ignore" });
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Chromium with the extension, without a window, its bridge on `vault`. */
export async function launchBrowser(dir, vault) {
  const context = await chromium.launchPersistentContext(join(dir, "browser"), {
    channel: "chromium",
    // --offscreen: with a window, as a user's browser (some sites refuse
    // headless ones), but out of sight.
    headless: !process.argv.includes("--headed") && !process.argv.includes("--offscreen"),
    args: [
      `--disable-extensions-except=${extensionDir}`,
      `--load-extension=${extensionDir}`,
      ...(process.argv.includes("--offscreen") ? ["--window-position=-32000,-32000"] : []),
    ],
    env: { ...process.env, ZEROPASS_VAULT: vault },
    viewport: { width: 1280, height: 900 },
  });
  // The extension's background starts with the browser.
  let worker = context.serviceWorkers()[0];
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 15_000 });
  expect(worker.url().startsWith(`chrome-extension://${EXTENSION_ID}/`), `unexpected extension: ${worker.url()}`);
  return context;
}

/** Whether the suggestion list is showing in `frame`. */
export function suggestionsShown(frame) {
  return frame.evaluate(() => document.querySelector("zeropass-suggestions") !== null);
}

/**
 * Clicks, as a user would, the first element inside the closed shadow root
 * of the `hostTag` element that `matches` (a DevTools node: nodeName and a
 * flat attribute list). The page cannot reach into a closed shadow root;
 * the DevTools protocol can, to find where it is drawn. Returns whether
 * there was one (in the page's own document; not in out-of-process frames).
 */
export async function clickClosed(page, hostTag, matches) {
  const cdp = await page.context().newCDPSession(page);
  try {
    const { root } = await cdp.send("DOM.getDocument", { depth: -1, pierce: true });
    const search = (node, test) => {
      if (test(node)) return node;
      for (const child of [...(node.children ?? []), ...(node.shadowRoots ?? []), ...(node.contentDocument ? [node.contentDocument] : [])]) {
        const found = search(child, test);
        if (found) return found;
      }
      return null;
    };
    const host = search(root, (node) => node.nodeName === hostTag.toUpperCase());
    if (!host) return false;
    const target = search({ children: host.shadowRoots ?? [] }, (node) => node.nodeId !== undefined && matches(node));
    if (!target) return false;
    const { model } = await cdp.send("DOM.getBoxModel", { nodeId: target.nodeId });
    const [x1, y1, , , x3, y3] = model.content;
    await page.mouse.click((x1 + x3) / 2, (y1 + y3) / 2);
    return true;
  } finally {
    await cdp.detach().catch(() => {});
  }
}

/** A DevTools node's attribute. */
export function attribute(node, name) {
  const attributes = node.attributes ?? [];
  for (let index = 0; index < attributes.length; index += 2) {
    if (attributes[index] === name) return attributes[index + 1];
  }
  return undefined;
}

/**
 * Clicks the first login of the suggestion list under `field`. The list is
 * in a closed shadow root, so it is clicked where it is drawn: a real
 * (trusted) click, as a user's.
 */
export async function pickFirst(page, field) {
  const clicked = await clickClosed(
    page,
    "zeropass-suggestions",
    (node) => node.nodeName === "BUTTON" && (attribute(node, "class") ?? "").split(" ").includes("item"),
  ).catch(() => false);
  if (clicked) return;
  // In a frame of another process the list cannot be found: click where
  // it is drawn.
  const box = await field.boundingBox();
  expect(box, "the field has no box");
  // 4 px gap, a 27 px heading, then the first item (about 48 px high).
  await page.mouse.click(box.x + 30, box.y + box.height + 4 + 27 + 20);
}
