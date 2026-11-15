// What the end-to-end tests share: starting the real application with its
// webview's debugging protocol open, and reporting steps.

import { spawn, spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { chromium } from "playwright-core";

export const profile = process.argv.includes("--release") ? "release" : "debug";
const root = resolve(import.meta.dirname, "..", "..", "..");

/** A program of this build. */
export function bin(name) {
  return join(root, "target", profile, `${name}.exe`);
}

let failures = 0;
const pages = new Set();

/** Runs one step; on failure keeps a picture of every open window. */
export async function step(name, run) {
  try {
    await run();
    console.log(`ok: ${name}`);
  } catch (error) {
    failures += 1;
    let index = 0;
    for (const page of pages) {
      const picture = join(tmpdir(), `zeropass-e2e-failure-${Date.now()}-${index++}.png`);
      await page.screenshot({ path: picture }).catch(() => {});
      console.log(`  screenshot: ${picture}`);
    }
    console.log(`FAILED: ${name}\n  ${String(error).split("\n").join("\n  ")}`);
    throw error;
  }
}

export function expect(condition, message) {
  if (!condition) throw new Error(message);
}

/** With E2E_SCREENSHOTS=<dir>, keeps a picture of `page` under `name`. */
export async function shot(page, name) {
  if (process.env.E2E_SCREENSHOTS) {
    await page.screenshot({ path: join(process.env.E2E_SCREENSHOTS, `${name}.png`) });
  }
}

/**
 * Starts the application for `vault` (development key store, no Windows
 * Hello) with a webview of its own (`dataDir`), and connects to its page.
 */
export async function launch(vault, dataDir) {
  const port = 9300 + Math.floor(Math.random() * 600);
  mkdirSync(dataDir, { recursive: true });
  const start = () => spawn(bin("zeropass"), ["--vault", vault, "--insecure-software-keystore"], {
    env: {
      ...process.env,
      ZEROPASS_VAULT: "",
      WEBVIEW2_USER_DATA_FOLDER: dataDir,
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port}`,
      // Development builds also pass it themselves (main.rs): some WebView2
      // versions ignore the variable above.
      ZEROPASS_E2E_CDP_PORT: String(port),
    },
    stdio: "ignore",
  });
  // A program just built may not start at once (a virus scanner still
  // reading it): try again for a while, rather than fail.
  let app;
  for (let attempt = 0; ; attempt += 1) {
    app = start();
    const started = await new Promise((resolve) => {
      app.once("spawn", () => resolve(null));
      app.once("error", (error) => resolve(error));
    });
    if (started === null) break;
    if (attempt >= 10) throw started;
    await sleep(1000);
  }
  let exited = null;
  app.on("exit", (code) => (exited = code));
  let browser;
  for (let attempt = 0; ; attempt += 1) {
    try {
      browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
      break;
    } catch (error) {
      if (exited !== null) throw new Error(`the application ended (exit code ${exited})`);
      // A first start creates the webview's profile: slow on a fresh machine.
      if (attempt > 300) {
        // What the webview runs as, to tell why its port did not open.
        const report = spawnSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_Process -Filter \"name='msedgewebview2.exe' or name='zeropass.exe'\" | Where-Object { $_.CommandLine -like '*zeropass*' -and $_.CommandLine -notlike '*--type=*' } | ForEach-Object { $_.ProcessId.ToString() + ' ' + $_.CommandLine }; Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -ge 9000 -and $_.LocalPort -lt 10000 } | ForEach-Object { 'listen ' + $_.LocalAddress + ':' + $_.LocalPort + ' pid ' + $_.OwningProcess }",
          ],
          { encoding: "utf8" },
        );
        console.log(`  webview processes and ports (port ${port}):\n${report.stdout}${report.stderr}`);
        throw error;
      }
      await sleep(200);
    }
  }
  const context = browser.contexts()[0];
  let page = context.pages()[0];
  for (let attempt = 0; !page; attempt += 1) {
    if (attempt > 100) throw new Error("the webview has no page");
    await sleep(100);
    page = context.pages()[0];
  }
  const problems = [];
  page.on("console", (message) => {
    if (message.type() === "error" || message.type() === "warning") {
      problems.push(`${message.type()}: ${message.text()}`);
    }
  });
  page.on("pageerror", (error) => problems.push(`page error: ${error.message}`));
  page.setDefaultTimeout(15_000);
  pages.add(page);
  return {
    page,
    problems,
    button: (name) => page.getByRole("button", { name, exact: true }),
    async close() {
      pages.delete(page);
      await browser.close().catch(() => {});
      app.kill();
      spawnSync(bin("zp-cli"), ["--vault", vault, "daemon", "stop"], { stdio: "ignore" });
    },
  };
}

/** Ends the run: the exit code says whether every step passed. */
export function finish() {
  if (failures > 0) {
    console.log(`${failures} step(s) failed`);
    process.exit(1);
  }
  console.log("all steps passed");
}

/** Marks the run as failed (a step already said why). */
export function failed(error) {
  // A failed step said why already; anything else is said here.
  if (failures === 0 && error) console.log(`FAILED: ${error}`);
  failures = Math.max(failures, 1);
}
