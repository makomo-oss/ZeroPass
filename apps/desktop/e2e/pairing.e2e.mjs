// End-to-end test of pairing in the desktop application: two copies of the
// real program, each with its own vault, vault daemon and sync daemon, on
// this computer. One adds a device, the other joins with the code; then they
// sync over the local network and the first revokes the second.
//
// Needs a local network interface with multicast, like the LAN tests of
// zp-cli and zp-transport; it is run by hand, not in CI. Build as for
// app.e2e.mjs, then:
//
//   node e2e/pairing.e2e.mjs [--release]

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { expect, failed, finish, launch, shot, step } from "./harness.mjs";

const PASSWORD_A = "first device passphrase";
const PASSWORD_B = "second device passphrase";

const dir = mkdtempSync(join(tmpdir(), "zeropass-pairing-"));
let a;
let b;
try {
  a = await launch(join(dir, "a.zpvault"), join(dir, "webview-a"));
  await step("the first device creates a vault with a login", async () => {
    const { page, button } = a;
    await page.getByLabel("Master password", { exact: true }).fill(PASSWORD_A);
    await page.getByLabel("Repeat the master password").fill(PASSWORD_A);
    await button("Create vault").click();
    await page.getByRole("button", { name: /^Logins/ }).waitFor();
    await page.getByTitle("New login").click();
    await page.getByLabel("Title").fill("Shared login");
    await page.locator("input[type=password]").fill("shared password 1");
    await button("Save").click();
    await page.getByRole("heading", { name: "Shared login" }).waitFor();
  });

  let code = "";
  await step("the first device shows a pairing code once its sync daemon waits", async () => {
    const { page, button } = a;
    await page.getByRole("button", { name: /^Devices/ }).click();
    await page.getByText(/Syncing with nearby devices/).waitFor({ timeout: 30_000 });
    await button("Add a device").click();
    const shown = page.getByLabel("pairing code");
    await shown.waitFor({ timeout: 30_000 });
    code = ((await shown.textContent()) ?? "").trim();
    expect(code.length > 20, `the code is ${code}`);
    expect(await page.getByAltText("Pairing code as a QR code").isVisible(), "no QR code");
    await shot(page, "pair-1-code");
  });

  b = await launch(join(dir, "b.zpvault"), join(dir, "webview-b"));
  await step("the second device joins with the code", async () => {
    const { page, button } = b;
    await button("Join a vault from another device instead").click();
    await page.getByLabel("Pairing code").fill(code);
    await page.getByLabel(/^This device's name/).fill("Second PC");
    await page.getByLabel(/^Master password for this device/).fill(PASSWORD_B);
    await page.getByLabel("Repeat the master password").fill(PASSWORD_B);
    await button("Join").click();
    await page.getByText(/^Connecting/).waitFor();
  });

  await step("the first device asks whether it may join, and admits it", async () => {
    const { page, button } = a;
    await page.getByRole("heading", { name: "Add this device to the vault?" }).waitFor({ timeout: 60_000 });
    await page.getByText("Second PC", { exact: true }).waitFor();
    await shot(page, "pair-2-confirm");
    await button("Add the device").click();
    await page.getByRole("heading", { name: "Device added" }).waitFor({ timeout: 60_000 });
    await shot(page, "pair-3-done");
  });

  await step("the second device has the vault, with the login", async () => {
    const { page } = b;
    await page.getByRole("button", { name: /^Logins/ }).waitFor({ timeout: 60_000 });
    await page.locator("ul.items").getByText("Shared login").waitFor();
  });

  await step("both devices list both devices", async () => {
    const { page, button } = a;
    await button("Close").click();
    await page.getByRole("cell", { name: /Second PC/ }).waitFor();
    await b.page.getByRole("button", { name: /^Devices/ }).click();
    await b.page.getByText("This device", { exact: true }).waitFor();
    await shot(b.page, "pair-4-devices");
  });

  await step("a change made on the second device reaches the first with a sync", async () => {
    await b.page.getByRole("button", { name: /^Logins/ }).click();
    await b.page.getByTitle("New login").click();
    await b.page.getByLabel("Title").fill("From the second PC");
    await b.page.locator("input[type=password]").fill("second password 2");
    await b.button("Save").click();
    await b.page.getByRole("heading", { name: "From the second PC" }).waitFor();
    await b.page.getByRole("button", { name: /^Devices/ }).click();
    await b.page.getByText(/Syncing with nearby devices/).waitFor({ timeout: 30_000 });
    await b.button("Sync now").click();
    await b.page.getByText(/^Synced with/).waitFor({ timeout: 60_000 });
    await a.page.getByRole("button", { name: /^Logins/ }).click();
    await a.page.locator("ul.items").getByText("From the second PC").waitFor();
  });

  await step("the first device revokes the second", async () => {
    const { page, button } = a;
    await page.getByRole("button", { name: /^Devices/ }).click();
    const row = page.getByRole("row", { name: /Second PC/ });
    await row.getByRole("button", { name: "Revoke" }).click();
    await row.getByRole("button", { name: "Revoke" }).click();
    await page.getByText(/was revoked and the vault keys were replaced/).waitFor({ timeout: 30_000 });
    await row.getByRole("cell", { name: "Revoked" }).waitFor();
  });

  await step("neither page reported errors", async () => {
    const problems = [...a.problems, ...b.problems];
    expect(problems.length === 0, problems.join("\n"));
  });
} catch (error) {
  failed(error);
} finally {
  await b?.close();
  await a?.close();
  // Each copy started a sync daemon too.
  for (const name of ["a", "b"]) {
    const { spawnSync } = await import("node:child_process");
    const { bin } = await import("./harness.mjs");
    spawnSync(bin("zp-cli"), ["--vault", join(dir, `${name}.zpvault`), "daemon", "stop"], {
      stdio: "ignore",
    });
  }
  // A daemon that is still ending holds its files for a moment (Windows:
  // EPERM, EBUSY); rmSync retries those.
  await sleep(500);
  rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
}
finish();
