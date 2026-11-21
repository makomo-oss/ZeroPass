// Registers a passkey on https://webauthn.io through ZeroPass and signs in
// with it (task P5-04): the real extension in Chromium, the real bridge and
// vault daemon (the development key store stands in for Windows Hello).
// webauthn.io is a public demonstration relying party; the test account is
// a new random name each run. Not run in CI (it needs the site). Windows only.
//
//   node e2e/webauthn-io.e2e.mjs --offscreen [--headed]

import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { attribute, clickClosed, cli, expect, failed, finish, launchBrowser, setUp, step } from "./harness.mjs";

const SITE = "https://webauthn.io/";
const USER = `zeropass-e2e-${randomBytes(4).toString("hex")}`;

const setup = setUp();
let context;
try {
  context = await launchBrowser(setup.dir, setup.vault);
  const page = await context.newPage();
  const shot = (name) => page.screenshot({ path: join(setup.dir, "..", `zeropass-webauthn-io-${name}.png`) });

  async function press(action) {
    await page.waitForFunction(() => document.querySelector("zeropass-passkey") !== null, null, { timeout: 20_000 });
    for (let attempt = 0; attempt < 50; attempt++) {
      const clicked = await clickClosed(
        page,
        "zeropass-passkey",
        (node) => node.nodeName === "BUTTON" && attribute(node, "data-action") === action,
      ).catch(() => false);
      if (clicked) return;
      await sleep(200);
    }
    throw new Error(`no "${action}" button in the dialog`);
  }

  const alertText = () => page.locator(".alert").first().textContent({ timeout: 30_000 }).catch(() => "");

  await step(`a passkey for ${USER} is registered on webauthn.io and kept in ZeroPass`, async () => {
    await page.goto(SITE, { waitUntil: "domcontentloaded", timeout: 60_000 });
    const name = page.locator("#input-email");
    await name.waitFor({ timeout: 30_000 });
    await name.fill(USER);
    // ZeroPass's list of logins opens under the field; out of the way.
    await page.keyboard.press("Escape");
    await page.locator("#register-button").click();
    await page.waitForFunction(() => document.querySelector("zeropass-passkey") !== null, null, { timeout: 20_000 });
    await shot("dialog");
    await press("zeropass");
    await page.waitForFunction(
      () => /Success/.test(document.querySelector(".alert")?.textContent ?? ""),
      null,
      { timeout: 30_000 },
    );
    const listed = cli(setup.vault, ["list", "--domain", "passkey"]);
    expect(listed.includes("webauthn.io") && listed.includes("1 item(s)"), `the vault lists:\n${listed}`);
  }, async () => {
    console.log(`  the page says: ${await alertText()}`);
    await shot("register");
  });

  await step("signing in to webauthn.io with it reaches the profile page", async () => {
    await page.locator("#login-button").click();
    await press("zeropass");
    await page.waitForURL(/\/profile/, { timeout: 30_000 });
    await shot("profile");
  }, async () => {
    console.log(`  the page says: ${await alertText()}`);
    await shot("authenticate");
  });
} catch (error) {
  failed(error);
} finally {
  await context?.close().catch(() => {});
  setup.close();
}
finish();
