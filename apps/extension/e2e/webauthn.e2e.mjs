// End-to-end passkey test against the real https://webauthn.io/ site
// (PLAN.md P5-04): registers a ZeroPass passkey on webauthn.io and signs in
// with it, verifying real server-side WebAuthn registration and assertion
// checks. Needs the internet; run by hand:
//
//   node e2e/webauthn.e2e.mjs [--headed | --offscreen]

import { join } from "node:path";

import {
  attribute,
  clickClosed,
  cli,
  expect,
  failed,
  finish,
  launchBrowser,
  setUp,
  step,
} from "./harness.mjs";

const setup = setUp();
let context;
try {
  context = await launchBrowser(setup.dir, setup.vault);
  const page = await context.newPage();
  const shot = (name) => page.screenshot({ path: join(setup.dir, "..", `zeropass-webauthn-${name}.png`) });

  const pressPrompt = (cls) =>
    clickClosed(
      page,
      "zeropass-passkey-prompt",
      (node) => node.nodeName === "BUTTON" && (attribute(node, "class") ?? "").split(" ").includes(cls),
    );

  const username = `zeropass-test-${Date.now()}`;

  await step("register a passkey on https://webauthn.io/", async () => {
    await page.goto("https://webauthn.io/", { waitUntil: "domcontentloaded", timeout: 30_000 });
    await page.locator("#input-email").fill(username);
    await page.locator("#register-button").click();

    await page.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
      timeout: 20_000,
    });
    expect(await pressPrompt("save"), "Save in ZeroPass button was not found on webauthn.io");

    // webauthn.io displays a success message once its server verifies attestationObject + clientDataJSON.
    await page.waitForFunction(
      () => /success/i.test(document.body.innerText),
      null,
      { timeout: 20_000 },
    );
  }, () => shot("register"));

  await step("authenticate with the ZeroPass passkey on https://webauthn.io/", async () => {
    await page.locator("#login-button").click();

    await page.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
      timeout: 20_000,
    });
    expect(await pressPrompt("candidate"), "ZeroPass passkey candidate button was not found on webauthn.io");

    // webauthn.io redirects to /dashboard or shows logged-in confirmation once server verifies the signature.
    await page.waitForFunction(
      () =>
        /logged in|authenticated|success/i.test(document.body.innerText) &&
        (window.location.pathname !== "/" || /logged in/i.test(document.body.innerText)),
      null,
      { timeout: 20_000 },
    );
  }, () => shot("authenticate"));

  await step("re-authenticate on https://webauthn.io/ after locking the vault", async () => {
    cli(setup.vault, ["lock"]);
    await page.goto("https://webauthn.io/", { waitUntil: "domcontentloaded", timeout: 30_000 });
    await page.locator("#input-email").fill(username);
    await page.locator("#login-button").click();

    await page.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
      timeout: 20_000,
    });
    expect(await pressPrompt("unlock"), "Sign in with ZeroPass button was not found");

    await page.waitForFunction(
      () =>
        /logged in|authenticated|success/i.test(document.body.innerText) &&
        (window.location.pathname !== "/" || /logged in/i.test(document.body.innerText)),
      null,
      { timeout: 20_000 },
    );
  }, () => shot("authenticate-locked"));
} catch (error) {
  failed(error);
} finally {
  await context?.close().catch(() => {});
  setup.close();
}
finish();
