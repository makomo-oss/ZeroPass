// End-to-end test of the desktop application: drives the real program
// (target/<profile>/zeropass), which starts the real vault daemon, through
// the webview's debugging protocol. Windows only (WebView2).
//
//   cd apps/desktop && npm run build && cargo build -p zeropass-desktop -p zp-vaultd -p zp-keyagent -p zp-syncd -p zp-cli
//   node e2e/app.e2e.mjs [--release]
//
// The vault is a new file in a temporary directory, protected by the
// development-only software key store (no Windows Hello prompt), and the
// daemon is stopped at the end.

import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { expect, failed, finish, launch, shot as picture, step } from "./harness.mjs";

const PASSWORD = "correct horse battery staple";
const NEW_PASSWORD = "a different long passphrase";
// The RFC 6238 SHA-1 test secret.
const TOTP_URI =
  "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";

const dir = mkdtempSync(join(tmpdir(), "zeropass-e2e-"));
const vault = join(dir, "e2e.zpvault");

let app;
try {
  app = await launch(vault, join(dir, "webview"));
  const { page, button } = app;
  const consoleProblems = app.problems;
  const shot = (name) => picture(page, name);

  await step("a new vault is offered", async () => {
    await page.getByRole("heading", { name: "Create your vault" }).waitFor();
    await shot("1-create");
  });

  await step("a short master password is refused", async () => {
    await page.getByLabel("Master password", { exact: true }).fill("short");
    await page.getByText("Use at least 12 characters").waitFor();
    expect(await button("Create vault").isDisabled(), "Create vault is enabled");
  });

  await step("the vault is created and open", async () => {
    await page.getByLabel("Master password", { exact: true }).fill(PASSWORD);
    await page.getByLabel("Repeat the master password").fill(PASSWORD);
    await button("Create vault").click();
    await page.getByText("This vault has no recovery kit yet.").waitFor();
  });

  await step("a recovery kit is made and its key shown once", async () => {
    await page.getByRole("button", { name: /^Settings/ }).click();
    await button("Make a recovery kit").click();
    const key = await page.getByLabel("recovery key").textContent();
    expect(key && key.trim().length >= 20, `recovery key looks wrong: ${key}`);
    await button("I have written it down").click();
    await page.getByText("This vault has a recovery kit.").waitFor();
  });

  let generated = "";
  await step("a login is added with a generated password", async () => {
    await page.getByRole("button", { name: /^Logins/ }).click();
    await page.getByTitle("New login").click();
    await page.getByLabel("Title").fill("Example Bank");
    await page.getByLabel("User name or e-mail").fill("alice@example.com");
    await button("Generate…").click();
    await page.waitForFunction(() => (document.querySelector("output.password")?.textContent ?? "").length === 20);
    generated = (await page.locator("output.password").textContent()) ?? "";
    expect(generated.length === 20, `generated password has length ${generated.length}`);
    await button("Use this password").click();
    await page.getByLabel("Websites (one per line)").fill("https://bank.example.com/login\n");
    await button("Save").click();
    await page.getByRole("heading", { name: "Example Bank" }).waitFor();
    await shot("2-login");
  });

  await step("the password is hidden until shown", async () => {
    expect(
      !(await page.content()).includes(generated),
      "the password is in the page before Show",
    );
    await button("Show").click();
    await page.getByText(generated, { exact: true }).waitFor();
    await button("Hide").click();
  });

  await step("the password is copied without passing through the page", async () => {
    await page.getByRole("button", { name: "Copy" }).nth(1).click();
    // As for the clipboard tests of zp-clipboard: only where this process may
    // use the clipboard (CI sets the variable; some shells cannot).
    if (process.env.ZEROPASS_TEST_CLIPBOARD === "1") {
      await page.getByRole("button", { name: "Copied" }).waitFor();
    } else {
      await page
        .getByRole("button", { name: "Copied" })
        .or(page.locator("p.notice.error"))
        .first()
        .waitFor();
      if (await page.locator("p.notice.error").count()) {
        console.log("  (the clipboard is not available here; set ZEROPASS_TEST_CLIPBOARD=1 to require it)");
        await page.getByRole("button", { name: /^Logins/ }).click();
        await page.locator("ul.items").getByText("Example Bank").click();
      }
    }
  });

  await step("editing keeps the password the user did not change", async () => {
    await button("Edit").click();
    await page.getByLabel("Title").fill("Example Bank (main)");
    await button("Save").click();
    await page.getByRole("heading", { name: "Example Bank (main)" }).waitFor();
    await button("Show").click();
    await page.getByText(generated, { exact: true }).waitFor();
    await button("Hide").click();
  });

  await step("search narrows the list", async () => {
    await page.getByTitle("New login").click();
    await page.getByLabel("Title").fill("Mail");
    await page.locator("input[type=password]").fill("mail password 123");
    await button("Save").click();
    await page.getByRole("heading", { name: "Mail" }).waitFor();
    const list = page.locator("ul.items li");
    expect((await list.count()) === 2, "two logins are listed");
    await page.getByLabel("Search").fill("bank");
    await page.waitForFunction(() => document.querySelectorAll("ul.items li").length === 1);
    await page.getByLabel("Search").fill("");
  });

  await step("a secure note is added", async () => {
    await page.getByRole("button", { name: /^Secure notes/ }).click();
    await page.getByTitle("New secure note").click();
    await page.getByLabel("Title").fill("Wi-Fi");
    await page.getByLabel("Text").fill("network: home\npassphrase: purple monkey dishwasher");
    await button("Save").click();
    await page.getByText("passphrase: purple monkey dishwasher").waitFor();
    await shot("3-note");
  });

  await step("one-time codes show only after unlocking their domain", async () => {
    await page.getByRole("button", { name: /^One-time codes/ }).click();
    // Creating the vault and the recovery kit unlocked every domain (one
    // minute for this one): lock it, so that showing the codes unlocks it.
    const hide = button("Hide codes");
    await hide.or(button("Show one-time codes")).first().waitFor();
    if (await hide.isVisible()) await hide.click();
    await button("Show one-time codes").click();
    await button("Add").click();
    await page.getByLabel("Setup key as an otpauth:// address").fill(TOTP_URI);
    await page.getByLabel("Belongs to the login (optional)").selectOption({ label: "Example Bank (main) (alice@example.com)" });
    await page.locator("form.add").getByRole("button", { name: "Add", exact: true }).click();
    const code = page.getByLabel("current code");
    await code.waitFor();
    const text = (await code.textContent())?.replace(/\s/g, "") ?? "";
    expect(/^\d{6}$/.test(text), `the code is ${text}`);
    await shot("4-codes");
  });

  await step("the generator follows its options", async () => {
    await page.getByRole("button", { name: /^Password generator/ }).click();
    await page.getByLabel("a–z", { exact: true }).uncheck();
    await page.getByLabel("A–Z", { exact: true }).uncheck();
    await page.getByLabel("!#$%").uncheck();
    await page.waitForFunction(() => /^\d+$/.test(document.querySelector("output.password")?.textContent ?? ""));
  });

  await step("the master password is changed", async () => {
    await page.getByRole("button", { name: /^Settings/ }).click();
    await page.getByLabel("Current master password").fill(PASSWORD);
    await page.getByLabel(/^New master password/).fill(NEW_PASSWORD);
    await page.getByLabel("Repeat the new master password").fill(NEW_PASSWORD);
    await shot("5-settings");
    await button("Change master password").click();
    // The password domain locks with the change.
    await page.getByRole("heading", { name: "ZeroPass is locked" }).waitFor();
  });

  await step("a wrong password does not unlock, the new one does", async () => {
    await page.getByLabel("Master password").fill(PASSWORD);
    await button("Unlock").click();
    await page.getByText("That is not the master password.").waitFor();
    await page.getByLabel("Master password").fill(NEW_PASSWORD);
    await button("Unlock").click();
    await page.getByRole("button", { name: /^Logins/ }).waitFor();
  });

  await step("a login is deleted after asking once more", async () => {
    await page.locator("ul.items").getByText("Mail", { exact: true }).click();
    await button("Delete").click();
    await page.getByText("Delete it for good?").waitFor();
    await page.locator(".ask").getByRole("button", { name: "Delete" }).click();
    await page.waitForFunction(() => document.querySelectorAll("ul.items li").length === 1);
  });

  await step("locking returns to the unlock screen", async () => {
    await button("Lock").click();
    await page.getByRole("heading", { name: "ZeroPass is locked" }).waitFor();
  });

  await step("resetting from the unlock screen removes the local vault and opens Join", async () => {
    await button("Reset and re-pair with another device").click();
    await button("Delete and re-pair").click();
    await page.getByRole("heading", { name: "Join a vault" }).waitFor({ timeout: 30_000 });
    expect(!existsSync(vault), "the vault file still exists after reset");
    await button("Back").click();
    await page.getByRole("heading", { name: "Create your vault" }).waitFor();
  });

  await step("the page reported no errors (CSP or otherwise)", async () => {
    expect(consoleProblems.length === 0, consoleProblems.join("\n"));
  });
} catch (error) {
  failed(error);
} finally {
  await app?.close();
  await sleep(1500);
  rmSync(dir, { recursive: true, force: true, maxRetries: 24, retryDelay: 250 });
}
finish();
