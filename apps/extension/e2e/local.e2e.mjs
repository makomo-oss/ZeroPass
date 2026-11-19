// End-to-end test of the extension on pages served here: the real extension
// in Chromium, the real bridge, the real vault daemon. Windows only.
//
//   node e2e/local.e2e.mjs [--headed]

import { createHash, createPublicKey, verify } from "node:crypto";
import { createServer } from "node:http";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import {
  addLogin,
  attribute,
  clickClosed,
  cli,
  expect,
  failed,
  finish,
  launchBrowser,
  PASSWORD,
  pickFirst,
  setUp,
  step,
  suggestionsShown,
} from "./harness.mjs";

const USER = "alice@example.test";
const SECRET = "local password 1";

const LOGIN_PAGE = `<!doctype html><title>Login</title>
<form id="login" action="/done" method="post">
  <label>E-mail <input type="email" name="email" id="email" autocomplete="username"></label>
  <label>Password <input type="password" name="password" id="password"></label>
  <button>Sign in</button>
</form>
<p id="typed"></p>
<script>
  // Like a framework that keeps its own copy of what was typed.
  const seen = {};
  for (const field of document.querySelectorAll("input")) {
    field.addEventListener("input", () => {
      seen[field.name] = field.value.length;
      document.getElementById("typed").textContent = JSON.stringify(seen);
    });
  }
  document.getElementById("login").addEventListener("submit", (event) => {
    event.preventDefault();
    document.title = "submitted";
  });
</script>`;

const OTP_PAGE = `<!doctype html><title>Two-factor</title>
<form><label>Code <input id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6"></label><button>Verify</button></form>`;

// A site that remembers who signs in: the password only, the user name kept
// in a hidden field for password managers.
const WELCOME_BACK_PAGE = `<!doctype html><title>Welcome back</title>
<form id="again" action="/done" method="post">
  <p>Welcome back, new.user@example.test</p>
  <input type="hidden" autocomplete="username" value="new.user@example.test">
  <label>Password <input type="password" id="again-password"></label>
  <button>Sign in</button>
</form>
<script>
  document.getElementById("again").addEventListener("submit", (event) => {
    event.preventDefault();
    document.title = "submitted";
  });
</script>`;

const TWO_STEP_PAGE = `<!doctype html><title>Step 1</title>
<form><input type="email" id="identifier" autocomplete="username"><button>Next</button></form>`;

const PASSKEY_PAGE = `<!doctype html><title>Passkey</title>
<p>WebAuthn local test page</p>`;

function framePage(src) {
  return `<!doctype html><title>Framed</title><p>A page of another site</p>
<iframe id="frame" src="${src}" width="600" height="300"></iframe>`;
}

const setup = setUp();
let server;
let context;
try {
  server = createServer((request, response) => {
    const host = request.headers.host ?? "";
    const pages = {
      "/login": LOGIN_PAGE,
      "/two-step": TWO_STEP_PAGE,
      "/welcome-back": WELCOME_BACK_PAGE,
      "/otp": OTP_PAGE,
      "/passkey": PASSKEY_PAGE,
      // A page of one site that frames the login page of another.
      "/framed": framePage(`http://localhost:${port}/login`),
      // ...and one that frames a page of its own site.
      "/self-framed": framePage(`http://${host}/login`),
    };
    const page = pages[request.url ?? ""];
    response.writeHead(page ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
    response.end(page ?? "not found");
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  // The server answers on 127.0.0.1 only; "localhost" reaches it too.
  var port = server.address().port;
  const site = `http://127.0.0.1:${port}`;

  const local = addLogin(setup.vault, "Local", USER, SECRET, site);
  cli(setup.vault, ["add", "totp", "--login", local], [
    "otpauth://totp/Local:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
  ]);
  addLogin(setup.vault, "Elsewhere", "bob", "elsewhere password", "https://elsewhere.test");
  addLogin(setup.vault, "Framed", "carol", "framed password", `http://localhost:${port}`);

  context = await launchBrowser(setup.dir, setup.vault);
  const page = await context.newPage();
  const shot = (name) => page.screenshot({ path: join(setup.dir, "..", `zeropass-ext-${name}.png`) });

  await step("the logins of the page are offered under its field, and filled when picked", async () => {
    await page.goto(`${site}/login`);
    const email = page.locator("#email");
    await email.click();
    await page.waitForFunction(() => document.querySelector("zeropass-suggestions") !== null, null, {
      timeout: 15_000,
    });
    await pickFirst(page, email);
    await page.waitForFunction(
      (user) => document.getElementById("email").value === user,
      USER,
      { timeout: 10_000 },
    );
    const password = await page.locator("#password").inputValue();
    expect(password === SECRET, "the password was not filled");
    // The page saw the values arrive, as typed; nothing was submitted.
    const typed = JSON.parse((await page.locator("#typed").textContent()) || "{}");
    expect(typed.email === USER.length && typed.password === SECRET.length, `the page saw ${JSON.stringify(typed)}`);
    expect((await page.title()) === "Login", "the form was submitted");
  }, () => shot("fill"));

  await step("the popup's way works: the tab finds its own logins and fills the chosen one", async () => {
    await page.goto(`${site}/login`);
    const worker = context.serviceWorkers()[0];
    // What the background does for the popup (find_for_tab, fill_tab), done
    // from the background itself: the toolbar button cannot be pressed here.
    const outcome = await worker.evaluate(async () => {
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      if (!tab?.id) return { error: "no active tab" };
      // `find_for_tab`: the tab's top frame finds its own logins.
      const found = await chrome.tabs.sendMessage(tab.id, { kind: "find_now" }, { frameId: 0 });
      const item = found?.logins?.[0]?.id;
      if (!item) return { found };
      // `fill_tab`: the top frame fills the login the user chose.
      const filled = await chrome.tabs.sendMessage(tab.id, { kind: "fill_now", item }, { frameId: 0 });
      return { found, filled };
    });
    expect(outcome.filled === true, `the popup's way failed: ${JSON.stringify(outcome)}`);
    await page.waitForFunction((user) => document.getElementById("email").value === user, USER, {
      timeout: 10_000,
    });
  }, () => shot("popup"));

  await step("the first step of a two-step login gets the user name", async () => {
    await page.goto(`${site}/two-step`);
    const field = page.locator("#identifier");
    await field.click();
    await page.waitForFunction(() => document.querySelector("zeropass-suggestions") !== null, null, {
      timeout: 15_000,
    });
    await pickFirst(page, field);
    await page.waitForFunction((user) => document.getElementById("identifier").value === user, USER, {
      timeout: 10_000,
    });
  }, () => shot("two-step"));

  await step("nothing is offered in a frame of another site", async () => {
    await page.goto(`${site}/framed`);
    const frame = page.frameLocator("#frame");
    await frame.locator("#email").click();
    await sleep(2000);
    const inner = page.frames().find((candidate) => candidate.url().includes("localhost"));
    expect(inner, "the frame did not load");
    expect(!(await suggestionsShown(inner)), "logins were offered inside a frame of another site");
  }, () => shot("framed"));

  await step("a frame of the same site is offered its logins", async () => {
    await page.goto(`${site}/self-framed`);
    const inner = page.frameLocator("#frame");
    await inner.locator("#email").click();
    const frame = page.frames().find((candidate) => candidate !== page.mainFrame());
    await frame.waitForFunction(() => document.querySelector("zeropass-suggestions") !== null, null, {
      timeout: 15_000,
    });
  }, () => shot("self-framed"));

  await step("a page cannot press the list itself", async () => {
    await page.goto(`${site}/login`);
    await page.locator("#email").click();
    await page.waitForFunction(() => document.querySelector("zeropass-suggestions") !== null, null, {
      timeout: 15_000,
    });
    // The page's own script: the list is in a closed shadow root, and a click
    // it makes up is not trusted.
    const reached = await page.evaluate(() => {
      const host = document.querySelector("zeropass-suggestions");
      host?.click();
      host?.dispatchEvent(new MouseEvent("click", { bubbles: true, composed: true }));
      return host?.shadowRoot ?? null;
    });
    await sleep(1000);
    expect(reached === null, "the page reached into the list");
    expect((await page.locator("#password").inputValue()) === "", "a made-up click filled the password");
  }, () => shot("untrusted"));

  await step("a one-time-code field gets the code of the page's login", async () => {
    await page.goto(`${site}/otp`);
    const field = page.locator("#otp");
    await field.click();
    await page.waitForFunction(() => document.querySelector("zeropass-suggestions") !== null, null, {
      timeout: 15_000,
    });
    await pickFirst(page, field);
    await page.waitForFunction(() => /^\d{6}$/.test(document.getElementById("otp").value), null, {
      timeout: 15_000,
    });
  }, () => shot("otp"));

  const pressProposal = (kind) =>
    clickClosed(
      page,
      "zeropass-proposal",
      (node) => node.nodeName === "BUTTON" && attribute(node, "class") === kind,
    );
  const signIn = async (email, password) => {
    await page.goto(`${site}/login`);
    await page.locator("#email").fill(email);
    await page.locator("#password").fill(password);
    await page.getByRole("button", { name: "Sign in" }).click();
  };

  await step("after signing in with a new login, ZeroPass offers to save it", async () => {
    await signIn("new.user@example.test", "a brand new password");
    await page.waitForFunction(() => document.querySelector("zeropass-proposal") !== null, null, {
      timeout: 15_000,
    });
    await shot("save");
    expect(await pressProposal("yes"), "the Save button was not found");
    await page.waitForFunction(() => document.querySelector("zeropass-proposal") === null);
    await sleep(1000);
    const listed = cli(setup.vault, ["list"]);
    expect(listed.includes(`127.0.0.1:${port}`), `the new login is not in the vault:\n${listed}`);
  }, () => shot("save-failed"));

  await step("signing in again with the login just saved offers nothing", async () => {
    await signIn("new.user@example.test", "a brand new password");
    await sleep(2500);
    expect(
      !(await page.evaluate(() => document.querySelector("zeropass-proposal") !== null)),
      "a proposal was shown for the login just saved",
    );
  }, () => shot("saved-again"));

  await step("the same login typed with other capitals offers nothing", async () => {
    await signIn("New.User@example.test", "a brand new password");
    await sleep(2500);
    expect(
      !(await page.evaluate(() => document.querySelector("zeropass-proposal") !== null)),
      "a proposal was shown for the same user name in other capitals",
    );
  }, () => shot("capitals"));

  await step("a site that asks for the password only offers nothing for a saved login", async () => {
    // That page's sign-in is noticed: another password gets an offer...
    await page.goto(`${site}/welcome-back`);
    await page.locator("#again-password").fill("not the saved password");
    await page.getByRole("button", { name: "Sign in" }).click();
    await page.waitForFunction(() => document.querySelector("zeropass-proposal") !== null, null, {
      timeout: 15_000,
    });
    const notNow = await clickClosed(
      page,
      "zeropass-proposal",
      (node) => node.nodeName === "BUTTON" && attribute(node, "class") === undefined,
    );
    expect(notNow, "the Not now button was not found");
    await page.waitForFunction(() => document.querySelector("zeropass-proposal") === null);
    // ...and the saved one none.
    await page.goto(`${site}/welcome-back`);
    await page.locator("#again-password").fill("a brand new password");
    await page.getByRole("button", { name: "Sign in" }).click();
    await sleep(2500);
    expect(
      !(await page.evaluate(() => document.querySelector("zeropass-proposal") !== null)),
      "a proposal was shown on the password-only page",
    );
  }, () => shot("welcome-back"));

  await step("after signing in with a changed password, ZeroPass offers to update it", async () => {
    await signIn(USER, "a changed password");
    await page.waitForFunction(() => document.querySelector("zeropass-proposal") !== null, null, {
      timeout: 15_000,
    });
    expect(await pressProposal("yes"), "the Update button was not found");
    await sleep(1000);
    const shown = cli(setup.vault, ["get", local, "--reveal"]);
    expect(shown.includes("a changed password"), `the password was not updated:\n${shown}`);
  }, () => shot("update-failed"));

  await step("signing in with what the vault has offers nothing", async () => {
    await signIn(USER, "a changed password");
    await sleep(2500);
    expect(
      !(await page.evaluate(() => document.querySelector("zeropass-proposal") !== null)),
      "a proposal was shown for an unchanged login",
    );
  }, () => shot("unchanged"));

  await step("a locked vault offers to open ZeroPass instead of logins", async () => {
    cli(setup.vault, ["lock"]);
    await page.goto(`${site}/login`);
    await page.locator("#email").click();
    await page.waitForFunction(() => document.querySelector("zeropass-suggestions") !== null, null, {
      timeout: 15_000,
    });
    await shot("locked");
    expect((await page.locator("#password").inputValue()) === "", "something was filled while locked");
    cli(setup.vault, ["unlock"], [PASSWORD]);
  }, () => shot("locked-failed"));

  const pressPasskeyButton = (cls) =>
    clickClosed(
      page,
      "zeropass-passkey-prompt",
      (node) => node.nodeName === "BUTTON" && (attribute(node, "class") ?? "").split(" ").includes(cls),
    );
  const b64ToBuf = (b64) => Buffer.from(b64, "base64url");
  let registeredCredId = "";
  let registeredSpki = null;

  await step("WebAuthn create registers a passkey after a trusted click and returns valid public key", async () => {
    await page.goto(`${site}/passkey`);
    const regPromise = page.evaluate(async () => {
      const challenge = new Uint8Array(32).fill(7);
      const userId = new TextEncoder().encode("alice-local-passkey");
      const cred = await navigator.credentials.create({
        publicKey: {
          rp: { id: "127.0.0.1", name: "Local Test" },
          user: { id: userId, name: "alice@local.test", displayName: "Alice" },
          challenge,
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { residentKey: "required", userVerification: "required" },
        },
      });
      const resp = cred.response;
      const toB64 = (buf) => {
        let s = "";
        for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
        return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      };
      return {
        isInstance: cred instanceof PublicKeyCredential,
        id: cred.id,
        type: cred.type,
        alg: resp.getPublicKeyAlgorithm(),
        transports: resp.getTransports(),
        clientDataJSON: toB64(resp.clientDataJSON),
        attestationObject: toB64(resp.attestationObject),
        authenticatorData: toB64(resp.getAuthenticatorData()),
        publicKeySpki: toB64(resp.getPublicKey()),
        ext: cred.getClientExtensionResults(),
        jsonId: cred.toJSON().id,
      };
    });
    await page.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
      timeout: 15_000,
    });
    // Untrusted script click on the host cannot approve the prompt.
    const reached = await page.evaluate(() => {
      const host = document.querySelector("zeropass-passkey-prompt");
      host?.click();
      return host?.shadowRoot ?? null;
    });
    expect(reached === null, "page reached into closed passkey prompt shadow root");
    expect(await pressPasskeyButton("save"), "Save in ZeroPass button was not found");
    const reg = await regPromise;
    expect(reg.isInstance, "credential is not instanceof PublicKeyCredential");
    expect(reg.type === "public-key", `unexpected type: ${reg.type}`);
    expect(reg.alg === -7, `unexpected alg: ${reg.alg}`);
    expect(reg.jsonId === reg.id, "toJSON().id mismatch");
    expect(reg.ext?.credProps?.rk === true, "credProps.rk not true");
    const clientData = JSON.parse(b64ToBuf(reg.clientDataJSON).toString("utf8"));
    expect(clientData.type === "webauthn.create", `clientData.type=${clientData.type}`);
    expect(clientData.origin === site, `clientData.origin=${clientData.origin}`);
    expect(clientData.crossOrigin === false, "crossOrigin should be false");
    registeredCredId = reg.id;
    registeredSpki = createPublicKey({
      key: b64ToBuf(reg.publicKeySpki),
      format: "der",
      type: "spki",
    });
  }, () => shot("passkey-create"));

  await step("WebAuthn get signs a verifiable assertion with the registered passkey", async () => {
    const authPromise = page.evaluate(async () => {
      const challenge = new Uint8Array(32).fill(9);
      const cred = await navigator.credentials.get({
        publicKey: {
          rpId: "127.0.0.1",
          challenge,
          userVerification: "required",
        },
      });
      const resp = cred.response;
      const toB64 = (buf) => {
        let s = "";
        for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
        return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      };
      return {
        isInstance: cred instanceof PublicKeyCredential,
        id: cred.id,
        clientDataJSON: toB64(resp.clientDataJSON),
        authenticatorData: toB64(resp.authenticatorData),
        signature: toB64(resp.signature),
        userHandle: toB64(resp.userHandle),
      };
    });
    await page.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
      timeout: 15_000,
    });
    expect(await pressPasskeyButton("candidate"), "passkey candidate button was not found");
    const auth = await authPromise;
    expect(auth.isInstance, "assertion is not instanceof PublicKeyCredential");
    expect(auth.id === registeredCredId, "assertion credential ID mismatch");
    const clientDataBytes = b64ToBuf(auth.clientDataJSON);
    const clientData = JSON.parse(clientDataBytes.toString("utf8"));
    expect(clientData.type === "webauthn.get", `clientData.type=${clientData.type}`);
    expect(clientData.origin === site, `clientData.origin=${clientData.origin}`);
    const authData = b64ToBuf(auth.authenticatorData);
    expect(authData.length === 37, `authData length=${authData.length}`);
    expect(authData[32] === 0x1d, `flags=0x${authData[32].toString(16)}`);
    expect(authData.readUInt32BE(33) === 0, "signCount must be 0");
    const signed = Buffer.concat([authData, createHash("sha256").update(clientDataBytes).digest()]);
    const verified = verify("sha256", signed, registeredSpki, b64ToBuf(auth.signature));
    expect(verified, "ECDSA P-256 signature verification failed");
  }, () => shot("passkey-get"));

  await step("locked passkey domain unlocks and signs in one step, and rejects bad RP ID or excluded credential", async () => {
    cli(setup.vault, ["lock"]);
    const lockedAuth = page.evaluate(async () => {
      const cred = await navigator.credentials.get({
        publicKey: { rpId: "127.0.0.1", challenge: new Uint8Array(32).fill(3) },
      });
      return cred.id;
    });
    await page.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
      timeout: 15_000,
    });
    expect(await pressPasskeyButton("unlock"), "Sign in with ZeroPass button was not found");
    expect((await lockedAuth) === registeredCredId, "locked passkey get did not return registered ID");

    // Cross-domain RP ID is rejected with SecurityError without prompting.
    const badRp = await page.evaluate(async () => {
      try {
        await navigator.credentials.create({
          publicKey: {
            rp: { id: "evil.example", name: "Evil" },
            user: { id: new Uint8Array([1, 2]), name: "eve", displayName: "Eve" },
            challenge: new Uint8Array(16).fill(1),
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        });
        return "unexpected-success";
      } catch (err) {
        return err.name;
      }
    });
    expect(badRp === "SecurityError", `expected SecurityError, got ${badRp}`);

    // Excluding the registered credential yields InvalidStateError.
    const excludedPromise = page.evaluate(async (credIdB64) => {
      const raw = Uint8Array.from(atob(credIdB64.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
      try {
        await navigator.credentials.create({
          publicKey: {
            rp: { id: "127.0.0.1", name: "Local Test" },
            user: { id: new Uint8Array([9, 9]), name: "bob", displayName: "Bob" },
            challenge: new Uint8Array(16).fill(2),
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            excludeCredentials: [{ type: "public-key", id: raw }],
          },
        });
        return "unexpected-success";
      } catch (err) {
        return err.name;
      }
    }, registeredCredId);
    await page.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
      timeout: 15_000,
    });
    expect(await pressPasskeyButton("save"), "Save button not found for excludeCredentials test");
    const excludedName = await excludedPromise;
    expect(excludedName === "InvalidStateError", `expected InvalidStateError, got ${excludedName}`);

    // Cancelling the prompt yields NotAllowedError.
    const cancelPromise = page.evaluate(async () => {
      try {
        await navigator.credentials.create({
          publicKey: {
            rp: { id: "127.0.0.1", name: "Local Test" },
            user: { id: new Uint8Array([8, 8]), name: "carol", displayName: "Carol" },
            challenge: new Uint8Array(16).fill(4),
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        });
        return "unexpected-success";
      } catch (err) {
        return err.name;
      }
    });
    await page.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
      timeout: 15_000,
    });
    expect(await pressPasskeyButton("cancel"), "Cancel button not found");
    const cancelName = await cancelPromise;
    expect(cancelName === "NotAllowedError", `expected NotAllowedError, got ${cancelName}`);
  }, () => shot("passkey-edge"));
} catch (error) {
  failed(error);
} finally {
  await context?.close().catch(() => {});
  server?.close();
  setup.close();
}
finish();
