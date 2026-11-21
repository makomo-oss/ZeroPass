// End-to-end test of passkeys through the extension (docs/spec/extension.md
// §11): the real extension in Chromium, the real bridge and vault daemon,
// and a relying party served here whose checks are those of an independent
// library (@simplewebauthn/server). Windows only.
//
//   node e2e/passkeys.e2e.mjs [--headed]

import { createServer } from "node:http";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

import { attribute, clickClosed, cli, expect, failed, finish, launchBrowser, setUp, step } from "./harness.mjs";

/** ZeroPass's AAGUID (docs/spec/passkey.md §4). */
const ZEROPASS_AAGUID = "4826244e-9eab-4432-8ad5-d2f3693fb8c5";
const RP_ID = "localhost";

const PAGE = `<!doctype html><title>Relying party</title><p>A relying party</p>`;

const setup = setUp();
let server;
let context;

/** How many passkeys the vault keeps (all of them for this relying party). */
function passkeysInVault() {
  const listed = cli(setup.vault, ["list", "--domain", "passkey"]);
  const count = Number(/(\d+) item\(s\)/.exec(listed)?.[1] ?? "0");
  expect(count === 0 || listed.includes("localhost"), `the vault lists:\n${listed}`);
  return count;
}

/** The passkeys the relying party has registered, by user name. */
const registered = new Map();

try {
  server = createServer((request, response) => {
    response.writeHead(request.url === "/" ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
    response.end(request.url === "/" ? PAGE : "not found");
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const origin = `http://localhost:${server.address().port}`;

  context = await launchBrowser(setup.dir, setup.vault);
  const page = await context.newPage();
  const shot = (name) => page.screenshot({ path: join(setup.dir, "..", `zeropass-passkey-${name}.png`) });
  await page.goto(`${origin}/`);

  const dialogShown = () => page.evaluate(() => document.querySelector("zeropass-passkey") !== null);
  const waitForDialog = () =>
    page.waitForFunction(() => document.querySelector("zeropass-passkey") !== null, null, { timeout: 15_000 });
  /** Clicks a button of the dialog, as the user would. */
  async function press(action, name) {
    await waitForDialog();
    for (let attempt = 0; attempt < 50; attempt++) {
      const clicked = await clickClosed(
        page,
        "zeropass-passkey",
        (node) =>
          node.nodeName === "BUTTON" &&
          attribute(node, "data-action") === action &&
          (name === undefined || attribute(node, "data-name") === name),
      ).catch(() => false);
      if (clicked) return;
      await sleep(200);
    }
    throw new Error(`no "${action}" button in the dialog`);
  }

  /** `navigator.credentials.create` in the page, with the relying party's options (JSON). */
  function create(options, extra = {}) {
    return page.evaluate(
      async ({ json, extra }) => {
        try {
          const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(json);
          if (extra.exclude) publicKey.excludeCredentials = extra.exclude.map((id) => ({
            type: "public-key",
            id: Uint8Array.from(atob(id.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)),
          }));
          const controller = new AbortController();
          if (extra.abortAfter) setTimeout(() => controller.abort(), extra.abortAfter);
          const credential = await navigator.credentials.create({ publicKey, signal: controller.signal });
          return {
            ok: true,
            json: credential.toJSON(),
            isCredential: credential instanceof PublicKeyCredential,
            algorithm: credential.response.getPublicKeyAlgorithm(),
            publicKeyBytes: credential.response.getPublicKey()?.byteLength ?? 0,
            rawIdBytes: credential.rawId.byteLength,
            attachment: credential.authenticatorAttachment,
            extensions: credential.getClientExtensionResults(),
          };
        } catch (error) {
          return { ok: false, name: error.name, message: error.message };
        }
      },
      { json: options, extra },
    );
  }

  /** `navigator.credentials.get` in the page. */
  function get(options, extra = {}) {
    return page.evaluate(
      async ({ json, extra }) => {
        try {
          const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(json);
          const controller = new AbortController();
          if (extra.abortAfter) setTimeout(() => controller.abort(), extra.abortAfter);
          const credential = await navigator.credentials.get({
            publicKey,
            signal: controller.signal,
            ...(extra.mediation ? { mediation: extra.mediation } : {}),
          });
          return { ok: true, json: credential.toJSON(), isCredential: credential instanceof PublicKeyCredential };
        } catch (error) {
          return { ok: false, name: error.name, message: error.message };
        }
      },
      { json: options, extra },
    );
  }

  async function register(userName) {
    const options = await generateRegistrationOptions({
      rpName: "Relying party",
      rpID: RP_ID,
      userName,
      attestationType: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { credProps: true },
    });
    return { options, verify: (json) => verifyRegistrationResponse({
      response: json,
      expectedChallenge: options.challenge,
      expectedOrigin: origin,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    }) };
  }

  async function signIn() {
    const options = await generateAuthenticationOptions({ rpID: RP_ID, userVerification: "required" });
    return {
      options,
      verify: (json) => {
        const known = [...registered.values()].find((passkey) => passkey.id === json.id);
        expect(known, `an unknown credential signed: ${json.id}`);
        return verifyAuthenticationResponse({
          response: json,
          expectedChallenge: options.challenge,
          expectedOrigin: origin,
          expectedRPID: RP_ID,
          credential: known,
          requireUserVerification: true,
        });
      },
    };
  }

  await step("a passkey is made in ZeroPass and the relying party accepts it", async () => {
    const { options, verify } = await register("alice");
    const pending = create(options);
    await press("zeropass");
    const result = await pending;
    expect(result.ok, `create failed: ${result.name}: ${result.message}`);
    expect(result.isCredential, "not a PublicKeyCredential");
    expect(result.attachment === "platform", `attachment ${result.attachment}`);
    expect(result.extensions.credProps?.rk === true, `extensions ${JSON.stringify(result.extensions)}`);
    expect(result.publicKeyBytes > 0 && result.rawIdBytes === 16, `key ${result.publicKeyBytes}, id ${result.rawIdBytes}`);
    // simplewebauthn lists EdDSA first: ZeroPass takes the first it can make.
    expect(result.algorithm === -8, `algorithm ${result.algorithm}`);
    const { verified, registrationInfo: info } = await verify(result.json);
    expect(verified, "the relying party refused the registration");
    expect(info.fmt === "none", `fmt ${info.fmt}`);
    expect(info.aaguid === ZEROPASS_AAGUID, `aaguid ${info.aaguid}`);
    expect(info.userVerified, "not user-verified");
    expect(info.credentialDeviceType === "multiDevice", `device type ${info.credentialDeviceType}`);
    expect(info.credentialBackedUp === false, "a vault on one device is not backed up");
    registered.set("alice", { ...info.credential, userId: options.user.id });
    expect(!(await dialogShown()), "the dialog stayed");
    expect(passkeysInVault() === 1, "the vault does not keep the passkey");
  }, () => shot("create"));

  await step("the relying party accepts a sign-in with it", async () => {
    const { options, verify } = await signIn();
    const pending = get(options);
    await press("zeropass");
    const result = await pending;
    expect(result.ok, `get failed: ${result.name}: ${result.message}`);
    expect(result.isCredential, "not a PublicKeyCredential");
    expect(result.json.response.userHandle === registered.get("alice").userId, "another user handle");
    const { verified, authenticationInfo } = await verify(result.json);
    expect(verified && authenticationInfo.userVerified, "the relying party refused the sign-in");
    expect(authenticationInfo.newCounter === 0, `counter ${authenticationInfo.newCounter}`);
  }, () => shot("get"));

  await step("with two accounts, the user picks one", async () => {
    const { options, verify } = await register("bob");
    const pending = create(options);
    await press("zeropass");
    const made = await pending;
    expect(made.ok, `create failed: ${made.name}`);
    const { registrationInfo } = await verify(made.json);
    registered.set("bob", { ...registrationInfo.credential, userId: options.user.id });

    const login = await signIn();
    const signing = get(login.options);
    await press("zeropass");
    await press("choose", "bob");
    const result = await signing;
    expect(result.ok, `get failed: ${result.name}: ${result.message}`);
    expect(result.json.id === registered.get("bob").id, "not bob's passkey");
    expect((await login.verify(result.json)).verified, "the relying party refused bob's sign-in");
  }, () => shot("choose"));

  await step("the user may leave a request to the browser", async () => {
    // A virtual authenticator stands in for the browser's own passkeys. On
    // some machines (the CI's Windows Server) the browser shows its own
    // prompt instead and waits: the page then gives up after a while, and
    // the browser's AbortError shows the request was the browser's.
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    try {
      const { options, verify } = await register("carol");
      const pending = create(options, { abortAfter: 8000 });
      await press("native");
      await page.waitForFunction(() => document.querySelector("zeropass-passkey") === null, null, { timeout: 5000 });
      const result = await pending;
      if (result.ok) {
        const { verified, registrationInfo } = await verify(result.json);
        expect(verified && registrationInfo.aaguid !== ZEROPASS_AAGUID, "the passkey was not the browser's");
      } else {
        expect(result.name === "AbortError", `the browser's create failed: ${result.name}: ${result.message}`);
        console.log("  (the browser did not use the virtual authenticator; its request was aborted)");
      }
      expect(passkeysInVault() === 2, "ZeroPass kept the browser's passkey");
    } finally {
      await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }).catch(() => {});
      await cdp.detach().catch(() => {});
    }
  }, () => shot("native"));

  await step("cancelling gives the page NotAllowedError, an excluded account InvalidStateError", async () => {
    const { options } = await register("dave");
    const pending = create(options);
    await press("cancel");
    const cancelled = await pending;
    expect(!cancelled.ok && cancelled.name === "NotAllowedError", `${cancelled.name}`);

    const again = await register("alice");
    const excluding = create(again.options, { exclude: [registered.get("alice").id] });
    await press("zeropass");
    // ZeroPass says why, then the page hears it.
    await press("cancel");
    const excluded = await excluding;
    expect(!excluded.ok && excluded.name === "InvalidStateError", `${excluded.name}: ${excluded.message}`);
  }, () => shot("cancel"));

  await step("a page that aborts takes the dialog away; the page cannot reach into it", async () => {
    const { options } = await signIn();
    const pending = get(options, { abortAfter: 1500 });
    await waitForDialog();
    const reachable = await page.evaluate(() => document.querySelector("zeropass-passkey").shadowRoot !== null);
    expect(!reachable, "the page can reach into the dialog");
    const result = await pending;
    expect(!result.ok && result.name === "AbortError", `${result.name}`);
    await page.waitForFunction(() => document.querySelector("zeropass-passkey") === null, null, { timeout: 5000 });
  }, () => shot("abort"));

  await step("passkey autofill (conditional mediation) stays with the browser", async () => {
    const { options } = await signIn();
    const pending = get(options, { mediation: "conditional", abortAfter: 2000 });
    await sleep(1000);
    expect(!(await dialogShown()), "ZeroPass answered a conditional request");
    const result = await pending;
    expect(!result.ok && result.name === "AbortError", `${result.name}`);
  }, () => shot("conditional"));
} catch (error) {
  failed(error);
} finally {
  await context?.close().catch(() => {});
  server?.close();
  setup.close();
}
finish();
