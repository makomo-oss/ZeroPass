// End-to-end passkey cross-device sync test (PLAN.md P5-05):
// Two separate vaults (PC A & PC B), two real zp-vaultd (sandboxed), two real
// zp-syncd (LAN mDNS + TCP + Noise), real zp-nmh, and two Chromium contexts
// with the built ZeroPass extension.
//
// Needs a local network interface with multicast (not run in CI):
//   cargo build -p zp-nmh -p zp-vaultd -p zp-syncd -p zp-cli -p zp-keyagent
//   cd apps/extension && npm run build
//   node e2e/passkey-sync.e2e.mjs [--webauthn-io] [--headed | --offscreen]

import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash, createPublicKey, verify } from "node:crypto";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  attribute,
  bin,
  clickClosed,
  cli,
  expect,
  EXTENSION_ID,
  failed,
  finish,
  HOST_KEYS,
  launchBrowser,
  NATIVE_HOST,
  PASSWORD,
  step,
  withoutVault,
} from "./harness.mjs";

const PASSWORD_A = PASSWORD;
const PASSWORD_B = "device B completely separate master password";
const USE_WEBAUTHN_IO = process.argv.includes("--webauthn-io");

const PASSKEY_PAGE = `<!doctype html><title>Passkey Sync Test</title>
<p>WebAuthn two-device sync test page</p>`;

function pressPrompt(page, cls) {
  return clickClosed(
    page,
    "zeropass-passkey-prompt",
    (node) => node.nodeName === "BUTTON" && (attribute(node, "class") ?? "").split(" ").includes(cls),
  );
}

/**
 * Pairs vaultA (existing) and vaultB (new) over the real LAN using `zp-cli pair`
 * and `zp-cli join`, exercising real `zp-vaultd`, `zp-syncd`, and Noise XXpsk3.
 */
async function pairOverLan(vaultA, vaultB) {
  cli(vaultA, ["lock"]);
  const pairChild = spawn(bin("zp-cli"), ["--vault", vaultA, "--insecure-software-keystore", "pair"], {
    env: withoutVault(),
    stdio: ["pipe", "pipe", "pipe"],
  });
  pairChild.stdin.write(`${PASSWORD_A}\ny\n`);

  let pairOut = "";
  let pairErr = "";
  pairChild.stderr.on("data", (chunk) => {
    pairErr += chunk.toString("utf8");
  });

  const code = await new Promise((resolveCode, rejectCode) => {
    const timer = setTimeout(() => rejectCode(new Error(`zp-cli pair timed out:\n${pairOut}\n${pairErr}`)), 20_000);
    pairChild.stdout.on("data", (chunk) => {
      pairOut += chunk.toString("utf8");
      for (const line of pairOut.split(/\r?\n/)) {
        if (line.startsWith("ZP1:")) {
          clearTimeout(timer);
          resolveCode(line.trim());
          return;
        }
      }
    });
    pairChild.once("exit", (exitCode) => {
      clearTimeout(timer);
      rejectCode(new Error(`zp-cli pair exited (${exitCode}) before showing a code:\n${pairOut}\n${pairErr}`));
    });
  });

  const joinOut = cli(vaultB, ["join", "--name", "PC B"], [PASSWORD_B, PASSWORD_B, code]);
  expect(joinOut.includes("joined vault"), `unexpected join output: ${joinOut}`);
  expect(joinOut.includes("passkey: available"), `passkey domain missing on PC B: ${joinOut}`);

  pairChild.stdin.end();
  const pairExit = await new Promise((resolveExit) => {
    if (pairChild.exitCode !== null) resolveExit(pairChild.exitCode);
    else pairChild.once("exit", resolveExit);
  });
  expect(pairExit === 0, `zp-cli pair failed (${pairExit}):\n${pairOut}\n${pairErr}`);
  return joinOut;
}

/** Runs `zp-cli sync --seconds 15` concurrently on both vaults over LAN. */
async function syncOverLan(vaultA, vaultB) {
  const run = (vault) =>
    new Promise((resolveRun, rejectRun) => {
      const child = spawn(
        bin("zp-cli"),
        ["--vault", vault, "--insecure-software-keystore", "sync", "--seconds", "15"],
        { env: withoutVault(), stdio: ["ignore", "pipe", "pipe"] },
      );
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (c) => {
        stdout += c.toString("utf8");
      });
      child.stderr.on("data", (c) => {
        stderr += c.toString("utf8");
      });
      child.once("exit", (code) => {
        if (code === 0) resolveRun(stdout);
        else rejectRun(new Error(`zp-cli sync (${vault}) failed (${code}): ${stdout}${stderr}`));
      });
    });

  const [outA, outB] = await Promise.all([run(vaultA), run(vaultB)]);
  expect(outA.includes('synced with "') && outB.includes('synced with "'), `sync did not pair:\nA: ${outA}\nB: ${outB}`);
}

/** Verifies a WebAuthn P-256 assertion signature against a registered SPKI key. */
function verifyP256Assertion(expectedOrigin, expectedRpId, spkiDer, assertion) {
  const clientDataBytes = Buffer.from(assertion.clientDataJSON);
  const clientData = JSON.parse(clientDataBytes.toString("utf8"));
  expect(clientData.type === "webauthn.get", `unexpected type: ${clientData.type}`);
  expect(clientData.origin === expectedOrigin, `unexpected origin: ${clientData.origin}`);
  expect(clientData.crossOrigin === false, "crossOrigin must be false");

  const authData = Buffer.from(assertion.authenticatorData);
  const expectedRpHash = createHash("sha256").update(expectedRpId, "utf8").digest();
  expect(authData.subarray(0, 32).equals(expectedRpHash), "rpIdHash mismatch");
  expect(authData[32] === 0x1d, `expected flags 0x1d (UP|UV|BE|BS), got 0x${authData[32].toString(16)}`);
  expect(authData.readUInt32BE(33) === 0, "expected signCount = 0");

  const clientDataHash = createHash("sha256").update(clientDataBytes).digest();
  const signedData = Buffer.concat([authData, clientDataHash]);
  const publicKey = createPublicKey({ key: Buffer.from(spkiDer), format: "der", type: "spki" });
  const ok = verify("sha256", signedData, publicKey, Buffer.from(assertion.signature));
  expect(ok, "P-256 WebAuthn assertion signature did not verify");
}

const rootDir = mkdtempSync(join(tmpdir(), "zeropass-passkey-sync-"));
const dirA = join(rootDir, "pc-a");
const dirB = join(rootDir, "pc-b");
mkdirSync(dirA);
mkdirSync(dirB);
const vaultA = join(dirA, "pc-a.zpvault");
const vaultB = join(dirB, "pc-b.zpvault");

let server;
let contextA;
let contextB;

try {
  // Register the native messaging host for Playwright's Chromium.
  const manifest = join(rootDir, "zp-nmh-chrome.json");
  writeFileSync(
    manifest,
    JSON.stringify({
      name: NATIVE_HOST,
      description: "ZeroPass (passkey sync test)",
      path: bin("zp-nmh"),
      type: "stdio",
      allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
    }),
  );
  for (const key of HOST_KEYS) {
    execFileSync("reg", ["add", key, "/ve", "/t", "REG_SZ", "/d", manifest, "/f"], { stdio: "ignore" });
  }

  cli(vaultA, ["init"], [PASSWORD_A, PASSWORD_A]);
  cli(vaultA, ["unlock"], [PASSWORD_A]);

  contextA = await launchBrowser(dirA, vaultA);
  const pageA = await contextA.newPage();

  if (USE_WEBAUTHN_IO) {
    const username = `zeropass-sync-${Date.now()}`;

    await step("PC A registers a passkey on https://webauthn.io/", async () => {
      await pageA.goto("https://webauthn.io/", { waitUntil: "domcontentloaded", timeout: 30_000 });
      await pageA.locator("#input-email").fill(username);
      await pageA.locator("#register-button").click();

      await pageA.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
        timeout: 20_000,
      });
      expect(await pressPrompt(pageA, "save"), "Save in ZeroPass button was not found on PC A");
      await pageA.waitForFunction(() => /success/i.test(document.body.innerText), null, { timeout: 20_000 });
    });

    await step("PC A and PC B pair and sync passkey ciphertext over LAN", async () => {
      await pairOverLan(vaultA, vaultB);
    });

    await step("PC B authenticates on https://webauthn.io/ with the synced passkey (from locked state)", async () => {
      cli(vaultB, ["lock"]);
      contextB = await launchBrowser(dirB, vaultB);
      const pageB = await contextB.newPage();
      await pageB.goto("https://webauthn.io/", { waitUntil: "domcontentloaded", timeout: 30_000 });
      await pageB.locator("#input-email").fill(username);
      await pageB.locator("#login-button").click();

      await pageB.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
        timeout: 20_000,
      });
      expect(await pressPrompt(pageB, "unlock"), "Sign in with ZeroPass button was not found on PC B");
      await pageB.waitForFunction(
        () =>
          /logged in|authenticated|success/i.test(document.body.innerText) &&
          (window.location.pathname !== "/" || /logged in/i.test(document.body.innerText)),
        null,
        { timeout: 20_000 },
      );
    });
  } else {
    server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(PASSKEY_PAGE);
    });
    await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
    const { port } = server.address();
    const origin = `http://127.0.0.1:${port}`;

    let aliceCred;
    let bobCred;

    await step("PC A registers alice's passkey in Chromium A", async () => {
      await pageA.goto(origin);
      const createPromise = pageA.evaluate(async () => {
        const cred = await navigator.credentials.create({
          publicKey: {
            challenge: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
            rp: { name: "Sync RP", id: "127.0.0.1" },
            user: {
              id: new TextEncoder().encode("alice-sync-id"),
              name: "alice@sync.test",
              displayName: "Alice Sync",
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        });
        return {
          id: cred.id,
          rawId: Array.from(new Uint8Array(cred.rawId)),
          publicKey: Array.from(new Uint8Array(cred.response.getPublicKey())),
        };
      });
      await pageA.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
        timeout: 10_000,
      });
      expect(await pressPrompt(pageA, "save"), "Save button missing on PC A");
      aliceCred = await createPromise;
      expect(aliceCred.rawId.length === 32, "expected 32-byte credential ID");
      expect(aliceCred.publicKey.length > 60, "expected SPKI public key");
    });

    await step("PC A and PC B pair over LAN and sync passkey ciphertext", async () => {
      const joinOut = await pairOverLan(vaultA, vaultB);
      expect(joinOut.includes("received 1"), `expected 1 synced op on join, got: ${joinOut}`);
    });

    contextB = await launchBrowser(dirB, vaultB);
    const pageB = await contextB.newPage();

    await step("PC B (locked) authenticates as alice in Chromium B and signature verifies against PC A's key", async () => {
      cli(vaultB, ["lock"]);
      await pageB.goto(origin);
      const getPromise = pageB.evaluate(async () => {
        const cred = await navigator.credentials.get({
          publicKey: {
            challenge: new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]),
            rpId: "127.0.0.1",
          },
        });
        return {
          id: cred.id,
          clientDataJSON: Array.from(new Uint8Array(cred.response.clientDataJSON)),
          authenticatorData: Array.from(new Uint8Array(cred.response.authenticatorData)),
          signature: Array.from(new Uint8Array(cred.response.signature)),
          userHandle: Array.from(new Uint8Array(cred.response.userHandle)),
        };
      });
      await pageB.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
        timeout: 10_000,
      });
      expect(await pressPrompt(pageB, "unlock"), "Unlock+Sign button missing on PC B");
      const assertion = await getPromise;
      expect(assertion.id === aliceCred.id, "PC B returned unexpected credential ID");
      expect(Buffer.from(assertion.userHandle).toString("utf8") === "alice-sync-id", "userHandle mismatch");
      verifyP256Assertion(origin, "127.0.0.1", aliceCred.publicKey, assertion);
    });

    await step("PC B registers bob's passkey, syncs back to PC A over LAN, and PC A authenticates as bob", async () => {
      const createBob = pageB.evaluate(async () => {
        const cred = await navigator.credentials.create({
          publicKey: {
            challenge: new Uint8Array([11, 22, 33, 44, 55, 66, 77, 88]),
            rp: { name: "Sync RP", id: "127.0.0.1" },
            user: {
              id: new TextEncoder().encode("bob-sync-id"),
              name: "bob@sync.test",
              displayName: "Bob Sync",
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          },
        });
        return {
          id: cred.id,
          rawId: Array.from(new Uint8Array(cred.rawId)),
          publicKey: Array.from(new Uint8Array(cred.response.getPublicKey())),
        };
      });
      await pageB.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
        timeout: 10_000,
      });
      expect(await pressPrompt(pageB, "save"), "Save button missing on PC B");
      bobCred = await createBob;

      // Sync ciphertext ops B -> A over LAN.
      await syncOverLan(vaultA, vaultB);

      // Authenticate as bob on PC A using allowCredentials so bob is targeted cleanly.
      const getBob = pageA.evaluate(async (rawId) => {
        const cred = await navigator.credentials.get({
          publicKey: {
            challenge: new Uint8Array([21, 22, 23, 24, 25, 26, 27, 28]),
            rpId: "127.0.0.1",
            allowCredentials: [{ type: "public-key", id: new Uint8Array(rawId) }],
          },
        });
        return {
          id: cred.id,
          clientDataJSON: Array.from(new Uint8Array(cred.response.clientDataJSON)),
          authenticatorData: Array.from(new Uint8Array(cred.response.authenticatorData)),
          signature: Array.from(new Uint8Array(cred.response.signature)),
          userHandle: Array.from(new Uint8Array(cred.response.userHandle)),
        };
      }, bobCred.rawId);
      await pageA.waitForFunction(() => document.querySelector("zeropass-passkey-prompt") !== null, null, {
        timeout: 10_000,
      });
      // PC A's passkey domain may be locked after pairOverLan; accept either candidate or unlock button.
      const clicked = (await pressPrompt(pageA, "candidate")) || (await pressPrompt(pageA, "unlock"));
      expect(clicked, "Neither candidate nor unlock button found on PC A");
      const assertion = await getBob;
      expect(assertion.id === bobCred.id, "PC A returned unexpected credential ID for bob");
      expect(Buffer.from(assertion.userHandle).toString("utf8") === "bob-sync-id", "bob userHandle mismatch");
      verifyP256Assertion(origin, "127.0.0.1", bobCred.publicKey, assertion);
    });
  }
} catch (error) {
  failed(error);
} finally {
  await contextA?.close().catch(() => {});
  await contextB?.close().catch(() => {});
  server?.close();
  for (const key of HOST_KEYS) {
    spawnSync("reg", ["delete", key, "/f"], { stdio: "ignore" });
  }
  spawnSync(bin("zp-cli"), ["--vault", vaultA, "daemon", "stop"], { env: withoutVault(), stdio: "ignore" });
  spawnSync(bin("zp-cli"), ["--vault", vaultB, "daemon", "stop"], { env: withoutVault(), stdio: "ignore" });
  rmSync(rootDir, { recursive: true, force: true });
}
finish();
