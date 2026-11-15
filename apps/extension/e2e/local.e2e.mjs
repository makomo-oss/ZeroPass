// End-to-end test of the extension on pages served here: the real extension
// in Chromium, the real bridge, the real vault daemon. Windows only.
//
//   node e2e/local.e2e.mjs [--headed]

import { createServer } from "node:http";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import {
  addLogin,
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

const TWO_STEP_PAGE = `<!doctype html><title>Step 1</title>
<form><input type="email" id="identifier" autocomplete="username"><button>Next</button></form>`;

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

  addLogin(setup.vault, "Local", USER, SECRET, site);
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
} catch (error) {
  failed(error);
} finally {
  await context?.close().catch(() => {});
  server?.close();
  setup.close();
}
finish();
