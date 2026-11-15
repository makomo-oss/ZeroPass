// The extension on the login pages of well-known sites (P4-05): for each, a
// dummy login is put into a test vault; the page is opened in Chromium with
// the extension; the user-name (or password) field is clicked; the login is
// picked from ZeroPass's list; the fields must hold the dummy values.
// Nothing is ever submitted. Needs the internet; run by hand:
//
//   node e2e/sites.e2e.mjs [--headed] [--only=github,gitlab]
//
// Prints a Markdown table of the results.

import { setTimeout as sleep } from "node:timers/promises";

import { addLogin, failed, launchBrowser, pickFirst, setUp } from "./harness.mjs";

const USER = "zeropass.test@example.invalid";
const SECRET = "ZeroPass-dummy-1!";

/** The sites: where the login page is, and the URL the login is saved with. */
const SITES = [
  ["GitHub", "https://github.com/login", "https://github.com"],
  ["GitLab", "https://gitlab.com/users/sign_in", "https://gitlab.com"],
  ["Stack Overflow", "https://stackoverflow.com/users/login", "https://stackoverflow.com"],
  // Wikipedia signs in on wikimedia.org: another site than wikipedia.org.
  ["Wikipedia", "https://en.wikipedia.org/w/index.php?title=Special:UserLogin", "https://auth.wikimedia.org"],
  ["Hacker News", "https://news.ycombinator.com/login", "https://news.ycombinator.com"],
  ["Reddit", "https://www.reddit.com/login/", "https://www.reddit.com"],
  ["LinkedIn", "https://www.linkedin.com/login", "https://www.linkedin.com"],
  ["Facebook", "https://www.facebook.com/login/", "https://www.facebook.com"],
  ["Instagram", "https://www.instagram.com/accounts/login/", "https://www.instagram.com"],
  ["X", "https://x.com/i/flow/login", "https://x.com"],
  ["Google", "https://accounts.google.com/", "https://accounts.google.com"],
  ["Microsoft", "https://login.live.com/", "https://login.live.com"],
  ["Apple", "https://account.apple.com/sign-in", "https://apple.com"],
  ["Dropbox", "https://www.dropbox.com/login", "https://www.dropbox.com"],
  ["PayPal", "https://www.paypal.com/signin", "https://www.paypal.com"],
  ["Netflix", "https://www.netflix.com/login", "https://www.netflix.com"],
  ["Discord", "https://discord.com/login", "https://discord.com"],
  ["Twitch", "https://www.twitch.tv/login", "https://www.twitch.tv"],
  ["WordPress.com", "https://wordpress.com/log-in", "https://wordpress.com"],
  ["Yahoo! JAPAN", "https://login.yahoo.co.jp/config/login", "https://login.yahoo.co.jp"],
  ["Atlassian", "https://id.atlassian.com/login", "https://id.atlassian.com"],
  ["Spotify", "https://accounts.spotify.com/login", "https://accounts.spotify.com"],
  ["Zoom", "https://zoom.us/signin", "https://zoom.us"],
  ["Pinterest", "https://www.pinterest.com/login/", "https://www.pinterest.com"],
  ["note", "https://note.com/login", "https://note.com"],
  // Notion signs in on notion.com: another site than notion.so.
  ["Notion", "https://www.notion.so/login", "https://app.notion.com"],
  ["Hugging Face", "https://huggingface.co/login", "https://huggingface.co"],
  ["npm", "https://www.npmjs.com/login", "https://www.npmjs.com"],
  ["PyPI", "https://pypi.org/account/login/", "https://pypi.org"],
  ["Docker", "https://login.docker.com/u/login/identifier", "https://login.docker.com"],
  ["Mozilla accounts", "https://accounts.firefox.com/", "https://accounts.firefox.com"],
  ["Proton", "https://account.proton.me/login", "https://account.proton.me"],
  ["Steam", "https://store.steampowered.com/login/", "https://store.steampowered.com"],
  ["Tumblr", "https://www.tumblr.com/login", "https://www.tumblr.com"],
  ["Vimeo", "https://vimeo.com/log_in", "https://vimeo.com"],
  ["Kaggle", "https://www.kaggle.com/account/login?phase=emailSignIn", "https://www.kaggle.com"],
  ["Amazon", "https://www.amazon.co.jp/-/en/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.co.jp%2F&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=jpflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0", "https://www.amazon.co.jp"],
];

/** Fields worth clicking, user-name fields first. */
const USERNAME_FIELDS = [
  "input[autocomplete~='username' i]",
  "input[type='email']",
  "input[autocomplete~='email' i]",
  "input[name*='user' i]",
  "input[name*='email' i]",
  "input[name*='login' i]",
  "input[id*='user' i]",
  "input[id*='email' i]",
  "input[id*='login' i]",
  "input[name='identifier']",
].join(", ");

async function firstVisible(frame, selector) {
  const all = frame.locator(selector);
  const count = Math.min(await all.count(), 10);
  for (let index = 0; index < count; index += 1) {
    const field = all.nth(index);
    if ((await field.isVisible().catch(() => false)) && (await field.isEditable().catch(() => false))) {
      return field;
    }
  }
  return null;
}

/** The field to click: in any frame, a user-name field, else a password. */
async function candidate(page) {
  for (const preferPassword of [false, true]) {
    for (const frame of page.frames()) {
      const field = await firstVisible(frame, preferPassword ? "input[type='password']" : USERNAME_FIELDS);
      if (field) return { frame, field, isPassword: preferPassword };
    }
  }
  return null;
}

async function trySite(context, [name, url]) {
  const row = { name, loaded: "", offered: "", filled: "", note: "" };
  const page = await context.newPage();
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 45_000 });
    await sleep(5000);
    row.loaded = "yes";
    const found = await candidate(page);
    if (!found) {
      row.offered = "no";
      row.note = "no login field found by the test";
      return row;
    }
    const { frame, field, isPassword } = found;
    await field.click({ timeout: 10_000 });
    const shown = await frame
      .waitForFunction(() => document.querySelector("zeropass-suggestions") !== null, null, {
        timeout: 8000,
      })
      .then(() => true)
      .catch(() => false);
    row.offered = shown ? "yes" : "no";
    if (!shown) {
      row.note = "ZeroPass did not recognise the field";
      return row;
    }
    await pickFirst(page, field);
    const expected = isPassword ? SECRET : USER;
    const filled = await frame
      .waitForFunction(
        ({ value }) => {
          const all = [...document.querySelectorAll("input")];
          return all.some((input) => input.value === value);
        },
        { value: expected },
        { timeout: 6000 },
      )
      .then(() => true)
      .catch(() => false);
    const password = await frame
      .evaluate((secret) => [...document.querySelectorAll("input[type=password]")].some((input) => input.value === secret), SECRET)
      .catch(() => false);
    const passwordShown = await firstVisible(frame, "input[type='password']");
    if (!filled) {
      row.filled = "no";
    } else if (isPassword || password) {
      row.filled = isPassword ? "password" : "user name + password";
    } else {
      row.filled = "user name";
      if (!passwordShown) row.note = "two-step: the password comes on the next page";
    }
    if (frame !== page.mainFrame()) row.note = [row.note, `in a frame (${new URL(frame.url()).host})`].filter(Boolean).join("; ");
  } catch (error) {
    row.loaded = row.loaded || "no";
    row.note = String(error).split("\n")[0].slice(0, 120);
  } finally {
    await page.close().catch(() => {});
  }
  return row;
}

const only = process.argv.find((arg) => arg.startsWith("--only="))?.slice(7).split(",");
const sites = only ? SITES.filter(([name]) => only.some((wanted) => name.toLowerCase().includes(wanted.toLowerCase()))) : SITES;

const setup = setUp();
let context;
const rows = [];
try {
  for (const [name, , saved] of sites) {
    addLogin(setup.vault, name, USER, SECRET, saved);
  }
  context = await launchBrowser(setup.dir, setup.vault);
  for (const site of sites) {
    const row = await trySite(context, site);
    rows.push(row);
    console.log(`${row.name}: loaded ${row.loaded}, offered ${row.offered}, filled ${row.filled || "-"}${row.note ? ` (${row.note})` : ""}`);
  }
} catch (error) {
  failed(error);
} finally {
  await context?.close().catch(() => {});
  setup.close();
}

console.log("\n| Site | Page loaded | List offered | Filled | Note |\n|---|---|---|---|---|");
for (const row of rows) {
  console.log(`| ${row.name} | ${row.loaded} | ${row.offered} | ${row.filled || "-"} | ${row.note} |`);
}
const worked = rows.filter((row) => row.filled !== "" && row.filled !== "no").length;
console.log(`\nfilled on ${worked} of ${rows.length} sites`);
