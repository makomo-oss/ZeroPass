# ZeroPass browser extension

Fills the logins of the ZeroPass vault into web pages, and makes and uses
passkeys kept in the vault. Built with
[WXT](https://wxt.dev/) and TypeScript: Manifest V3 for Chrome and Edge,
Manifest V2 for Firefox. How it works and what it guards against:
[`docs/spec/extension.md`](../../docs/spec/extension.md).

The extension keeps no secret. Its background talks to the bridge `zp-nmh`
(native messaging), which asks the vault daemon; the daemon decides which
logins belong to the page, by the origin the browser reports.

- `src/entrypoints/background.ts` — the connection to the bridge; takes each
  request's origin from the browser (`sender`).
- `src/entrypoints/content.ts` — finds login fields, shows the matching
  logins under the field (closed shadow DOM), fills the one the user picks.
- `src/entrypoints/webauthn.content.ts` — in the page's own world:
  answers `navigator.credentials.create` / `.get` through ZeroPass when the
  user wants it, otherwise leaves them to the browser.
- `src/entrypoints/passkeys.content.ts` — the extension's side of a passkey
  request: the dialog (closed shadow DOM), the request to ZeroPass.
- `src/entrypoints/popup/` — the toolbar popup.
- `src/lib/` — field detection, filling, visibility, origins (unit-tested).

## Build

```sh
npm ci
npm run build            # .output/chrome-mv3
npm run build:firefox    # .output/firefox-mv2
```

The Chrome-family identifier is fixed by the public key in `wxt.config.ts`
(`gehobienihkbhglhnibeobdkgeinamdn`), Firefox's by its gecko id
(`zeropass@makomo-oss.github.io`); the bridge serves these only. The Windows
package ships both builds in `browser-extension\` (see
`packaging/windows/README.txt` for adding them to a browser).

## Checks

```sh
npm run check    # TypeScript
npm test         # vitest (happy-dom)
npm audit --audit-level=moderate
```

End to end (Windows): the real extension in Playwright's Chromium, the real
bridge and the real vault daemon. Build the Rust programs first
(`cargo build -p zp-nmh -p zp-vaultd -p zp-cli -p zp-keyagent`) and get the
browser once (`npx playwright install chromium`). The tests register the
bridge for that browser under `HKCU` while they run and remove it after.

```sh
node e2e/local.e2e.mjs                 # pages served locally (also in CI)
node e2e/passkeys.e2e.mjs              # passkeys, checked by @simplewebauthn/server (also in CI)
node e2e/sites.e2e.mjs --offscreen     # login pages of well-known sites
node e2e/webauthn-io.e2e.mjs --offscreen  # a passkey on https://webauthn.io
```

`sites.e2e.mjs` opens each site's login page, clicks the user-name (or
password) field, picks the dummy login from ZeroPass's list and checks the
fields; it never submits. `--offscreen` runs a browser with a window placed
out of sight, because several sites refuse headless browsers. Results:
[`docs/extension-sites.md`](../../docs/extension-sites.md).
