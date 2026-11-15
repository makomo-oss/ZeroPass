import { defineConfig } from "wxt";

// The ZeroPass browser extension (docs/spec/extension.md). It keeps no secret:
// it asks the vault daemon, through the native messaging host zp-nmh, for one
// login at a time when the user picks it.


/**
 * The public key that fixes the Chrome-family extension identifier of an
 * unpacked build, gehobienihkbhglhnibeobdkgeinamdn, which the bridge serves
 * (docs/spec/extension.md §2). A public key: no secret.
 */
const CHROME_KEY =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoucHw+apLbvmtapzSDUgyP5BdA37lZ6MRRGaH/DUKBih33Ap6JbMCzf7fEPux1H+nLPdmldobgKUh9/J839aBKSUxgN0L0loLn6qgY2pEbO9dMT93VjOIIbG838ezRFcEBla5m8sSqzgg5J2EeixkRTSgfsM0mZE2xSZ45FHYKdvOvKHF3QSQuyUJFy0FR4irIkh4khBbPQzAwZH7lAOsCLrWfwGCj5R0LUHPDGbxnV5/tkIDFf/FQfHSwN4Ah+BtHjQYPWz3EqRu8sNuXLmZZmaet7jx0GocvJ4xIKNDLZQN8jPxZ6/IwhZokV1bobJR9XKMjUK6GDM9HxwJeu7EQIDAQAB";

export default defineConfig({
  srcDir: "src",
  manifest: ({ browser }) => ({
    name: "ZeroPass",
    description:
      "Fills your logins from ZeroPass, the password manager without a server. Needs the ZeroPass desktop application.",
    // Only the bridge to the desktop application. No storage, no tabs, no
    // addresses of tabs: the popup asks a tab's own content script.
    permissions: ["nativeMessaging"],
    ...(browser === "firefox"
      ? {
          browser_specific_settings: {
            gecko: { id: "zeropass@makomo-oss.github.io", strict_min_version: "115.0" },
          },
        }
      : { key: CHROME_KEY }),
  }),
});
