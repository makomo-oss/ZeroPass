ZeroPass for Windows
====================

ZeroPass is a password and passkey manager without a server. Your vault stays
on your devices and syncs between them over your local network or Bluetooth.

Install (needs administrator rights once; Windows asks for them):

    In this folder:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1

    The programs go to C:\Program Files\ZeroPass, where only administrators
    can change them. ZeroPass trusts its own programs by that location.
    Windows Firewall lets the sync daemon accept connections from devices on
    your local network (the same subnet) only. Those connections are
    authenticated and encrypted, and never leave the local network.

Create your vault (as yourself):

    Open ZeroPass from the Start menu, or in a new terminal:  zp-cli init

    The vault is kept in %LOCALAPPDATA%\ZeroPass\Vault\vault.zpvault.
    Windows Hello protects the TOTP and passkey parts; set it up first in
    Settings > Accounts > Sign-in options.

    Then make a recovery kit and keep it offline.

Browser extension (fills your logins into web pages):

    Chrome or Edge: open chrome://extensions (edge://extensions), turn on
    "Developer mode", choose "Load unpacked" and pick
    C:\Program Files\ZeroPass\browser-extension\chrome

    Firefox: open about:debugging#/runtime/this-firefox, choose "Load
    Temporary Add-on" and pick
    C:\Program Files\ZeroPass\browser-extension\firefox\manifest.json
    (Firefox removes it when it closes, until the extension is published.)

    The extension keeps no password. When you pick a login under a field, it
    asks ZeroPass for that one login, and only if it belongs to the page.
    Unlock ZeroPass in the desktop application first.

    Passkeys: when a site offers to create a passkey or to sign in with one,
    ZeroPass asks whether to use it ("Save in ZeroPass" / "Use ZeroPass") or
    to leave it to the browser ("Use another device or key"). Windows Hello
    confirms every passkey. Passkeys sync to your other devices like
    everything else; see them in the desktop application under "Passkeys".

    A PC that joined the vault before Windows Hello was set up on it has no
    one-time codes or passkeys yet. Set up Windows Hello (a PIN), then on a
    PC that has them choose Devices > "Add a device", and enter the code it
    shows on this PC under "Passkeys" (or "One-time codes") > "Get the keys".

Uninstall: "Installed apps" > ZeroPass > Uninstall, or:

    powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\ZeroPass\uninstall.ps1"

    Your vault is kept.

More: https://github.com/makomo-oss/ZeroPass
License: GNU General Public License, version 3 (see LICENSE).
