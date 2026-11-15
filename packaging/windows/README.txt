ZeroPass for Windows
====================

ZeroPass is a password and passkey manager without a server. Your vault stays
on your devices and syncs between them over your local network or Bluetooth.

Install (needs administrator rights once; Windows asks for them):

    In this folder:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1

    The programs go to C:\Program Files\ZeroPass, where only administrators
    can change them. ZeroPass trusts its own programs by that location.
    Windows Firewall lets the sync daemon accept connections from your other
    devices on private networks (not on public ones).

Create your vault (as yourself, in a new terminal):

    zp-cli init

    The vault is kept in %LOCALAPPDATA%\ZeroPass\Vault\vault.zpvault.
    Windows Hello protects the TOTP and passkey parts; set it up first in
    Settings > Accounts > Sign-in options.

    Then make a recovery kit and keep it offline:  zp-cli recovery-kit

Uninstall: "Installed apps" > ZeroPass > Uninstall, or:

    powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\ZeroPass\uninstall.ps1"

    Your vault is kept.

More: https://github.com/makomo-oss/ZeroPass
License: GNU General Public License, version 3 (see LICENSE).
