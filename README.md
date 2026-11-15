# ZeroPass
Zero-server, offline-first password &amp; passkey manager. Syncs instantly across devices via local Wi-Fi and Bluetooth — without touching the internet.

## Status

Under development; not ready for real secrets yet. The plan and progress are in [`.claude/PLAN.md`](.claude/PLAN.md), the design in [`docs/`](docs/).

## Installing on Windows (development builds)

```powershell
# Build the package (target\package\ZeroPass-<version>-windows-x64)
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1
# Install it for every user of this PC (as administrator)
powershell -NoProfile -ExecutionPolicy Bypass -File .\target\package\ZeroPass-0.0.0-windows-x64\install.ps1
# Then, as yourself, in a new terminal
zp-cli init
```

ZeroPass goes to `C:\Program Files\ZeroPass` and starts at logon for users who have a vault; your vault is kept in `%LOCALAPPDATA%\ZeroPass\Vault`. Why it is installed this way: [ADR-0008](docs/adr/0008-windows-installation.md).

## License

ZeroPass is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 3, as published by the Free Software Foundation. It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See [LICENSE](LICENSE) for the full text.
