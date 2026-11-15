# ZeroPass desktop application

A window onto the vault: [Tauri 2](https://tauri.app/) with a Svelte 5 +
TypeScript page. The vault daemon holds the vault; this program asks it over
the local IPC with the UI role, like `zp-cli`. Decisions and limits:
[ADR-0009](../../docs/adr/0009-desktop-application.md).

- `src/` — the page (Svelte). It calls only the application's own commands.
- `src-tauri/` — the program (`zeropass`, Cargo package `zeropass-desktop`, a
  member of the Rust workspace). The commands are in `src-tauri/src/commands.rs`.

## Build

The page is embedded into the program when the program is compiled, so build
the page first:

```sh
cd apps/desktop
npm ci
npm run build          # writes dist/
cd ../..
cargo build -p zeropass-desktop     # target/debug/zeropass(.exe)
```

Without `dist/`, `cargo build` puts a placeholder page there that says the
page was not built, so that the Rust workspace builds without Node.js. Run
`npm run build` and build again to replace it. `scripts/package-windows.ps1`
builds the page itself and refuses the placeholder.

The program must stay next to `zp-vaultd`, `zp-syncd` and `zp-keyagent`:
the daemons admit it, and it trusts them, by that directory. `cargo build`
puts them all in `target/<profile>/`.

While changing the page, `npm run watch` rebuilds `dist/` on every change;
rebuild the program to embed it. There is no development server: the
program never loads a page from anywhere (ADR-0009).

## Run

```sh
target/debug/zeropass --vault <file> [--no-hardware-keystore | --insecure-software-keystore] [--no-sandbox]
```

Without `--vault`, the same default vault as `zp-cli`
(`%LOCALAPPDATA%\ZeroPass\Vault\vault.zpvault` on Windows).

`--startup-time <FILE>` writes the milliseconds from the start of the process
until the first screen is drawn, then exits (P4-01).

## Checks

```sh
npm run check     # svelte-check (TypeScript), warnings fail
npm test          # vitest
npm audit --audit-level=moderate
```

Known `npm audit` findings below that level: `deepmerge` (low; prototype
pollution in merging objects) inside `@sveltejs/vite-plugin-svelte`, which
merges the build configuration only and is not part of the page.

## Icons

`src-tauri/icons/` was generated from `src-tauri/icons/source.png` with
`npx @tauri-apps/cli icon` (only the files listed in `tauri.conf.json` are
kept).
