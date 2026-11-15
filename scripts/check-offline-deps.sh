#!/usr/bin/env bash
# Fail if any crate that must stay offline (the vault, and the user interfaces) depends,
# directly or transitively, on a networking crate. See docs/adr/0004-process-architecture.md.
#
# This is a build-time guard; the OS sandbox (P3-03) is the runtime guard.
# The workspace-wide cargo-deny ban list cannot express this, because zp-syncd is
# allowed (and required) to use networking crates.
#
# Usage: scripts/check-offline-deps.sh
set -euo pipefail

# Crates that must never reach the network, on every platform.
OFFLINE_CRATES=(zp-crypto zp-sync zp-pairing zp-vault zp-drive zp-ipc zp-sandbox zp-origin zp-import zp-client zp-vaultd zp-keyagent zp-autostart zp-nmh zp-cli)

# Crates that are built for desktop platforms only, and checked for those
# (docs/adr/0009-desktop-application.md): Tauri depends on an HTTP client on
# Android and iOS only, which the desktop application is never built for.
DESKTOP_CRATES=(zeropass-desktop)
DESKTOP_TARGETS=(x86_64-pc-windows-msvc aarch64-pc-windows-msvc x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-apple-darwin)

# Crates that provide sockets, network protocols or radio access.
# `mio` covers tokio's net/process/signal features; tokio without them is allowed.
BANNED=(
  mio socket2 polling async-io async-net
  hyper h2 h3 quinn reqwest ureq isahc attohttpc curl curl-sys surf
  rustls native-tls tokio-rustls tokio-native-tls
  tungstenite tokio-tungstenite
  hickory-resolver hickory-proto trust-dns-resolver trust-dns-proto
  mdns-sd libmdns zeroconf
  btleplug bluer bluest
  libp2p
)

failed=0
checked=0

# check <description> <cargo tree target arguments...> -- <crates...>
check() {
  local what=$1
  shift
  local target_args=()
  while [[ $1 != -- ]]; do
    target_args+=("$1")
    shift
  done
  shift
  local pkg_args=()
  for c in "$@"; do pkg_args+=(-p "$c"); done

  # Normal (runtime) dependencies only.
  local deps
  deps=$(cargo tree "${pkg_args[@]}" --edges normal "${target_args[@]}" --prefix none \
    --format '{p}' --locked | tr -d '\r' | awk 'NF {print $1}' | sort -u)
  checked=$((checked + $(wc -l <<<"$deps")))

  local violations=()
  for b in "${BANNED[@]}"; do
    if grep -qx -- "$b" <<<"$deps"; then
      violations+=("$b")
    fi
  done

  if ((${#violations[@]})); then
    echo "error: networking crates found in the dependency tree of $what:" >&2
    for v in "${violations[@]}"; do
      echo "  - $v (pulled in via:)" >&2
      cargo tree "${pkg_args[@]}" --edges normal "${target_args[@]}" --locked -i "$v" 2>/dev/null \
        | tr -d '\r' | sed 's/^/      /' >&2 || true
    done
    failed=1
  fi
}

check "offline crates (every target)" --target all -- "${OFFLINE_CRATES[@]}"
for target in "${DESKTOP_TARGETS[@]}"; do
  check "desktop crates ($target)" --target "$target" -- "${DESKTOP_CRATES[@]}"
done

if ((failed)); then
  echo "Offline crates: ${OFFLINE_CRATES[*]}; desktop crates: ${DESKTOP_CRATES[*]}." >&2
  echo "See docs/adr/0004-process-architecture.md and docs/adr/0009-desktop-application.md." >&2
  exit 1
fi

echo "ok: ${OFFLINE_CRATES[*]} and, on desktop targets, ${DESKTOP_CRATES[*]} have no networking dependencies ($checked crate entries checked)"
