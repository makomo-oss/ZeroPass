#!/usr/bin/env bash
# Fail if any crate that must stay offline (layer 1: the vault) depends, directly or
# transitively, on a networking crate. See docs/adr/0004-process-architecture.md.
#
# This is a build-time guard; the OS sandbox (P3-03) is the runtime guard.
# The workspace-wide cargo-deny ban list cannot express this, because zp-syncd is
# allowed (and required) to use networking crates.
#
# Usage: scripts/check-offline-deps.sh
set -euo pipefail

# Crates that must never reach the network.
OFFLINE_CRATES=(zp-crypto zp-sync zp-pairing zp-vault zp-ipc zp-sandbox zp-vaultd)

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

pkg_args=()
for c in "${OFFLINE_CRATES[@]}"; do pkg_args+=(-p "$c"); done

# Normal (runtime) dependencies only, for every target platform.
deps=$(cargo tree "${pkg_args[@]}" --edges normal --target all --prefix none \
  --format '{p}' --locked | tr -d '\r' | awk 'NF {print $1}' | sort -u)

violations=()
for b in "${BANNED[@]}"; do
  if grep -qx -- "$b" <<<"$deps"; then
    violations+=("$b")
  fi
done

if ((${#violations[@]})); then
  echo "error: networking crates found in the dependency tree of offline crates:" >&2
  for v in "${violations[@]}"; do
    echo "  - $v (pulled in via:)" >&2
    cargo tree "${pkg_args[@]}" --edges normal --target all --locked -i "$v" 2>/dev/null \
      | tr -d '\r' | sed 's/^/      /' >&2 || true
  done
  echo "Offline crates: ${OFFLINE_CRATES[*]}. See docs/adr/0004-process-architecture.md." >&2
  exit 1
fi

echo "ok: ${OFFLINE_CRATES[*]} have no networking dependencies ($(wc -l <<<"$deps") crates checked)"
