#!/usr/bin/env bash
# Type-check the Rust side for every Apple target from Linux (no Xcode).
#
# `cargo check` never links, but C build scripts (aws-lc-sys, blake3) still
# run and need an Apple SDK. Without one, point them at a stand-in compiler
# that emits empty objects: the Rust code is fully checked, the C code is
# not (that only happens in the real build-xcframework.sh on macOS).
#
#   apple/check-apple-targets.sh                # all targets, sbr-apple
#   apple/check-apple-targets.sh -p sbr-core    # extra cargo args
set -euo pipefail
cd "$(dirname "$0")/.."

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios-macabi aarch64-apple-tvos aarch64-apple-tvos-sim)
ARGS=("$@")
[ ${#ARGS[@]} -eq 0 ] && ARGS=(-p sbr-apple --all-targets)

stub=""
if [ "$(uname)" != Darwin ]; then
  stub=$(mktemp -d)
  trap 'rm -rf "$stub"' EXIT
  printf '%s\n' '#!/bin/sh' 'out=""' \
    'while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; -E) exit 0;; esac; shift; done' \
    '[ -n "$out" ] && : > "$out"' 'exit 0' > "$stub/cc"
  printf '%s\n' '#!/bin/sh' 'for a in "$@"; do case "$a" in *.a) : > "$a";; esac; done' 'exit 0' > "$stub/ar"
  chmod +x "$stub/cc" "$stub/ar"
fi

status=0
for t in "${TARGETS[@]}"; do
  if ! rustup target list --installed | grep -qx "$t"; then
    rustup target add "$t" >/dev/null 2>&1 || { echo "skip  $t (no rust-std)"; continue; }
  fi
  env_args=()
  if [ -n "$stub" ]; then
    u=${t//-/_}
    env_args=("CC_$u=$stub/cc" "AR_$u=$stub/ar" "SDKROOT=$stub")
  fi
  if env "${env_args[@]}" cargo check --quiet --target "$t" "${ARGS[@]}" 2>"${TMPDIR:-/tmp}/sbr-check-$t.log"; then
    echo "ok    $t"
  else
    echo "FAIL  $t (see ${TMPDIR:-/tmp}/sbr-check-$t.log)"
    status=1
  fi
done

exit $status
