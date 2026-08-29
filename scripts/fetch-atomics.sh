#!/usr/bin/env bash
# Vendor Atomic Red Team at the commit recorded in mappings/atomic-red-team.commit.
#
# This PINS: it checks out the recorded commit and verifies HEAD matches, so two
# people running it get byte-identical atomics. (The older path in lab-fetch.sh
# cloned HEAD and then recorded whatever it happened to get, which is a record,
# not a pin — a re-clone months later would silently change every command the
# engine runs.)
set -euo pipefail
cd "$(dirname "$0")/.."

art=lab/atomic-red-team
pin_file=mappings/atomic-red-team.commit

if [ ! -f "$pin_file" ]; then
  echo "no pin recorded at $pin_file" >&2
  exit 1
fi
pin=$(tr -d '[:space:]' < "$pin_file")

if [ ! -d "$art/.git" ]; then
  echo "cloning atomic-red-team…"
  rm -rf "$art"
  git clone --filter=blob:none --no-checkout \
    https://github.com/redcanaryco/atomic-red-team.git "$art"
fi

echo "checking out pinned commit ${pin}"
git -C "$art" fetch --depth 1 origin "$pin" 2>/dev/null || git -C "$art" fetch origin
git -C "$art" checkout --quiet --detach "$pin"

actual=$(git -C "$art" rev-parse HEAD)
if [ "$actual" != "$pin" ]; then
  echo "PIN MISMATCH: wanted $pin, got $actual" >&2
  exit 1
fi

count=$(find "$art/atomics" -maxdepth 1 -mindepth 1 -type d | wc -l)
echo "atomic-red-team pinned at $actual (${count} techniques)"
