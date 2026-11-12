#!/usr/bin/env bash
# 构建 Node addon。可选参数：目标 triple（默认构建宿主平台）。
set -euo pipefail
cd "$(dirname "$0")/../bindings/node"

target="${1:-}"
if [[ -f package-lock.json ]]; then
  npm ci
else
  npm install
fi

if [[ -n "$target" ]]; then
  if [[ "$target" == *musl* ]]; then
    npx napi build --platform --release --target "$target" --zig
  else
    npx napi build --platform --release --target "$target"
  fi
else
  npx napi build --platform --release
fi
