#!/usr/bin/env bash
# 构建 Python wheel。可选参数：目标 triple（默认构建宿主平台）。
set -euo pipefail
cd "$(dirname "$0")/../bindings/python"

target="${1:-}"
args=(--release --out dist)
if [[ -n "$target" ]]; then
  args+=(--target "$target")
fi

maturin build "${args[@]}"
ls -lh dist/*.whl
