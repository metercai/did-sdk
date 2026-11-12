#!/usr/bin/env bash
# 三语言 golden vector 一致性检查。
#
# 三套测试都读取 tests/vectors/signing_vectors.json；任何一套偏离都会失败。
set -euo pipefail
cd "$(dirname "$0")/.."
root="$(pwd)"

echo "== Rust =="
cargo test --locked --test vectors

echo "== Python =="
python3 -m venv "$root/.venv-vectors"
# shellcheck disable=SC1091
source "$root/.venv-vectors/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet pytest
( cd bindings/python && maturin build --release --out dist )
python -m pip install --quiet --force-reinstall bindings/python/dist/*.whl
python -m pytest bindings/python/tests

echo "== Node =="
( cd bindings/node && npm ci && npx napi build --platform --release && npm test )
