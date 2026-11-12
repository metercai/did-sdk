# did-sdk 实施报告

| 项目 | 内容 |
|---|---|
| 日期 | 2026-11-12 |
| 计划版本 | `docs/implementation-plan.md` v0.1（已批准） |
| 范围 | P0–P6 本地可执行部分 |
| 结论 | Rust 核心、keyvault-core、Python/Node 绑定、golden vector、本地构建与测试完成；跨平台 CI 与真实链验证待外部条件 |

---

## 1. 阶段完成情况

| 阶段 | 状态 | 交付物 |
|---|---|---|
| P0 | ✅ | `keyvault-core`（trait / crypto / MemoryKeystore / FileKeystore / password / index / KVLT）、`did-sdk` config/error/trait/SdkCore |
| P1 | ✅ | `signing_input` 三函数 + `vp_v1`；`tests/vectors/signing_vectors.json`；`tests/vectors.rs` |
| P2 | ✅ | `types` / `vc` / `did_signature` / `server_request` / `MockDidSdk` / `CentralizedDidSdk` / `ChainModeDidSdk`；配置、UserRejected、Centralized 契约、三模式一致性测试 |
| P3 | ✅（本地） | `examples/mini_cli` 原生 release 构建并运行；musl/Windows 交给 CI |
| P4 | ✅ | PyO3 绑定（异步 API、异常、纯函数、`resolved_config`、`.pyi`）；maturin wheel；pytest 7 项 |
| P5 | ✅ | napi-rs 绑定（异步 API、Buffer、错误码 wrapper、`.d.ts`）；vitest 6 项 |
| P6 | ⏳（部分） | CI workflows、README、验收清单、跨语言脚本已完成；GitHub 远程/CI 待推送 |

---

## 2. 本地验证证据

### 2.1 Rust

```text
cargo fmt --all -- --check                    # 通过
cargo clippy --workspace --all-targets -D warnings  # 通过
cargo test --workspace --exclude did-sdk-python --exclude did-sdk-node
  keyvault-core: 4 unit + 10 integration = 14 passed
  did-sdk:       3 unit + 26 integration = 29 passed, 1 ignored
```

覆盖：

- did:key 往返、BLAKE2b-256 已知向量、KVLT 格式往返；
- Memory/File keystore 生成、签名、公钥、列举、删除；
- 错误密码 → `InvalidPassword`；
- 密码来源：Env / File / Direct / AutoGenerate；unix `0600`；
- 配置优先级：默认 / 环境变量 / 部分 TOML / 显式覆盖；密码优先级；
- `UserRejected` 三来源：Mock AutoReject、vault 返回、handler 返回；
- Mock/Centralized/Chain 本地一致性；
- Centralized 只读契约（wiremock，全部 GET，缓存命中）；
- DID-Signature header 构造/验签；
- VC 签发/存储/读取/列举/删除、VP 构造、授权签名；
- 三语言 golden vector 的 Rust 侧逐字节断言。

### 2.2 Python

```text
maturin build --release --out dist
pip install dist/*.whl pytest
pytest bindings/python/tests -q
  → 7 passed
```

覆盖 golden vector（did_signature_v1 / issued_vc_v1 / vp_v1 / fixed seed）、
异步 API roundtrip、VC/VP、DID-Signature、授权签名、异常导入、未知 override。

### 2.3 Node

```text
npm ci
npx napi build --platform --release
npm test
  → 6 passed
```

覆盖同一组 golden vector、异步 API roundtrip、`err.code === "InvalidArgument"`
（自定义 JS wrapper）。

### 2.4 跨语言

```bash
bash scripts/cross-lang-vectors.sh
```

Rust/Python/Node 都读取 `tests/vectors/signing_vectors.json`，脚本退出码 0。

### 2.5 原生可执行

```bash
cargo build --release --example mini_cli
DID_SDK_HOME=$PWD/.local-home ./target/release/examples/mini_cli
# did=did:key:z6Mk...
# sig_len=64
```

---

## 3. 实现要点

### 3.1 keyvault-core

- `FileKeystore`：Argon2id（64 MiB / t=3 / p=1）+ ChaCha20-Poly1305；
  KVLT 文件格式；AEAD AAD 绑定 magic/version/key_type/salt；
  key 文件名 = blake2b256(key_id) hex；`index.json` 原子写；
  自动生成密码文件 0600；错误密码统一 `InvalidPassword`。
- `MemoryKeystore`：测试/Mock/显式内存模式；Ed25519 生成与签名。
- `crypto`：Ed25519、sr25519、multibase did:key、base58、BLAKE2b-256。
- `signing_input`：三语言共享的唯一字符串拼接实现；新增 `vp_v1`。

### 3.2 did-sdk

- `SdkCore`：active key、签名、handler、VC 存储、错误映射收敛到一处。
- Mock：`AutoConfirm` / `AutoReject` / `Delay`；预置 anchor。
- Centralized：reqwest + rustls；仅 GET；TTL 缓存；404 语义。
- Chain：subxt 动态 storage 查询；懒连接；无链账户 signer；TTL 缓存；
  真实链测试 `#[ignore]`。
- VC/VP：W3C 风格字段；RFC3339 自实现；proof 使用 base58；
  `anchor_id` 使用 BLAKE2b-256 作为本地存储键。
- DID-Signature header：`DID-Signature-v1.<multibase base64url JSON>`；
  `verify` 本地解析 did:key，不访问网络。

### 3.3 绑定

- Python：PyO3 0.23 + pyo3-async-runtimes；`create_exception!` 定义
  `DidSdkError` / `UserRejectedError` / `NotFoundError` / `InvalidArgumentError`；
  `pythonize` 负责 serde JSON ↔ dict；`python-source` 修复 wheel 布局。
- Node：napi-rs 2；`serde_json::Value` 直出 JS 对象；手写 `wrapper.js`
  把原生错误 reason 前缀转成 `err.code`；`index.d.ts` 自动生成并提交。

---

## 4. 与计划的偏差 / 实现决定

| 项 | 计划 | 实际 |
|---|---|---|
| `create_did` / `issue_self_asserted_vc` | async（D-05） | 已按 async 实现 |
| VP 签名输入 | 新增 `vp_v1`（D-06） | 已实现并纳入 golden vector |
| Python 异常 | `create_exception!`（D-12） | 已实现；`UserRejectedError` 等 |
| Node `err.code` | JS wrapper（D-13） | `wrapper.js` 已实现 |
| Chain 元数据 | 动态查询 + ignore（D-14） | 已实现；真实链未验证 |
| MSRV | 1.88.0（D-01） | 已固定 |
| 文件存储 | 三模式统一 `VcStore`（D-08） | 已实现 |
| DID-Signature header | 附录 C 格式（D-07） | 已实现 |

---

## 5. 未完成 / 外部依赖

1. **GitHub 远程仓库**：环境无 `gh`、无 GitHub token、SSH key 未被授权；
   尚未创建/推送 `metercai/did-sdk`。因此 S1/S3 的 GitHub Actions 尚未实跑。
2. **真实 identity-chain**：无节点与 pallet 元数据；D7 仅完成代码路径与
   `#[ignore]` 测试入口。
3. **发布**：crates.io / PyPI / npm 未发布；需要凭据与包名所有权确认。
4. **musl 静态 / Windows**：本地未安装 zig，按评审结论由 CI runner 验证。

---

## 6. 复现命令

```bash
# Rust
export RUSTUP_HOME="$PWD/.rustup"       # 仅本沙箱；普通开发机不需要
export RUSTUP_TOOLCHAIN=1.88.0
export CARGO_HOME="$PWD/.cargo-home"    # 仅本沙箱
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --exclude did-sdk-python --exclude did-sdk-node

# Python
cd bindings/python
maturin build --release --out dist
python3 -m venv /tmp/didvenv
/tmp/didvenv/bin/pip install dist/*.whl pytest
/tmp/didvenv/bin/python -m pytest tests

# Node
cd bindings/node
npm ci
npx napi build --platform --release
npm test

# 三语言向量
cd ../..
bash scripts/cross-lang-vectors.sh
```
