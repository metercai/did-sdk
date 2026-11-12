# did-sdk 实施步骤文档（评审稿）

| 项目 | 内容 |
|---|---|
| 文档编号 | DID-SDK-PLAN-001 |
| 版本 | v0.1 |
| 日期 | 2026-11-12 |
| 状态 | **已批准并实施完成（2026-11-12）**：D-01～D-18 全部通过；GitHub Actions 5 个 workflow 全绿 |
| 输入规格 | `did-sdk-bootstrap.md`（1800 行，自包含引导规格） |
| 初始化基线 | 本仓库 `main` 分支初始提交（见 §2） |
| 评审入口 | §4 关键决策、§11 确认清单 |

> 阅读顺序建议：先看 §3（架构）与 §4（需要拍板的差异），再看 §5（分阶段步骤）
> 和 §10（风险）。§12–§14 是可直接执行的契约附录。
>
> **评审结论（2026-11-12）**：批准 D-01～D-18；GitHub 仓库维护者/org 为 `metercai`；
> 跨硬件平台编译统一使用 GitHub Actions runner，本地不做交叉编译。

---

## 1. 目标、范围与成功定义

### 1.1 交付目标

在同一仓库内产出三套可发布产物，共享同一套 Rust 核心逻辑：

1. **Rust crate** `did-sdk` + 子 crate `keyvault-core`；
2. **Python wheel** `did-sdk`（PyO3 + maturin）；
3. **Node 原生模块** `@did-sdk/node`（napi-rs，含 TypeScript 类型）。

功能范围：Mock / Centralized / Chain 三种模式、DID key 生成与解析、签名对象构造、
VC / VP、DID-Signature header、Anchor 只读查询、`UserRejected` 三语言透传。

### 1.2 成功定义（以命令为准）

| 编号 | 成功标准 | 验证命令 |
|---|---|---|
| A1 | Rust 核心与 keyvault-core 单测全绿 | `cargo test -p keyvault-core` |
| A2 | 三份集成测试全绿 | `cargo test -p did-sdk` |
| A3 | 格式 / Clippy 零告警 | `cargo fmt --all -- --check`；`cargo clippy ... -D warnings` |
| A4 | Linux musl 完全静态 | `bash scripts/build-rust-musl.sh` 的 `file` 断言 |
| A5 | Python wheel 可安装且向量通过 | `maturin build` + `pytest` |
| A6 | Node addon 可加载且向量通过 | `napi build` + `vitest` |
| A7 | 三语言 golden vector 一致 | `bash scripts/cross-lang-vectors.sh` |
| A8 | 验收清单逐项有证据 | `docs/acceptance-checklist.md` |

### 1.3 非目标（本期不做）

- 浏览器 / WASM 版本（规格明确不提供）。
- `keyvault-device` / `keyvault-server` 的实际实现（只保留 trait、错误变体与 feature 门控）。
- 链上写操作、链账户私钥注入、链节点部署。
- 发布到 crates.io / PyPI / npm（需要凭据与仓库所有权，另立发布任务）。
- 生产级密钥托管、审计、合规认证。
- 真实链的集成验收（缺少链与 pallet 元数据，见 D-14）。

---

## 2. 初始化现状（已完成，可复核）

### 2.1 已建立的仓库骨架

```text
did-sdk/
├── Cargo.toml / rust-toolchain.toml / .gitignore / README.md
├── src/lib.rs                          # 占位
├── keyvault-core/{Cargo.toml,src/lib.rs}
├── bindings/python/{Cargo.toml,pyproject.toml,src/lib.rs,python/did_sdk/__init__.py,tests/}
├── bindings/node/{Cargo.toml,package.json,build.rs,src/lib.rs,__test__/}
├── examples/mini_cli.rs                # 占位
├── tests/{common,vectors,*.rs,vectors/signing_vectors.json}
├── configs/did-sdk.toml.example
├── scripts/{build-rust-musl,build-python,build-node,cross-lang-vectors}.sh
├── .github/workflows/{ci,rust-musl,python,node,cross-lang}.yml
├── docs/acceptance-checklist.md
└── metadata/README.md                  # 说明为何暂不提交 .scale
```

初始化提交点：`git log --oneline -1`（评审时可见）。

### 2.2 工具链基线

| 项 | 初始化环境 | 说明 |
|---|---|---|
| OS | macOS arm64（10 核 / 16 GB） | 本地开发机 |
| Rust | `rustc 1.88.0` | `rust-toolchain.toml` 固定 1.88.0（原因见 D-01） |
| Cargo | 1.88.0 | 使用 `resolver = "3"` |
| Python | 3.12.2 + maturin 1.8.2 | CI 用 3.12 |
| Node | 23.10.0 + npm | CI 用 22 |
| 其他 | 无 `gh`、无 `zig`、无 `cargo-zigbuild` | 见 §2.5 |

### 2.3 依赖解析结果（`Cargo.lock` 已生成并提交）

规格要求 Rust 1.85，但 `subxt 0.50.x` 的 `build.rs` 使用 let-chains（Rust 1.88 才稳定），
且 0.50.3 明确声明 MSRV 1.88；这是规格内部的硬冲突。初始化实测后把 MSRV 提升到
**1.88.0**，并使用 `resolver = "3"`。关键选中版本：

| crate | 版本 | 备注 |
|---|---|---|
| subxt | 0.50.3 | MSRV 1.88，与 D-01 一致 |
| base45 / multibase | 3.2.0 / 0.9.3 | 1.88 下 `as_chunks` 已稳定，不再需要 pin |
| reqwest | 0.12.28 | `default-features=false, rustls-tls` |
| rustls / ring | 0.23.46 / 0.17.14 | ring 为 reqwest TLS 栈的传递依赖（D-04） |
| ed25519-dalek | 3.0.0 | 使用 `from_bytes` + `getrandom 0.4`（D-03） |
| getrandom | 0.4.3 | 直接熵源 |
| pyo3 / pyo3-async-runtimes | 0.23.5 / 0.23.0 | 规格锁定 |
| napi / napi-derive / napi-build | 2.16.17 / 2.16.13 / 2.6.0 | napi 2 系列，规格锁定 |
| tokio / proptest | 1.54.1 / 1.12.0 | |
| rustls-platform-verifier | 0.5.3 | subxt jsonrpsee 的 TLS 验证 |
| 依赖总数 | 513（lock 全量） | 核心构建子集更少 |

### 2.4 已完成的验证

| 检查 | 结果 |
|---|---|
| `git init -b main` | 完成 |
| `cargo generate-lockfile` | 完成（`Cargo.lock`） |
| `cargo check -p did-sdk -p keyvault-core --locked` | **通过**（1.88.0，39.02s） |
| `cargo check -p did-sdk-python -p did-sdk-node --locked` | **通过**（1.88.0，15.28s） |
| `cargo fmt --all -- --check` | 通过 |
| `cargo metadata --no-deps` | 通过；4 个成员，默认仅根 + keyvault-core |
| `maturin build --release`（P4 骨架） | **通过**：`did_sdk-0.1.0-cp312-cp312-macosx_11_0_arm64.whl`，venv 内导入成功 |
| `napi build --platform`（P5 骨架） | **通过**：`did-sdk.darwin-arm64.node`；`require('./index.js').version()` → `0.1.0` |
| 目录树与规格 §1 的差异 | 无（仅增加 `metadata/README.md`、`docs/implementation-plan.md`） |

> 初始化阶段刻意**不写业务代码**：所有 `lib.rs` 只有 crate 文档，所有测试文件只有
> 占位注释，`mini_cli` 只打印占位信息。这样 `cargo check` 验证的是依赖图与工具链，
> 而不是未经评审的实现。

### 2.5 环境限制与应对

| 限制 | 影响 | 应对 |
|---|---|---|
| 沙箱只允许写 workspace | cargo 无法写 `~/.cargo` | 本地命令使用 `CARGO_HOME=$PWD/.cargo-home`（已 gitignore） |
| 沙箱无法写 `~/.rustup` | 不能直接 `rustup toolchain install` | 用 `RUSTUP_HOME=$PWD/.rustup` 把 1.88.0 装进仓库本地（已 gitignore）；普通开发机直接安装即可 |
| 无 `gh` CLI / 无 GitHub 凭据 | 无法创建或推送 GitHub 仓库 | 仅本地 git；远程仓库由用户创建（D-17） |
| 无 zig / cargo-zigbuild | 本地无法交叉构建 Linux musl / Windows | 按评审结论：**跨平台编译只在 GitHub Actions runner 执行**，本地只构建 macOS arm64；S1/S3 标注“CI 验证” |
| cargo 全局配置使用清华 git 镜像，在当前网络 SSL 握手失败 | 依赖拉取失败 | 本地使用 **gitignored** 的 `.cargo/config.toml` 指向 tuna-sparse；或命令追加 `--config`。不写入仓库 |
| 无真实 identity-chain 元数据 | Chain 模式无法真实验收 | 运行时动态查询 + `#[ignore]` 集成测试（D-14） |

---

## 3. 架构与模块边界

### 3.1 crate 依赖图

```text
did-sdk-python ─┐
                ├──> did-sdk ──> keyvault-core
did-sdk-node ───┘
```

- `keyvault-core` 不依赖 `did-sdk`，可单独发布/测试。
- 绑定层只做类型转换与错误映射，**不得**自行拼接签名对象字节。
- `did-sdk` 对 `KeyVault` 只持有 `Arc<dyn KeyVault>`，不关心实现。

### 3.2 运行时对象图

```text
Arc<dyn DidSdk>
  ├── MockDidSdk         { core: SdkCore, anchors, vcs: VcStore, confirm: ConfirmPolicy, handler }
  ├── CentralizedDidSdk  { core: SdkCore, http: reqwest::Client, cache, vcs: VcStore, handler }
  └── ChainModeDidSdk    { core: SdkCore, client: OnceCell<OnlineClient>, cache, vcs: VcStore, handler }

SdkCore { vault: Arc<dyn KeyVault>, config: DidSdkConfig, active_key: RwLock<Option<KeyId>> }
```

`SdkCore` 把“三模式共用的部分”收敛到一处：

- active key 选择；
- DID / did:key 解析；
- DID-Signature header 构造与校验；
- VC 签发、存储、VP 构造；
- 请求确认 handler 调用；
- `KeyVaultError → DidSdkError` 映射。

> 实现上 `SdkCore` 作为 `pub(crate)` 结构，三种模式各持一份；共享逻辑以
> `impl SdkCore` 方法提供，避免复制粘贴。

### 3.3 关键数据流

| 流程 | 步骤 |
|---|---|
| 生成 key | `generate_did_key` → `vault.generate()` → `did:key:z...` → 设为 active key |
| 原始签名 | 策略/确认检查 → `vault.sign(active_key, message)` → `Signature(Vec<u8>)` |
| DID-Signature header | 取 active key/DID → `signing_input::did_signature_v1` → `vault.sign` → 编码 header |
| VC 签发 | 组装 VC → 规范化 JSON → `blake2b256` → `signing_input::issued_vc_v1` → 签名 → proof |
| VP 构造 | handler 确认 → 对每个 VC 取 hash → `signing_input::vp_v1` → 签名 → proof |
| Anchor 查询 | 模式实现 → 缓存（Centralized/Chain）→ `AnchorRecord` |
| 错误透传 | `KeyVaultError::UserRejected` → `map_vault_err` → `DidSdkError::UserRejected` |

### 3.4 存储布局

```text
{DID_SDK_HOME}/
├── identity-keys/
│   ├── index.json                 # 密钥索引（不含私钥）
│   └── keys/
│       └── <blake2b256(key_id)>.kvlt
├── vc_store/
│   └── <blake2b256(anchor_id)>.json
└── keyvault.password              # 自动生成时创建，unix 0600
```

所有写入均为**同目录临时文件 + fsync + rename**；读取时校验版本与完整性。
文件名一律使用哈希，避免 `did:key:...` 中的冒号在 Windows 上非法。

### 3.5 错误映射（唯一路径）

| `KeyVaultError` | `DidSdkError` |
|---|---|
| `KeyNotFound` | `KeyNotFound` |
| `KeyAlreadyExists` | `InvalidArgument("key exists: ...")` |
| `UserRejected` | **`UserRejected`（不允许字符串比较）** |
| `InvalidPassword` / `DecryptionFailed` | `SigningFailed("invalid password" / "decryption failed")` |
| `Locked` | `SigningFailed("keystore locked")` |
| `SigningFailed` | `SigningFailed` |
| `IoError` | `ChainUnavailable`（保持规格映射） |
| `InvalidKeyFormat` / `SerializationError` | `InvalidArgument` |
| `Unsupported` | `Unsupported("keystore operation")` |

绑定层：

| Rust | Python | Node |
|---|---|---|
| `UserRejected` | `UserRejectedError`（`RuntimeError` 子类） | `err.code === "UserRejected"` |
| `VcNotFound` / `AnchorNotFound` | `NotFoundError` | `err.code === "NotFound"` |
| `InvalidArgument` | `ValueError` | `err.code === "InvalidArgument"` |
| 其他 | `DidSdkError` | `err.code === "DidSdkError"` |

### 3.6 三模式语义差异

| 能力 | Mock | Centralized | Chain |
|---|---|---|---|
| key 生成 / 签名 | 本地 vault | 本地 vault | 本地 vault |
| VC 存储 | `VcStore` | `VcStore` | `VcStore` |
| `resolve_did` | 进程内 map | `GET /dids/{did}` | subxt storage |
| `get_anchor` | 预置 map | `GET /anchors/{id}` + TTL | subxt storage + TTL |
| 确认策略 | AutoConfirm/AutoReject/Delay | handler | handler |
| 链账户私钥 | 无 | 无 | **无** |
| 写远端 | 无 | **无（仅 GET）** | **无（只读 storage）** |

---

## 4. 关键决策（评审重点）

以下决策是规格未写死、或按当前生态无法按字面实现的部分。**未获批准前不进入 P0。**

| ID | 规格现状 / 冲突 | 建议决策 | 影响与理由 |
|---|---|---|---|
| **D-01** | 规格要求 **Rust 1.85** + **subxt 0.50**；但 subxt 0.50.x 的 `build.rs` 使用 let-chains（Rust 1.88 才稳定），0.50.3 声明 MSRV 1.88。1.85 下 `cargo check` 直接失败 | **把 MSRV 提升到 1.88.0**；`resolver = "3"`；提交 `Cargo.lock` | 这是当前生态下唯一干净、可维护的方案；不改公开 API。若坚持 1.85，唯一替代是 vendoring subxt 并改其 build.rs（维护成本高、供应链风险大），不推荐 |
| **D-02** | `secrecy = { features = ["zeroize"] }` 在 secrecy 0.10 不存在该 feature（zeroize 是必需依赖） | 改为 `secrecy = "0.10"` | 否则依赖解析直接失败（已实测） |
| **D-03** | 规格 `rand = "0.8"` + `ed25519-dalek 3.0` 的 `rand_core`；但 dalek 3.0 用 rand_core 0.10，rand 0.8 的 `OsRng` 不兼容 | 移除 `rand`；用 `getrandom 0.4` 直接生成 32 字节种子，`SigningKey::from_bytes`；dalek 只开 `fast + zeroize` | 熵源更小、更利于 musl 静态；不改变密钥格式。若坚持 `SigningKey::generate`，需改用 rand 0.10 + `SysRng` |
| **D-04** | 规格“禁止 ring”；但 `reqwest(rustls-tls)` 与 subxt 的 jsonrpsee 必然带入 ring 0.17 | **接受 ring 作为传递依赖**，把 S1 定义为“musl 静态 + `ldd` 无动态依赖”，不把“无 ring”作为验收项 | ring 是纯 Rust + 汇编，无 `-sys`/系统库；aws-lc-rs 需要 cmake/C 工具链，对 musl 交叉更差。禁止 ring 与“用 reqwest”不可兼得 |
| **D-05** | `create_did()` / `issue_self_asserted_vc()` 在 trait 中是**同步**，但内部必须调用异步 `KeyVault::generate/sign` | 改为 `async fn`；Python/Node 暴露为 awaitable | 同步实现只能用 `block_on`，在 Tokio 运行时内会 panic，且绑定层线程不安全。这是规格的内部矛盾，必须改 |
| **D-06** | `build_vp` 需要签名，但 `signing_input` 只定义了 3 个函数，VP 没有规范化输入 | 新增 `signing_input::vp_v1(holder, challenge, domain, vc_hashes)`，并在 golden vector 中锁定 | 不允许在绑定层拼接；新增函数是唯一干净做法。若评审要求严格不加函数，则 VP 只能不带 proof（不可接受） |
| **D-07** | `build_did_signature_header` / `verify_did_signature_header` 的 header 线格式未定义 | 定义为 `DID-Signature-v1.<multibase-base64url(JSON)>`；JSON 字段固定顺序，签名值用 base58 | header 必须无换行、可放 HTTP header；自包含，便于 verify 重建签名输入。见附录 C |
| **D-08** | Mock 结构体有内存 `vcs`，但 `vc_storage_path` 又存在；Centralized/Chain 也需要 VC 存储 | 三种模式统一使用文件型 `VcStore`（原子 JSON）；Mock 可额外预置 VC | 保证 D3“三模式语义一致”，重启后 VC 不丢；Mock 的预置能力不受影响 |
| **D-09** | FileKeystore 只给了格式常量，index / 文件名 / Argon2 参数 / AAD 未定义 | 见附录 C：`index.json` v1；文件名 = blake2b256(key_id) hex；Argon2id m=64MiB,t=3,p=1；AAD=头部 22 字节 | Windows 文件名安全、索引可读、密文绑定头部防篡改 |
| **D-10** | `sign_with_did_key` 没有 key_id 参数，无法确定用哪把 key | `SdkCore` 维护 `active_key`：`generate_did_key` / `create_did` 后设为该 key；无 active 时取 `list_keys()` 第一把；为空则自动生成 | 语义确定、可测试；不扩展 trait。多 key 选择留给后续 `set_active_key`（非本期） |
| **D-11** | 规格 `resolve_config` 在 overrides 之后无条件重算密码，会覆盖 `key_vault_password`；TOML 示例是部分字段但 `DidSdkConfig` 无默认反序列化 | 用 `FileConfig`（全 Option）做部分合并；密码顺序：显式 override > 环境变量 > password_file > 自动生成；补测试 | 这是规格代码中的真实 bug；不修会导致“显式密码无效”和“示例 TOML 解析失败” |
| **D-12** | Python 侧规格建议“PyO3 先抛 RuntimeError，Python 再包装”，但 `DidSdk` 是原生类，无法在 `__init__.py` 包装每个方法；且 `pyproject` 缺 `python-source` | 用 PyO3 `create_exception!` 直接定义 `UserRejectedError` 等异常；`pyproject` 增加 `python-source = "python"` | 异常类型稳定、保留 traceback；否则 `from ._did_sdk import DidSdk` 找不到 Python 源码 |
| **D-13** | napi-rs 的 `err.code` 由 `Status` 决定，无法直接设成 `UserRejected` | 保留原生错误，另加手写 JS loader：捕获后按 reason 前缀设置 `err.code`；`.d.ts` 由 napi 生成并提交 | 满足 `err.code === "UserRejected"` 的三语言契约；原生层仍可独立使用 |
| **D-14** | `chain.rs` 需要 `./metadata/identity_chain.scale`，但仓库没有该链的 pallet/type 定义 | POC 用 subxt 运行时元数据做动态 storage 查询；pallet/entry 名可通过环境变量覆盖；真实链集成测试 `#[ignore]`，S3/D7 标注“需链 fixture” | 不提交错误元数据；Chain 模式可编译、可单测，但不能声称真实链验收通过。若评审能提供元数据，改为静态 metadata |
| **D-15** | `types.rs` 字段未给出；VC/VP 时间格式未定 | 采用附录 A 的字段；VC 使用 W3C 风格的 `issuanceDate`/`expirationDate`（RFC3339）；内部时间戳用 u64 Unix 秒，自实现 UTC 格式化（不引入时间 crate） | 避免 `time`/`chrono` 的 MSRV 风险；字段固定后三语言 JSON 形状一致 |
| **D-16** | 测试需要设环境变量，但 Rust 2024 的 `set_var` 是 `unsafe`，workspace `unsafe_code = "forbid"` | 新增 dev-dependency `temp-env` 做测试内环境隔离；production 代码不设环境变量；测试模块局部 `allow(clippy::unwrap_used/expect_used)` | 否则配置测试无法写；`temp-env` 内部封装 unsafe，业务代码仍保持 forbid |
| **D-17** | 规格要求创建 GitHub 仓库 `did-sdk` | 已创建 `https://github.com/metercai/did-sdk` 并推送 `main`；`origin` 为 HTTPS；5 个 workflow 全绿 | 与规格一致 |
| **D-18** | 规格要求发布三套产物，但未给发布凭据/版本策略 | 本期只做**可重复构建 + 本地安装验证**；发布另立任务，版本从 0.1.0 起 | 避免把“能否 publish”混入代码验收 |

> **批准方式**：回复“D-01…D-18 全部批准”，或逐条给出修改。任何一条被否决，
> 我会先更新本文件与相关契约，再开始对应阶段。

---

## 5. 分阶段实施步骤

### 总体节奏

| 阶段 | 主题 | 预计 | 门禁 |
|---|---|---|---|
| P0 | keyvault-core + 配置骨架 | 1.5 天 | A1/A3 通过 |
| P1 | signing_input + golden vector | 0.5 天 | `cargo test --test vectors` |
| P2 | 三模式 + VC/VP + 集成测试 | 2.5 天 | `cargo test -p did-sdk` |
| P3 | musl 静态 + mini_cli | 1 天 | A4 |
| P4 | Python 绑定 | 1.5 天 | A5 + 向量 |
| P5 | Node 绑定 | 1.5 天 | A6 + 向量 |
| P6 | 三语言 CI + 文档 + 验收 | 1 天 | A7/A8 |

每个阶段结束必须：跑门禁命令 → 更新 `docs/acceptance-checklist.md` 证据 →
`git commit`（提交信息 `P<N>: ...`）→ 才进入下一阶段。

---

### P0 — keyvault-core 与配置骨架

**目标**：K1–K7 全部可测；`did-sdk` 可以 `cargo check`。

**任务**

1. `keyvault-core/src/trait_.rs`
   - `KeyId` / `Signature` / `PublicKey` / `Keypair` / `KeyVaultError` / `KeyVault`；
   - `Keypair` 不实现 `Clone`/`Serialize`；`KeyVaultError::UserRejected` 必须有文档注释。
2. `keyvault-core/src/crypto/`
   - `base58.rs`、`blake2.rs`（Blake2b-256）、`multibase.rs`（`did:key` 0xED01）、
     `ed25519.rs`（`verify` + 测试辅助 `sign_with_seed`）、`sr25519.rs`（`b"substrate"`）。
3. `memory_keystore.rs`：Ed25519 生成/签名/公钥/列举/删除；`Default`。
4. `file_keystore/`
   - `format.rs`：MAGIC `KVLT`、VERSION 1、salt/nonce/tag 长度、`encode/decode`；
   - `index.rs`：`index.json` 读写（原子写）；
   - `password.rs`：`PasswordSource::{Env,File,Direct,AutoGenerate}` 与 `resolve_password`；
   - `mod.rs`：`generate/load/sign/public_key/list_keys/delete` 全实现；
   - 错误密码 → `InvalidPassword`；`FileKeystore` 永不返回 `UserRejected`。
5. `did-sdk/src/error.rs`、`src/config.rs`、`src/lib.rs`
   - `DidSdkError` 全变体；`DidSdk` trait；`SdkCore`；`map_vault_err`；
   - 配置默认值 / 环境变量 / 部分 TOML / overrides / 密码链；
   - `build_vault` / `build_did_sdk`（Mock/Centralized/Chain 构造函数在 P2 补齐，
     P0 可先返回 `Unsupported` 占位并加 `todo!` 注释，**但必须能编译**）。
6. 测试
   - keyvault-core 单测：did:key 往返、签名可验证、错误密码、三种密码来源、
     自动生成 0600（unix）、index 原子写、删除；
   - `tests/config_resolution.rs`：默认值、env 覆盖、显式 override 胜出、
     部分 TOML、密码优先级（用 `temp-env`）。

**验收**

```bash
cargo test -p keyvault-core
cargo check -p did-sdk
cargo fmt --all -- --check
cargo clippy -p keyvault-core -p did-sdk --all-targets -- -D warnings
```

**风险**：Argon2 64MiB 会使每次文件解锁约 100–300ms；P0 单测用 `m=8MiB` 的测试
参数需通过构造器注入，生产默认仍为 64MiB（附录 C）。Windows 上文件权限测试
用 `#[cfg(unix)]` 跳过。

---

### P1 — 签名对象与 golden vector

**目标**：K8 锁定；为 P4/P5 提供唯一事实源。

**任务**

1. `keyvault-core/src/signing_input.rs`
   - 规格 3 个函数逐字节实现；
   - D-06 的 `vp_v1`；
   - 所有函数只返回 `Vec<u8>`，不做 I/O。
2. `tests/vectors/signing_vectors.json`
   - 保留 `did_signature_v1`；
   - 用 Rust 参考实现生成 `fixed_seed_signature[0].expected_signature_hex`；
   - 增加 `vp_v1` 用例与 `issued_vc_v1` 用例（同样由 Rust 生成期望值）。
3. `tests/vectors.rs`
   - 读取 JSON，断言 `did_signature_v1` 的 UTF-8 字节完全相等（含无尾随换行）；
   - 固定 seed 签名 hex 完全相等；
   - `issued_vc_v1` / `vp_v1` 字节完全相等。

**验收**

```bash
cargo test --test vectors
cargo test -p keyvault-core
```

**生成期望值的方式**：在 `tests/vectors.rs` 放一个 `#[ignore] print_golden_vector`
测试，输出 JSON 片段，人工粘贴回 `signing_vectors.json` 后再跑非 ignore 测试。
**禁止**让测试在运行时写 JSON（会导致“永远通过”）。

---

### P2 — 三模式 + VC/VP + 集成测试

**目标**：D1–D11 的主干全部可测；Chain 只做到“可编译 + 可单测 + 真实链测试 ignore”。

**任务顺序（每步可独立提交）**

1. **types.rs / error.rs / lib.rs**：附录 A 的类型；trait 全方法；`SdkCore` 共享方法。
2. **vc.rs**：`VcStore`（原子 JSON、list/remove）、`issue_self_asserted_vc`、
   `build_vp`、`verify_vc`（内部）、RFC3339 格式化。
3. **did_signature.rs**：header 编解码、签名、验签、`UserRejected` 透传。
4. **server_request.rs**：`ServerRequestHandler` trait + 三个 context + `AutoConfirmHandler`。
5. **mock.rs**：`ConfirmPolicy`、预置 anchor、`with_*` 构造器、完整 trait 实现。
6. **centralized.rs**：reqwest Client（超时）、`GET /anchors/{id}` / `GET /dids/{did}`、
   TTL 缓存（`Instant`）、404/网络错误映射。
7. **chain.rs**：subxt `OnlineClient` 懒连接、动态 storage 查询、缓存、忽略测试。
8. **配置与错误测试**：
   - `tests/config_resolution.rs` 补齐 5 条以上；
   - `tests/user_rejected.rs` 两条（Mock AutoReject、自定义 vault 返回 UserRejected）；
   - `tests/centralized_contract.rs`：wiremock 只挂两个 GET；断言
     `received_requests()` 全部是 GET；404 → `AnchorNotFound` / `resolve_did` 返回 `None`；
     缓存命中后请求数不增加；
   - `tests/consistency.rs`：Mock 与 Centralized（wiremock）跑同一组断言
     （生成 key → 签名 → header 往返 → VC issue/store/get/list/remove → VP）；
   - Chain 测试 `#[ignore]`，入口用 `DID_SDK_CHAIN_ENDPOINT`。

**关键语义**

- Mock `AutoReject` 必须在 `vault.sign` **之前**返回 `DidSdkError::UserRejected`；
- `Delay(ms)` sleep 后按自动确认处理；
- 自定义 KeyVault 的 `UserRejected` 必须经 `map_vault_err` 透传；
- Centralized 的写操作只能是本地（VC store / 签名），绝不发 POST/PUT/DELETE；
- Chain 构造 `OnlineClient` 时不注入 signer；只读 storage。

**验收**

```bash
cargo test -p did-sdk
cargo test --test config_resolution --test user_rejected --test consistency --test centralized_contract
cargo clippy --workspace --exclude did-sdk-python --exclude did-sdk-node --all-targets -- -D warnings
```

**风险**：wiremock 0.6 与 reqwest 0.12 的异步测试 API；`get_anchor` 的 TTL 缓存
需要可注入时钟（测试用 `tokio::time::pause/advance` 或 0 TTL）。计划在
`CentralizedDidSdk` 内部用 `Instant`，测试用 `cache_ttl_secs = 0` 强制过期，
避免引入 mock 时钟。

---

### P3 — musl 静态链接与 mini_cli

**目标**：S1 由 CI 验证；本地只验证 macOS arm64 原生构建。

**任务**

1. `examples/mini_cli.rs` 接入真实 API：`resolve_config(Default)` → `build_did_sdk`
   → `generate_did_key` → `sign_with_did_key` → 打印 DID 与签名长度。
2. 本地：`cargo build --release --example mini_cli`（aarch64-apple-darwin），
   运行二进制确认免配置可用。
3. **不在本地安装 zig / cargo-zigbuild**。推送到 GitHub 后由
   `.github/workflows/rust-musl.yml` 的四个 runner 完成：
   - Linux musl x64/arm64：`cargo zigbuild` + `file`/`ldd` 静态断言；
   - macOS arm64 / Windows x64：原生构建。
4. CI 若发现静态链接失败，按 R2 处理；**不允许**用动态链接产物冒充静态通过。

**验收**

```bash
# 本地
cargo build --release --example mini_cli -p did-sdk
./target/release/examples/mini_cli

# CI
gh run watch   # 或 GitHub Actions 页面；rust-musl.yml 四平台全绿
```

---

### P4 — Python 绑定

**目标**：A5；Python 侧可 `pip install`、可 await、异常类型稳定、向量通过。

**任务**

1. `bindings/python/src/lib.rs`
   - `#[pyclass] DidSdk`：构造函数解析 `**overrides`（snake_case，符合规格）；
   - 全方法映射（async → `pyo3_async_runtimes::tokio::future_into_py`）；
   - 静态纯函数：`did_signature_v1_bytes`、`issued_vc_v1_bytes`、`vp_v1_bytes`、
     `ed25519_sign_with_seed`（测试向量用）；
   - `resolved_config()` 返回 dict；
   - 异常：`DidSdkError`、`UserRejectedError`、`NotFoundError`、`InvalidArgumentError`；
   - `to_pyerr` 统一映射（用户拒绝 → `UserRejectedError("UserRejected")`）。
2. `python/did_sdk/__init__.py`：从 `._did_sdk` 导入类与异常，`__all__` 完整。
3. `python/did_sdk/_did_sdk.pyi`：类、异步方法、静态方法、异常签名。
4. `tests/test_vectors.py`：读取共享 JSON；`UserRejected` / 配置 / 异步 smoke。
5. 构建与安装验证（venv，避免污染系统 Python）：
   `maturin build --release --out dist` → `pip install dist/*.whl` → `pytest`。

**验收**

```bash
cd bindings/python
maturin build --release --out dist
python3 -m venv .venv && .venv/bin/pip install dist/*.whl pytest
.venv/bin/python -m pytest tests
```

**风险**：`pyo3-async-runtimes 0.23` 的 Tokio runtime 初始化方式；若 `future_into_py`
找不到 runtime，则在模块初始化时用 `OnceLock<Runtime>` + `Handle` 显式驱动。
Python 3.9 的 typing 语法（`list[str]` 在 3.9 可用；`X | None` 需 3.10，pyi 中用
`Optional`）。

---

### P5 — Node 绑定

**目标**：A6；`require("@did-sdk/node")` 可用、TS 类型完整、`err.code` 正确。

**任务**

1. `bindings/node/src/lib.rs`
   - `JsConfigOverrides`（camelCase → Rust snake_case 显式映射）；
   - `DidSdk` 类：构造、全异步方法、静态纯函数、
     `didSignatureV1Bytes` / `issuedVcV1Bytes` / `vpV1Bytes` / `ed25519SignWithSeed`；
   - 时间戳用 `u32`（POC，2106 年前安全），Rust 侧转 `u64`；
   - Buffer 返回签名/字节；
   - 错误：原生 `napi::Error` 带 `code:` 前缀 reason。
2. `bindings/node/index.js`（手写 loader）
   - 加载 napi 生成的 `.node`；
   - 包装 `DidSdk` 方法：捕获错误，按 reason 前缀设置 `err.code`
     （`UserRejected` / `NotFound` / `InvalidArgument` / `DidSdkError`）；
   - 导出 `DidSdk` 与纯函数。
3. `.d.ts`：`napi build` 生成后提交；CI 校验未过期（构建后 `git diff --exit-code`）。
4. `__test__/vectors.test.ts`：共享 JSON 向量、配置、异步、`err.code` 断言。

**验收**

```bash
cd bindings/node
npm install
npx napi build --platform --release
npm test
```

**风险**：napi-rs 2 的自定义 `code` 不可直接设置（D-13 的 JS 包装）；
napi-build 2.2.4 受 MSRV 限制，升级需先升 Rust。Node 22/23 ABI 兼容性在 CI 验证。

---

### P6 — 三语言 CI、文档与验收

**目标**：A7/A8；仓库可交接。

**任务**

1. `scripts/cross-lang-vectors.sh` 跑通（Rust/Python/Node 都读同一 JSON）。
2. GitHub Actions：
   - `ci.yml`（fmt/clippy/test）；
   - `rust-musl.yml`（四平台 + 静态断言）；
   - `python.yml`（5 平台 wheel）；
   - `node.yml`（5 平台 addon）；
   - `cross-lang.yml`（三语言向量）。
3. README 定稿：安装、免配置示例、环境变量、模式、平台矩阵、
   `UserRejected` 三语言语义、未来扩展、无 WASM。
4. `docs/acceptance-checklist.md` 逐项打勾并记录命令输出摘要。
5. `git tag v0.1.0`（可选，评审后定）。

**验收**

```bash
bash scripts/cross-lang-vectors.sh
# 以及在 GitHub 上跑通 5 个 workflow
```

**外部依赖**：GitHub 远程仓库与 Actions 需要用户创建/推送（D-17）。本地只能验证
workflow 语法与脚本逻辑，不能替代 CI 实跑。

---

## 6. 测试矩阵

| 测试文件 | 阶段 | 覆盖 | 命令 |
|---|---|---|---|
| keyvault-core 单测 | P0 | trait、did:key、签名、错误密码、密码来源、原子写 | `cargo test -p keyvault-core` |
| `tests/config_resolution.rs` | P0/P2 | 默认值、env、TOML、overrides、密码优先级 | `cargo test --test config_resolution` |
| `tests/vectors.rs` | P1 | 三个签名输入 + VP 的逐字节向量 | `cargo test --test vectors` |
| `tests/user_rejected.rs` | P2 | Mock AutoReject、vault UserRejected、handler 拒绝 | `cargo test --test user_rejected` |
| `tests/centralized_contract.rs` | P2 | 仅 GET、404、缓存命中 | `cargo test --test centralized_contract` |
| `tests/consistency.rs` | P2 | Mock vs Centralized 同一断言；Chain `#[ignore]` | `cargo test --test consistency` |
| Python `tests/` | P4 | 向量、异步、异常、配置 | `pytest bindings/python/tests` |
| Node `__test__/` | P5 | 向量、异步、`err.code`、配置 | `npm test` |
| musl 静态 | P3 | `file` / `ldd` | `scripts/build-rust-musl.sh` |

### 向量覆盖（`tests/vectors/signing_vectors.json`）

| key | 内容 | 用途 |
|---|---|---|
| `did_signature_v1` | 文本输入 + 期望 UTF-8 字节 | 三语言逐字节一致 |
| `issued_vc_v1` | VC 输入 + 期望字节 | P1/P4/P5 |
| `vp_v1` | holder/challenge/domain/vc hashes + 期望字节 | P1/P4/P5 |
| `fixed_seed_signature` | 固定 seed + payload + 期望签名 hex | Ed25519 确定性签名；Rust + 绑定测试辅助函数 |

---

## 7. CI 与构建矩阵

| workflow | 平台 | 产物 | 关键断言 |
|---|---|---|---|
| `ci.yml` | ubuntu | — | fmt / clippy -D warnings / test |
| `rust-musl.yml` | ubuntu ×2、macos-15、windows | `mini_cli` | musl `file` = statically linked（macOS 14 于 2026-10 退役） |
| `python.yml` | ubuntu gnu/musl ×2、macos-15、windows | `.whl` | 5 平台 wheel |
| `node.yml` | ubuntu gnu/musl ×2、macos-15、windows | `.node` | 5 平台 addon |
| `cross-lang.yml` | ubuntu | — | 三语言读同一向量 JSON |

发布（crates.io / PyPI / npm）不在本期；P6 只保证构建可重复与本地安装可验证。

---

## 8. 安全与威胁模型

| 威胁 | 对策 |
|---|---|
| 私钥被业务层读出 | `KeyVault` 无导出方法；`Keypair` 不 `Serialize`/`Clone`；绑定层不暴露 key 对象 |
| 密钥文件被离线读取 | Argon2id + ChaCha20-Poly1305；每文件独立 salt/nonce；AAD 绑定头部 |
| 密码泄漏到日志 | 只用 `SecretString`；不 `Debug` 打印密码；错误信息不含密码 |
| 密码文件权限 | Unix `0600`（`OpenOptions::mode` + `set_permissions` 兜底）；Windows 仅创建 |
| 进程崩溃导致半写文件 | 同目录 tmp + fsync + rename；index 与 key 文件都原子写 |
| 用户误签 | `ServerRequestHandler` 三处确认；Mock AutoReject；未来设备安全区返回 `UserRejected` |
| 链账户私钥泄漏 | Chain 模式不注入 signer，只读 storage |
| TLS 降级 | 仅 `rustls-tls`；禁止 native-tls/OpenSSL；CI 检查依赖树（可选 `cargo tree -i openssl` 为空） |
| 绑定层误解拒绝 | 统一 `UserRejected` 映射；禁止字符串比较 |

**残留风险（POC 接受）**：自动生成密码与密钥同目录；内存中解锁的私钥在进程生命周期内
存在；无硬件隔离；无速率限制/审计。生产化由 `keyvault-device`/`keyvault-server` 解决。

---

## 9. 依赖约束与平台说明

| 依赖 | 用途 | 静态/平台注意 |
|---|---|---|
| `reqwest(rustls-tls)` | Centralized HTTP | 禁止 native-tls；ring 传递依赖（D-04） |
| `subxt 0.50.2` | Chain 只读 | jsonrpsee + rustls-platform-verifier；不启用 light-client |
| `ed25519-dalek 3` | 签名/验签 | 纯 Rust；`fast + zeroize` |
| `schnorrkel 0.11` | sr25519 验签 | 纯 Rust；`b"substrate"` 上下文 |
| `chacha20poly1305` / `argon2` | 文件加密 | 纯 Rust |
| `getrandom 0.4` | 熵源 | musl 下直接 syscall |
| `tokio` | 异步运行时 | multi-thread + fs |
| `pyo3 0.23` / `napi 2` | 绑定 | 不追求静态；musl 下 `-crt-static` 由 maturin/napi 处理 |

**禁止**：`openssl`、`native-tls`、任何无 bundled 的 `*-sys` crate。
**例外**：ring（reqwest/subxt 传递依赖，D-04）。

---

## 10. 风险登记

| ID | 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|---|
| R1 | 依赖 MSRV 继续漂移，固定工具链无法编译 | 中 | 高 | resolver 3 + 提交 lock；CI 固定 1.88；已发现 subxt 0.50 与 1.85 硬冲突（D-01） |
| R2 | subxt + ring 在 musl 静态链接失败 | 中 | 高 | P3 最早验证；失败则 feature-gate Chain 或换 TLS 后端，需评审 |
| R3 | Chain 无真实元数据，D7 无法验收 | 高 | 中 | D-14 明确范围；动态查询 + ignore 测试；提供 metadata 后补 |
| R4 | pyo3-async-runtimes runtime 初始化失败 | 中 | 中 | P4 第一天做最小 async smoke；`OnceLock<Runtime>` 兜底 |
| R5 | napi 自定义 `err.code` 实现复杂 | 中 | 中 | D-13 JS loader；保底 `err.message` 前缀 + `isUserRejected()` |
| R6 | Windows 文件权限/路径不可用 | 低 | 中 | 哈希文件名；`#[cfg(unix)]` 权限测试；CI windows 实跑 |
| R7 | Argon2 64MiB 使测试/解锁慢 | 中 | 低 | 测试构造器注入低参数；生产默认不变 |
| R8 | 环境变量测试相互污染 | 高 | 中 | `temp-env` + `serial_test`；每个用例独立 HOME |
| R9 | 无 gh / 无远程，CI 不能实跑 | 高 | 中 | D-17；本地脚本 + workflow 语法校验；用户推送后补跑 |
| R10 | 工期估计偏乐观（尤其 P2/P5） | 中 | 中 | 每阶段可独立交付；优先保证 P0–P3 核心链路 |

---

## 11. 评审确认清单

请逐项确认（回复“批准”或给出修改）：

- [x] **D-01** MSRV 1.88 + resolver 3 + lockfile（subxt 0.50 需要 1.88）
- [x] **D-02** `secrecy` 去掉不存在的 `zeroize` feature
- [x] **D-03** 用 `getrandom 0.4` 替代 `rand 0.8` + dalek `rand_core`
- [x] **D-04** 接受 ring 作为 reqwest/subxt 传递依赖，S1 只验证静态
- [x] **D-05** `create_did` / `issue_self_asserted_vc` 改为 async
- [x] **D-06** 新增 `vp_v1` 签名输入并纳入 golden vector
- [x] **D-07** DID-Signature header 线格式（multibase base64url JSON）
- [x] **D-08** 三模式统一文件型 `VcStore`
- [x] **D-09** FileKeystore index / 文件名 / Argon2 参数 / AAD
- [x] **D-10** active key 选择规则
- [x] **D-11** 配置部分合并 + 密码优先级修复
- [x] **D-12** Python `create_exception!` + `python-source`
- [x] **D-13** Node JS loader 设置 `err.code`
- [x] **D-14** Chain 动态元数据 + `#[ignore]`，不提交 `.scale`
- [x] **D-15** 附录 A 的类型字段与 RFC3339 时间
- [x] **D-16** `temp-env` 做环境变量测试隔离
- [x] **D-17** `metercai/did-sdk` 已创建并推送，CI 全绿
- [x] **D-18** 本期不 publish，只做构建/安装验证

**其他需要确认的问题**

1. 是否接受总工期约 **9.5 个工作日**？有无优先阶段（例如必须先出 Python）？
2. Chain 模式是否接受“编译 + 单测 + ignore 集成测试”的 POC 范围？
3. 是否有真实 `identity_chain` 的 pallet / 存储项 / 元数据可以提供？
4. ~~`repository` 的 GitHub org 是否为 `metercai`？~~ 已确认。
5. 是否需要 Apache-2.0 `LICENSE` 文件？（当前 README 引用但文件未创建）

**评审结论（2026-11-12）**：已批准。实施按 P0 → P6 推进，每阶段一个 commit，
并汇报门禁命令输出与验收清单更新。跨平台编译由 GitHub Actions 完成。

---

## 12. 附录 A：公开类型契约（建议）

```rust
// src/types.rs

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningContext {
    pub purpose: String,
    pub payload_summary: String,
    pub requestor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Signature(pub Vec<u8>);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Ed25519PublicKey(pub [u8; 32]);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AddressStatus {
    Active,
    Revoked,
    Expired,
    Pending,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    Valid,
    Invalid,
    Revoked,
    Expired,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidRecord {
    pub did: String,
    pub public_key: Ed25519PublicKey,
    pub created_at: u64,
    pub updated_at: u64,
    pub anchor_id: Option<String>,
    pub status: AddressStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyResult {
    pub valid: bool,
    pub integrity: IntegrityStatus,
    pub did: Option<String>,
    pub timestamp: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VcProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<VcProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub holder: String,
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,
    pub challenge: String,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<VcProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorRecord {
    pub anchor_id: String,
    pub did: String,
    pub status: AddressStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssueAuthorizationSignature {
    pub issuer_did: String,
    pub subject_did: String,
    pub vc_type: String,
    pub vc_hash: String,
    pub timestamp: u64,
    /// base58btc 编码的 Ed25519 签名
    pub signature: String,
}
```

`server_request.rs`：

```rust
#[derive(Debug, Clone)]
pub struct ChallengeContext {
    pub did: String,
    pub from: String,
    pub anchor_id: String,
    pub body_hash: String,
    pub rcpt_hash: String,
}

#[derive(Debug, Clone)]
pub struct VpRequestContext {
    pub holder: String,
    pub challenge: String,
    pub domain: String,
    pub vc_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationRequestContext {
    pub subject_did: String,
    pub vc_type: String,
    pub vc_hash: String,
    pub timestamp: u64,
}

#[async_trait]
pub trait ServerRequestHandler: Send + Sync {
    async fn on_challenge(&self, ctx: &ChallengeContext) -> Result<(), DidSdkError>;
    async fn on_vp_request(&self, ctx: &VpRequestContext) -> Result<(), DidSdkError>;
    async fn on_authorization_request(
        &self,
        ctx: &AuthorizationRequestContext,
    ) -> Result<(), DidSdkError>;
}

/// POC 默认实现：总是确认。应用可替换为 UI/生物识别/设备安全区。
pub struct AutoConfirmHandler;
```

---

## 13. 附录 B：配置解析算法（伪代码）

```text
resolve_config(overrides):
  cfg = DidSdkConfig::default()          # mode=mock, file-keystore, home=...
  file = load_partial_toml()             # FileConfig { all Option }
  merge(file, cfg)                       # 只覆盖出现的字段；key_vault 逐字段合并
  apply_env(cfg)                         # DID_SDK_*（不含密码值）
  apply_overrides(cfg, overrides)        # 显式参数；key_vault_password 写入 resolved_password
  if cfg.resolved_password is None:
      cfg.resolved_password = resolve_password(cfg.key_vault)
  return cfg

resolve_password(kv):
  if explicit override password: return it                 # 已在 apply_overrides 设置
  if env(kv.password_env) exists: return SecretString(env) # 最高环境优先
  if kv.password_file exists: return read_trim(file)
  if kv.allow_auto_generate_password:
      return auto_generate_atomic_0600(kv.password_file)   # 已存在则读取，不覆盖
  return ConfigError("keystore password unavailable")
```

**测试矩阵**：默认 / 仅 env / 仅文件 / 仅 override / env+override / 文件+env /
自动生成 / 禁止自动生成时报错 / 部分 TOML / 非法 TOML。全部用 `temp-env` 隔离。

---

## 14. 附录 C：文件格式

### C.1 KVLT 密钥文件

```text
偏移   长度   字段
0      4      magic = "KVLT"
4      1      version = 0x01
5      1      key_type (0x01 Ed25519, 0x02 Sr25519)
6      16     salt (Argon2id)
22     12     nonce (ChaCha20-Poly1305)
34     *      ciphertext
末尾   16     tag
```

- AAD = 前 22 字节（magic|version|key_type|salt）；
- 明文 = 32 字节 Ed25519 seed，或 64 字节 sr25519 secret；
- Argon2id：m=65536 KiB、t=3、p=1、输出 32 字节；salt 16 字节；
- 文件名为 `blake2b256(key_id)` 的小写 hex + `.kvlt`。

### C.2 `index.json`

```json
{
  "version": 1,
  "keys": [
    {
      "key_id": "did:key:z6Mk...",
      "key_type": 1,
      "file": "<64 hex>.kvlt",
      "created_at": 1700000000
    }
  ]
}
```

读取时校验 `version == 1`、`file` 只含 `[0-9a-f]{64}.kvlt`（防目录穿越）。
写入用 tmp + fsync + rename。

### C.3 VC 存储文件

`vc_store/<blake2b256(anchor_id)>.json`，内容为 `VerifiableCredential` 的 JSON；
`list_vcs` 扫描目录并解析，损坏文件记录 `warn` 并跳过（不阻塞其他 VC）。

### C.4 DID-Signature header

```text
DID-Signature-v1.<multibase(base64url, canonical_json)>
```

`canonical_json` 字段顺序固定：

```json
{"v":1,"did":"did:key:z...","from":"alice@example.com","timestamp":1700000000,
 "anchor_ref":"anchor:abc","body_hash":"blake2b:1111","rcpt_hash":"blake2b:2222",
 "sig":"<base58>"}
```

签名输入仍是 `signing_input::did_signature_v1(...)` 的 7 行文本；
`sig` 不参与签名输入。`verify` 解析后校验 `from`、`body_hash`、`rcpt_hash`
与调用参数一致，再验签。

---

## 15. 附录 D：常用命令与环境

```bash
# 本机（沙箱）通用前缀
export RUSTUP_HOME="$PWD/.rustup"
export RUSTUP_TOOLCHAIN=1.88.0
export CARGO_HOME="$PWD/.cargo-home"
# 依赖镜像已放在 gitignored 的 .cargo/config.toml；因此不需要额外 --config

cargo check --locked -p did-sdk -p keyvault-core
cargo test -p keyvault-core
cargo test -p did-sdk

# 三套产物
bash scripts/build-rust-musl.sh
bash scripts/build-python.sh
bash scripts/build-node.sh
bash scripts/cross-lang-vectors.sh
```

CI 不使用上述本地变量；workflow 直接使用 crates.io 与固定工具链。

---

## 16. 变更控制

1. **评审前**：只允许修改文档与初始化骨架，不写业务实现。
2. **评审后**：按 P0→P6 顺序推进；每个阶段一个 commit，commit message 以 `P<N>:` 开头。
3. **任何新增依赖 / 公开 API 变更 / 与规格不一致的实现**：先在本文件 §4 增加决策条目，
   获确认后再写代码；不得“先实现后解释”。
4. **阶段门禁失败**：不进入下一阶段；在 `docs/acceptance-checklist.md` 记录失败命令与原因。
5. **外部依赖阻塞**（GitHub / zig / 链元数据）：记录为“未验证”，不得标记为通过。

---

*本文档为评审稿。评审通过后，P0 的第一条 commit 会引用本文件版本号。*
