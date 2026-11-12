# did-sdk 验收清单

> 状态：初始化完成，实施待评审。每个阶段完成后更新本文件，记录**命令 + 输出摘要**，
> 不允许只打勾不记录证据。
>
> 关联文档：[`docs/implementation-plan.md`](implementation-plan.md)

## 0. 初始化基线

| 项 | 状态 | 证据 |
|---|---|---|
| 目录树与规格 §1 一致 | ✅ | `tree` / git 初始提交 |
| workspace 可解析（4 成员，默认 2） | ✅ | `cargo metadata --no-deps` |
| 工具链 1.88.0（D-01） | ✅ | `rust-toolchain.toml` + 本地 `.rustup` |
| `Cargo.lock` 生成（resolver 3） | ✅ | `Cargo.lock` |
| 依赖解析（subxt 0.50.2 等） | ✅ | plan §2.3 |
| 核心依赖编译 | ✅ | `cargo check -p did-sdk -p keyvault-core --locked` → Finished 39.02s（1.88.0） |
| Python/Node 绑定骨架编译 | ✅ | `cargo check -p did-sdk-python -p did-sdk-node --locked` → Finished 15.28s |
| 业务实现 | ⬜ | 按 P0–P6 |

## 1. keyvault-core（K1–K7）

| 编号 | 验收项 | 状态 | 验证命令 | 证据摘要 |
|---|---|---|---|---|
| K1 | KeyVault trait 完整（含 `UserRejected`） | ⬜ | `cargo check -p keyvault-core` | |
| K2 | FileKeystore 生成 / 加密落盘 | ⬜ | `cargo test -p keyvault-core` | |
| K3 | 错误密码被拒绝 | ⬜ | 同上 | |
| K4 | 签名可验证（Ed25519 / Sr25519） | ⬜ | 同上 | |
| K5 | 私钥不出 KeyVault（`Keypair` 不 Serialize/Clone） | ⬜ | 代码审查 | |
| K6 | 三种密码来源 + 自动生成 0600 | ⬜ | 同上 | |
| K7 | did:key 编解码（0xED01 + base58btc） | ⬜ | 同上 | |

## 2. did-sdk 核心（D1–D11）

| 编号 | 验收项 | 状态 | 验证命令 | 证据摘要 |
|---|---|---|---|---|
| D1 | `DidSdk` 接口契约完整 | ⬜ | `cargo check -p did-sdk` | |
| D2 | 三模式配置切换（默认/环境/覆盖/TOML） | ⬜ | `cargo test --test config_resolution` | |
| D3 | 三模式语义一致 | ⬜ | `cargo test --test consistency` | |
| D4 | Mock 自动确认 / 自动拒绝 | ⬜ | `cargo test --test user_rejected` | |
| D5 | Mock 签名延迟 | ⬜ | `cargo test -p did-sdk` | |
| D6 | Centralized 只读（仅 GET） | ⬜ | `cargo test --test centralized_contract` | |
| D7 | Chain 只读 storage，不注入 signer | ⬜ | `#[ignore]` 集成测试 / 代码审查 | |
| D8 | did:key 私钥安全 | ⬜ | 代码审查 | |
| D9 | 零链账户私钥 | ⬜ | 代码审查 | |
| D10 | keyvault-core 集成（build_vault） | ⬜ | `cargo test` | |
| D11 | 一致性测试 | ⬜ | `cargo test --test consistency` | |

## 3. 发布形态（S1–S3）

| 编号 | 验收项 | 状态 | 验证命令 | 证据摘要 |
|---|---|---|---|---|
| S1 | Linux musl 完全静态、零运行时依赖 | ⬜ | `bash scripts/build-rust-musl.sh` | |
| S2 | `UserRejected` 三语言透传 | ⬜ | Rust/Python/Node 测试 | |
| S3 | 四平台构建矩阵 | ⬜ | GitHub Actions `rust-musl.yml` | |

## 4. 绑定

| 项 | 状态 | 验证命令 | 证据摘要 |
|---|---|---|---|
| Python wheel 构建（初始化骨架） | ✅ | 本地 `maturin build --release` → cp312 macOS arm64 wheel，venv 导入成功 |
| Python wheel 完整 API | ⬜ | P4 | |
| Python pytest（golden vector + 异常） | ⬜ | `pytest bindings/python/tests` | |
| Node addon 构建（初始化骨架） | ✅ | `npx napi build --platform` → darwin-arm64 `.node`，`version()` 可调用 |
| Node addon 完整 API | ⬜ | P5 | |
| Node vitest（golden vector + `err.code`） | ⬜ | `npm test` | |
| `.d.ts` 已提交且未过期 | ⬜ | `git diff --exit-code bindings/node/index.d.ts` | |
| 三语言向量一致 | ⬜ | `bash scripts/cross-lang-vectors.sh` | |

## 5. 文档

| 项 | 状态 | 证据 |
|---|---|---|
| README 安装 / 快速开始 / 环境变量 / 平台矩阵 / UserRejected / 未来扩展 / 无 WASM | ⬜ | `README.md` |
| 实施计划评审通过 | ⬜ | `docs/implementation-plan.md` §11 |
| 验收清单逐项有命令输出摘要 | ⬜ | 本文件 |
| LICENSE 文件 | ⬜ | `LICENSE`（Apache-2.0） |

## 6. 已知未验证项（需外部条件）

| 项 | 原因 | 解除条件 |
|---|---|---|
| D7 真实链接入 | 无 identity-chain 节点与 pallet 元数据 | 提供元数据 / 节点后跑 `#[ignore]` 测试 |
| S3 GitHub Actions 实跑 | 无远程仓库 | 用户创建并推送 `did-sdk` |
| musl 本地交叉构建 | 初始化环境无 zig | P3 安装；否则以 CI 为准 |
| crates.io / PyPI / npm 发布 | 无凭据 | 另立发布任务 |
