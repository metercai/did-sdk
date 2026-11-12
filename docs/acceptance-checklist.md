# did-sdk 验收清单

> 状态：实现与本地测试完成（2026-11-12）；跨平台 CI 与真实链接入待外部条件。
> 每个阶段完成后更新本文件，记录**命令 + 输出摘要**；不允许只打勾不记录证据。
>
> 关联文档：[`docs/implementation-plan.md`](implementation-plan.md) ·
> [`docs/implementation-report.md`](implementation-report.md)

## 0. 初始化基线

| 项 | 状态 | 证据 |
|---|---|---|
| 目录树与规格 §1 一致 | ✅ | 初始提交 `1b38cc0` |
| workspace 可解析（4 成员，默认 2） | ✅ | `cargo metadata --no-deps` |
| 工具链 1.88.0（D-01） | ✅ | `rust-toolchain.toml` + CI `dtolnay/rust-toolchain@1.88.0` |
| `Cargo.lock` 提交（resolver 3） | ✅ | `Cargo.lock` |
| 核心依赖编译 | ✅ | `cargo check -p did-sdk -p keyvault-core` → Finished |
| Python/Node 绑定编译 | ✅ | `cargo check -p did-sdk-python -p did-sdk-node` → Finished |
| 业务实现 | ✅ | P0–P5；见下 |

## 1. keyvault-core（K1–K7）

| 编号 | 验收项 | 状态 | 验证命令 | 证据摘要 |
|---|---|---|---|---|
| K1 | KeyVault trait 完整（含 `UserRejected`） | ✅ | `cargo check -p keyvault-core` | 通过 |
| K2 | FileKeystore 生成 / 加密落盘 | ✅ | `cargo test -p keyvault-core` | 12 个集成测试 + 6 个单测（含 proptest）全绿 |
| K3 | 错误密码被拒绝 | ✅ | `cargo test -p keyvault-core --test keystore` | `Err(InvalidPassword)` |
| K4 | 签名可验证（Ed25519 / Sr25519） | ✅ | 同上 | Ed25519 往返 + sr25519 verify 测试 |
| K5 | 私钥不出 KeyVault | ✅ | 代码审查 | `Keypair` 无 `Serialize`/`Clone`/`Debug`；trait 无导出方法 |
| K6 | 三种密码来源 + 自动生成 0600 | ✅ | `cargo test -p keyvault-core` | Env / File / Direct / AutoGenerate；unix 权限断言 |
| K7 | did:key 编解码（0xED01 + base58btc） | ✅ | `cargo test -p keyvault-core` | `did:key:z...` 往返；非法前缀拒绝 |

## 2. did-sdk 核心（D1–D11）

| 编号 | 验收项 | 状态 | 验证命令 | 证据摘要 |
|---|---|---|---|---|
| D1 | `DidSdk` 接口契约完整 | ✅ | `cargo check -p did-sdk` | 全方法实现 |
| D2 | 三模式配置切换（默认/环境/覆盖/TOML） | ✅ | `cargo test --test config_resolution` | 13 passed（默认/env/覆盖/部分 TOML/密码优先级/错误 TOML/空密码/禁用自动生成） |
| D3 | 三模式语义一致 | ✅ | `cargo test --test consistency` | 4 passed + 1 ignored（Mock/Centralized/Chain 本地流程；header 篡改/删除不存在 VC 等） |
| D4 | Mock 自动确认 / 自动拒绝 | ✅ | `cargo test --test user_rejected` | 6 passed（AutoReject 全签名路径、vault UserRejected、handler、delay） |
| D5 | Mock 签名延迟 | ✅ | 同上 | `with_signing_delay(1)` 签名成功 |
| D6 | Centralized 只读（仅 GET） | ✅ | `cargo test --test centralized_contract` | 7 passed；`received_requests` 全部 GET；缓存命中/TTL=0/500 错误 |
| D7 | Chain 只读 storage，不注入 signer | ⚠️ | 代码审查 + `#[ignore]` 测试 | 动态 storage 查询/缓存/无 signer 已实现；真实链未验证 |
| D8 | did:key 私钥安全 | ✅ | 代码审查 | 私钥仅存在于 KeyVault；绑定层不暴露 |
| D9 | 零链账户私钥 | ✅ | 代码审查 | `chain.rs` 只构造 `OnlineClient`，无 signer |
| D10 | keyvault-core 集成（build_vault） | ✅ | `cargo test -p did-sdk` | Mock/Centralized/Chain 均通过 |
| D11 | 一致性测试 | ✅ | `cargo test --test consistency` | 同上 |

## 3. 发布形态（S1–S3）

| 编号 | 验收项 | 状态 | 验证命令 | 证据摘要 |
|---|---|---|---|---|
| S1 | Linux musl 完全静态、零运行时依赖 | ⏳ CI | GitHub Actions `rust-musl.yml` | 按评审结论由 CI runner 验证；本地不做交叉编译 |
| S2 | `UserRejected` 三语言透传 | ✅ | Rust `user_rejected.rs`；绑定错误映射代码 | Rust 三来源测试全绿；Python `UserRejectedError` / Node `err.code` 映射已实现（当前 Mock 工厂不暴露 AutoReject，触发路径留给未来设备安全区） |
| S3 | 四平台构建矩阵 | ⏳ CI | GitHub Actions | 需先创建/推送 `metercai/did-sdk` 并启用 Actions |

## 4. 绑定

| 项 | 状态 | 验证命令 | 证据摘要 |
|---|---|---|---|
| Python wheel 构建 | ✅ | `maturin build --release` | cp312 macOS arm64 wheel（本地） |
| Python pytest（golden vector + 异步 roundtrip） | ✅ | `pytest bindings/python/tests` | **7 passed** |
| Node addon 构建 | ✅ | `npx napi build --platform --release` | darwin-arm64 `.node` |
| Node vitest（golden vector + `err.code`） | ✅ | `npm test` | **6 passed** |
| `.d.ts` 已提交 | ✅ | `bindings/node/index.d.ts` | napi 生成并提交 |
| 三语言向量一致 | ✅ | `bash scripts/cross-lang-vectors.sh` | 脚本退出码 0；Rust/Python/Node 全绿 |
| 跨平台构建（CI） | ⏳ | GitHub Actions | 待远程仓库 |

## 5. 文档

| 项 | 状态 | 证据 |
|---|---|---|
| README 安装 / 快速开始 / 环境变量 / 平台矩阵 / UserRejected / 未来扩展 / 无 WASM | ✅ | [`README.md`](../README.md) |
| 实施计划评审通过 | ✅ | [`docs/implementation-plan.md`](implementation-plan.md) §11 |
| 实施报告 | ✅ | [`docs/implementation-report.md`](implementation-report.md) |
| 验收清单逐项有命令输出摘要 | ✅ | 本文件 |
| LICENSE 文件 | ✅ | [`LICENSE`](../LICENSE)（Apache-2.0） |
| CI workflow YAML 语法 | ✅ | `actionlint -color .github/workflows/*.yml` → exit 0 |
| CI 接入 runbook | ✅ | [`docs/ci-setup.md`](ci-setup.md) |
| Shell 脚本语法 | ✅ | `bash -n scripts/*.sh` 全部通过 |

## 6. 已知未验证项（需外部条件）

| 项 | 原因 | 解除条件 |
|---|---|---|
| S1 / S3 跨平台 CI | 仓库尚未创建（API 404）；本地无 GitHub 凭据 | 用户创建 `metercai/did-sdk` 并推送；或提供可用 token / 已授权 SSH key |
| D7 真实链接入 | 无 identity-chain 节点与 pallet 元数据 | 提供节点 + `DID_SDK_CHAIN_ENDPOINT` + pallet/storage 名称后跑 `#[ignore]` 测试 |
| crates.io / PyPI / npm 发布 | 无凭据、包名所有权未确认 | 另立发布任务 |
| npm 依赖审计告警 | devDependencies（vitest 等）传递依赖 | 发布前执行 `npm audit` 评估；不影响 addon 运行时 |
