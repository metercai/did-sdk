# did-sdk 验收清单（更新版规格 v2）

> 状态：代码与本地测试完成；GitHub Actions 需在推送后重新验证。
> 规格输入：`01-DidSdk接口契约与实现规格书1.md`、`04-keyvault-core_crate规格书1.md`。
>
> 关联：[`docs/implementation-report.md`](implementation-report.md) ·
> [`docs/implementation-plan.md`](implementation-plan.md)

## 0. 基础环境

| 项 | 状态 | 证据 |
|---|---|---|
| Rust 1.88.0 / edition 2024 | ✅ | `rust-toolchain.toml`；CI |
| workspace 4 成员 | ✅ | `cargo metadata --no-deps` |
| `Cargo.lock` 提交（resolver 3） | ✅ | `Cargo.lock` |
| 本地 fmt / clippy / test | ✅ | 见 §5 计数 |

## 1. keyvault-core（K1–K13）

| 编号 | 验收项 | 状态 | 验证 / 证据 |
|---|---|---|---|
| K1 | `KeyVault` trait 完整（generate/load/sign/sign_checked/public_key/list_keys/delete） | ✅ | `cargo test -p keyvault-core` |
| K2 | 按 namespace × algorithm 生成，写入 namespace 子目录 | ✅ | `file_keystore_namespace_layout_and_reload` |
| K3 | 正确密码解锁；错误密码 `InvalidPassword` | ✅ | 同上 |
| K4 | 签名可被公钥验证 | ✅ | Ed25519 + sr25519 测试 |
| K5 | 私钥不出 KeyVault | ✅ | 代码审查；`Keypair` 不 Serialize/Clone/Debug |
| K6 | 环境变量 / 文件 / 交互输入 | ✅ | `password_sources`；`PasswordSource::Prompt` |
| K7 | did:key + SS58 原语 | ✅ | `ss58_roundtrip_and_checksum`、`did_key_roundtrip...` |
| K8 | 7 个签名对象构造函数 | ✅ | `signing_input` 单测 + `tests/vectors` + 三语言绑定 |
| K9 | 跨 crate 共享 | ✅ | did-sdk / Python / Node 均调用 keyvault-core |
| K10 | namespace 强制隔离 + 文件头/index 一致 | ✅ | `rejects_invalid_namespace_algorithm_combination`、`index_algorithm_mismatch_is_rejected` |
| K11 | `sign_checked` 拒绝跨 namespace / algorithm | ✅ | `sign_checked_enforces_namespace_and_algorithm` |
| K12 | 三类签名入口隔离 | ✅ | namespace 单测 + did-sdk 使用 `ClientDid` |
| K13 | 签名对象字段与链上字段对应 | ✅ | `participant_registration_v1` 等固定格式测试 |

## 2. did-sdk 契约（D1–D15）

| 编号 | 验收项 | 状态 | 验证 / 证据 |
|---|---|---|---|
| D1 | 接口契约完整 | ✅ | `DidSdk<Client>` / `DidSdk<Server>` 编译 |
| D2 | 类型参数编译期隔离 | ✅ | 方法按 `impl DidSdk<Client>` / `impl DidSdk<Server>` 分离 |
| D3 | 三后端模式切换 | ✅ | `ClientConfig.mode` + `build_client_sdk` |
| D4 | 三后端语义一致 | ✅ | `tests/consistency.rs` |
| D5 | did:key / did:peer:0/1/2 / did:web | ✅ | `tests/did_methods.rs`；did:web URL 单测 |
| D6 | Mock 自动确认/拒绝/延迟（仅 Client） | ✅ | `tests/user_rejected.rs` |
| D7 | Centralized 只读 | ✅ | `tests/centralized_contract.rs` |
| D8 | Chain 只读 | ✅ | `tests/consistency.rs` + `#[ignore]` 真链测试 |
| D9 | Client 私钥安全 | ✅ | KeyVault 封装 + 用户确认 |
| D10 | 两模式均不持链账户私钥 | ✅ | 代码审查；无 Signer 注入 |
| D11 | keyvault-core 集成 | ✅ | Client 经 `FileKeystore` 管理 `client-did/` |
| D12 | VC 钱包统一 | ✅ | 两模式共享 `store/get/list/remove/build_vp` |
| D13 | Server 不持签名私钥 | ✅ | `assemble_vc_with_proof` 只接受外部 `Proof` |
| D14 | 一致性测试 | ✅ | Mock / Centralized / Chain 本地流程 |
| D15 | Server 校验他人 VC | ✅ | `server_verifies_client_issued_vc` / tampered 测试 |

## 3. 发布形态（S1–S3）

| 编号 | 验收项 | 状态 | 证据 |
|---|---|---|---|
| S1 | Linux musl 完全静态 | ⏳ CI | 需推送 v2 后重跑 `rust-musl.yml` |
| S2 | `UserRejected` 三语言透传 | ✅ | Rust 测试 + Python/Node 映射代码 |
| S3 | 四平台构建矩阵 | ⏳ CI | 需推送 v2 后重跑 |

## 4. 绑定

| 项 | 状态 | 证据 |
|---|---|---|
| Python wheel 构建 | ✅ | 本地 maturin build |
| Python pytest | ✅ | **8 passed** |
| Node addon 构建 | ✅ | 本地 napi build |
| Node vitest | ✅ | **7 passed** |
| 三语言 golden vector | ✅ | Rust/Python/Node 各自执行 |
| `.d.ts` 已提交 | ✅ | `bindings/node/index.d.ts` |

## 5. 本地测试计数

| 套件 | 结果 |
|---|---|
| `cargo test -p keyvault-core` | **9 单测 + 16 集成 = 25 passed** |
| `cargo test -p did-sdk` | **3 单测 + 44 集成 = 47 passed，1 ignored** |
| `cargo fmt --all -- --check` | 通过 |
| `cargo clippy --workspace --all-targets -- -D warnings` | 通过 |
| Python `pytest` | **8 passed** |
| Node `vitest` | **7 passed** |

## 6. 待外部条件

| 项 | 原因 |
|---|---|
| S1/S3 CI | 本次重构后需重新推送并跑 Actions |
| 真实 Chain | 无 identity-chain 节点 / pallet 元数据 |
| 发布 | crates.io / PyPI / npm 未发布 |
