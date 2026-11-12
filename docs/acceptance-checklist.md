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
| K8 | 9 个签名对象构造函数（含 vp_v1 / vp_sd_v1） | ✅ | `signing_input` 单测 + `tests/vectors` + 三语言绑定 |
| K9 | 跨 crate 共享 | ✅ | did-sdk / Python / Node 均调用 keyvault-core |
| K10 | namespace 强制隔离 + 文件头/index 一致 | ✅ | `rejects_invalid_namespace_algorithm_combination`、`index_algorithm_mismatch_is_rejected` |
| K11 | `sign_checked` 拒绝跨 namespace / algorithm | ✅ | `sign_checked_enforces_namespace_and_algorithm` |
| K12 | 三类签名入口隔离 | ✅ | namespace 单测 + did-sdk 使用 `ClientDid` |
| K13 | 签名对象字段与链上字段对应 | ✅ | `participant_registration_v1` 等固定格式测试 |

## 2. did-sdk 契约（D1–D18）

| 编号 | 验收项 | 状态 | 验证 / 证据 |
|---|---|---|---|
| D1 | 接口契约完整 | ✅ | `DidSdk<Client>` / `DidSdk<Server>` 编译 |
| D2 | 类型参数编译期隔离 | ✅ | 方法按 `impl DidSdk<Client>` / `impl DidSdk<Server>` 分离 |
| D3 | 两后端模式切换 | ✅ | `ClientConfig.mode`（mock / centralized）+ `build_client_sdk` |
| D4 | 两后端语义一致 | ✅ | `tests/consistency.rs` |
| D5 | did:key / did:peer:0/1/2 / did:web | ✅ | `tests/did_methods.rs`；did:web URL 单测 |
| D6 | Mock 自动确认/拒绝/延迟（仅 Client） | ✅ | `tests/user_rejected.rs` |
| D7 | Centralized 只读 | ✅ | `tests/centralized_contract.rs` |
| D8 | 无 Chain 后端 / 无 subxt | ✅ | `cargo tree -p did-sdk` 无 subxt；无 ChainBackend |
| D9 | Client 私钥安全 | ✅ | KeyVault 封装 + 用户确认 |
| D10 | 两模式均不持链账户私钥 | ✅ | 代码审查；无 Signer 注入 |
| D11 | keyvault-core 集成 | ✅ | Client 经 `FileKeystore` 管理 `client-did/` |
| D12 | VC 钱包统一 | ✅ | 两模式共享 `store/get/list/remove/build_vp` |
| D13 | Server 生产不持签名私钥 | ✅ | `assemble_vc_with_proof` 接受外部 `Proof`；开发/测试可配置 FileKeystore |
| D14 | 一致性测试 | ✅ | Mock / Centralized 本地流程 |
| D15 | Server 校验他人 VC | ✅ | issuer 签名/有效期/注册状态；不做链上锚定查询 |
| D16 | 无 `subxt` 依赖 | ✅ | Cargo.toml / `cargo tree -p did-sdk` |
| D17 | 无链上查询接口 | ✅ | 无 `get_anchor` / `ChainBackend` |
| D18 | 锚定查询职责边界 | ✅ | 签名/验签不读取锚定结果 |

## 3. 发布形态（S1–S3）

| 编号 | 验收项 | 状态 | 证据 |
|---|---|---|---|
| S1 | Linux musl 完全静态 | ✅ | `rust-musl` [43268561636](https://github.com/metercai/did-sdk/actions/runs/43268561636)；x86_64/aarch64 `statically linked` + `ldd: not a dynamic executable` |
| S2 | `UserRejected` 三语言透传 | ✅ | Rust 测试 + Python/Node 映射代码 |
| S3 | 双产物构建矩阵 | ✅ | Rust 4/4、Python 10/10（client+server）、Node 10/10（client+server） |

## 4. 绑定

| 项 | 状态 | 证据 |
|---|---|---|
| Python wheel 构建 | ✅ | 本地 maturin build |
| Python pytest | ✅ | **13 passed** |
| Node addon 构建 | ✅ | 本地 napi build |
| Node vitest | ✅ | **11 passed** |
| 三语言 golden vector | ✅ | Rust/Python/Node 各自执行 |
| `.d.ts` 已提交 | ✅ | `bindings/node/index.d.ts` |

## 5. 本地测试计数

| 套件 | 结果 |
|---|---|
| `cargo test -p keyvault-core` | **12 单测 + 16 集成 = 28 passed** |
| `cargo test -p did-sdk` | **3 单测 + 52 集成 = 55 passed** |
| `cargo fmt --all -- --check` | 通过 |
| `cargo clippy --workspace --exclude did-sdk-python --exclude did-sdk-python-server --exclude did-sdk-node --exclude did-sdk-node-server --all-targets -- -D warnings` | 通过 |
| Python `pytest` | **13 passed** |
| Node `vitest` | **11 passed** |

## 5.1 本轮新增要求

| 要求 | 状态 | 证据 |
|---|---|---|
| Server 可选 FileKeystore 本地签名（开发/测试/试运行） | ✅ | `ServerConfig.key_vault` + `server_dev_file_signer_can_sign` |
| Client VC 存储密文 | ✅ | `client_vc_is_stored_as_ciphertext_and_reloads`（`DVCS` 头，无明文） |
| Server VC 存储密文 | ✅ | `server_vc_is_stored_as_ciphertext` |
| VC 加密密钥来源 | ✅ | `DID_SDK_VC_STORAGE_PASSWORD` 或自动生成 `.vc_password`（0600） |

## 5.2 Client/Server 双产物

| 产物 | Client | Server | 状态 |
|---|---|---|---|
| Rust crate | `did-sdk-client` | `did-sdk-server` | ✅ |
| Python wheel | `did-sdk-client` (`did_sdk`) | `did-sdk-server` (`did_sdk_server`) | ✅ 本地构建/测试 |
| Node addon | `@did-sdk/client` | `@did-sdk/server` | ✅ 本地构建/测试 |
| CI 矩阵 | 5 平台 | 5 平台 | ✅ 10/10 全绿 |

Server 默认 `key_vault: Some(FileKeystore)`；`key_vault_scheme="none"` 可关闭本地签名器。
VC 加密密钥默认复用 KeyVault 密码；无 KeyVault 时回退
`DID_SDK_VC_STORAGE_PASSWORD` / 自动 `.vc_password`。

## 5.3 选择性披露（SD-JWT）

| 编号 | 状态 | 证据 |
|---|---|---|
| I1–I6 签发 | ✅ | `issue_selective_vc`、16 字节盐、`_sd`、`_sd_alg`、Disclosure 交付 |
| D1 绑定加密存储 | ✅ | VC + Disclosures 同一 `DVCS` 信封 |
| D2 用户选择 | ✅ | `list_disclosable_attributes`；默认 disclose=[] |
| D3 子集筛选 | ✅ | `build_vp_selective` + `select_disclosures` |
| D4 VP disclosures | ✅ | `VerifiablePresentation.disclosures` |
| D5 holder 签名覆盖 | ✅ | `vp_sd_v1` 覆盖 VC 哈希 + Disclosures 哈希 + challenge/domain |
| V1 VP 签名/challenge | ✅ | `Server::verify_vp` |
| V2 VC 签名 | ✅ | 复用 `verify_vc` |
| V3 Disclosure 哈希比对 | ✅ | `sd::verify_disclosures` / `verify_vp` |
| V4 未披露属性不可见 | ✅ | VP 只携带选中 Disclosure |
| V5 链上锚定 | ⏳ | 由 chain-sdk Verifier 负责（R1） |
| V6 篡改检测 | ✅ | `disclosure_hash_mismatch` |
| V7 重复检测 | ✅ | `disclosure_duplicate` |
| P1–P3 隐私边界 | ✅ | 独立盐 + 文档边界说明 |

测试：`tests/selective_disclosure.rs`；Python `test_selective_disclosure.py` / `test_server.py`；Node `vectors.test.ts`。

## 6. GitHub Actions（SD-JWT 代码提交 `ffd59fd`）

| workflow | run | 结果 |
|---|---|---|
| `ci` | [43268561991](https://github.com/metercai/did-sdk/actions/runs/43268561991) | success |
| `rust-musl` | [43268561636](https://github.com/metercai/did-sdk/actions/runs/43268561636) | 4/4 success |
| `python` | [43268561958](https://github.com/metercai/did-sdk/actions/runs/43268561958) | 10/10 success |
| `node` | [43268561892](https://github.com/metercai/did-sdk/actions/runs/43268561892) | 10/10 success |
| `cross-lang` | [43268561597](https://github.com/metercai/did-sdk/actions/runs/43268561597) | success |

## 6.1 首个 Release

| 项 | 证据 |
|---|---|
| tag | [`v0.1.0`](https://github.com/metercai/did-sdk/releases/tag/v0.1.0) |
| release workflow | [43245495138](https://github.com/metercai/did-sdk/actions/runs/43245495138) success |
| Python wheels | 10（Client/Server × 5 平台） |
| Node tarballs | 2（各含 5 平台 `.node`） |
| Rust CLI | 4（musl x64/arm64、macOS arm64、Windows x64） |
| 校验 | `SHA256SUMS` 已附 |

## 7. 待外部条件

| 项 | 原因 |
|---|---|
| 发布 | crates.io / PyPI / npm 未发布 |
