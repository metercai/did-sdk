# did-sdk 实施报告（v2 + R1）

| 项目 | 内容 |
|---|---|
| 日期 | 2026-11-12 |
| 规格 | `docs/01-DidSdk接口契约与实现规格书1.md`、`docs/04-keyvault-core_crate规格书1.md` |
| 修订 | `docs/did-sdk移除链上查询与subxt依赖的修订.md`（R1） |
| 范围 | Client/Server 双产物、Mock/Centralized 两后端、三种 DID 方法、VC 钱包、Server 本地签名器、VC 密文存储 |
| 结论 | 代码与本地测试完成；GitHub Actions 需在推送后重跑 |

---

## 1. 架构

```text
DidSdk<Client> ── vault: KeyVault(client-did/) ── 本地签名/VC 签发
DidSdk<Server> ── vault: 可选 FileKeystore(participant-did/) ── 外部 Proof 或本地开发签名
        │
        └── Backend: Mock / Centralized（只读 resolve_did；无链上查询）
```

- `DidSdk<Client>` 与 `DidSdk<Server>` 是不同类型，方法按类型 impl 隔离。
- **不提供 Chain 后端，不暴露 `get_anchor`，依赖树无 `subxt` / `scale-value`。**
- 锚定查询归验证方 `chain-sdk`；`did-sdk` 的签名/验签不读取锚定结果。
- Server 默认 `FileKeystore` 本地签名器（开发/测试/试运行）；生产可关闭。
- VC 钱包（store/get/list/remove/build_vp）在两种模式共享。

## 2. R1 落地

| 项 | 状态 |
|---|---|
| `ChainBackend` / `src/chain.rs` | 已删除 |
| `DidSdkMode::Chain` | 已删除，只保留 `Mock` / `Centralized` |
| `get_anchor` | 已从 `Backend` / `DidSdk` / 绑定中删除 |
| `AnchorRecord` / anchor 错误码 | 已删除 |
| `subxt` / `scale-value` | 已从 Cargo.toml / 依赖树移除 |
| `[did_sdk.chain]` / `DID_SDK_CHAIN_ENDPOINT` | 已删除 |
| `verify_vc` | 只校验 issuer + proof + 有效期，不做链上锚定查询 |
| D16–D18 | 已加入验收清单 |

## 3. keyvault-core

- `KeyNamespace`（ChainAccount / ParticipantDid / ClientDid）× `KeyAlgorithm`（Ed25519 / Sr25519）。
- `KeyVault::{generate, list_keys, sign_checked}`；跨 namespace/algorithm 拒绝。
- `FileKeystore` v2：namespace 子目录 + `.enc` + index v2 + 文件头 namespace/algorithm。
- SS58、8 个签名输入（含 vp_sd_v1）、Argon2id + ChaCha20-Poly1305。

## 4. Client / Server 双产物

| 产物 | Client | Server |
|---|---|---|
| Rust | `did-sdk-client` | `did-sdk-server` |
| Python | `did-sdk-client` / `did_sdk` | `did-sdk-server` / `did_sdk_server` |
| Node | `@did-sdk/client` | `@did-sdk/server` |

## 5. Server 签名与 VC 加密

- `ServerConfig.key_vault` 默认 `Some(FileKeystore)`；`key_vault = None` 关闭本地签名器。
- Server 可用 `participant-did/` 密钥执行 `sign_with_participant_key` / `issue_self_asserted_vc`。
- VC 文件：`DVCS` 头 + ChaCha20-Poly1305 密文。
- 默认复用 KeyVault 密码；无 KeyVault 时回退 `DID_SDK_VC_STORAGE_PASSWORD` / 自动 `.vc_password`（0600）。
- 旧明文 VC 读取时自动迁移为密文。

## 5.2 选择性披露（SD-JWT）

- `keyvault-core::sd`：16 字节 CSPRNG 盐、base64url、SHA-256 盐化哈希。
- `did-sdk`：`_sd`/`_sd_alg`、`Disclosure`、`issue_selective_vc`、
  `store_vc_with_disclosures`、`build_vp_selective`、`verify_vp`。
- VC 与 Disclosures 同一加密信封；未披露属性不出现在 VP。
- `vp_sd_v1` 覆盖 VC 原文哈希 + Disclosures 哈希 + challenge + domain。
- 错误码：`disclosure_hash_mismatch` / `disclosure_duplicate` /
  `disclosure_missing` / `sd_alg_unsupported`。

## 6. 本地验证

```text
cargo test -p keyvault-core           # 12 unit + 16 integration = 28 passed
cargo test -p did-sdk                 # 3 unit + 52 integration = 55 passed
cargo fmt --all -- --check            # passed
cargo clippy --workspace --exclude did-sdk-python --exclude did-sdk-python-server --exclude did-sdk-node --exclude did-sdk-node-server --all-targets -- -D warnings  # passed
pytest bindings/python/tests          # 11 passed
pytest bindings/python-server/tests   # 2 passed
npm test (bindings/node)              # 10 passed
npm test (bindings/node-server)       # 1 passed
cargo tree -p did-sdk | grep subxt    # 无输出
```

## 7. GitHub Actions

| workflow | run | 结果 |
|---|---|---|
| `ci` | [43229893389](https://github.com/metercai/did-sdk/actions/runs/43229893389) | success |
| `rust-musl` | [43229893304](https://github.com/metercai/did-sdk/actions/runs/43229893304) | 4/4 success |
| `python` | [43229893563](https://github.com/metercai/did-sdk/actions/runs/43229893563) | 10/10 success |
| `node` | [43229893408](https://github.com/metercai/did-sdk/actions/runs/43229893408) | 10/10 success |
| `cross-lang` | [43229893279](https://github.com/metercai/did-sdk/actions/runs/43229893279) | success |

## 7.1 首个 Release

- tag：`v0.1.0`
- run：[43245495138](https://github.com/metercai/did-sdk/actions/runs/43245495138)
- 资产：10 个 wheel、2 个 npm tarball（各含 5 平台 `.node`）、4 个 Rust CLI、`SHA256SUMS`。
- 已验证：发布 wheel 可 import 并完成 Client/Server 签名；npm tarball 可安装并完成同样流程。

## 8. 待外部条件

1. **发布**：未发布 crates.io / PyPI / npm；
2. **did:peer 生产编码**：POC 使用简化 `0/2` 内嵌公钥、`1` 文档哈希 + 本地文档；
3. **did:web 实网**：HTTPS 抓取未做网络级集成测试。
