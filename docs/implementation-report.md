# did-sdk 实施报告（更新版规格 v2）

| 项目 | 内容 |
|---|---|
| 日期 | 2026-11-12 |
| 规格 | `01-DidSdk接口契约与实现规格书1.md`、`04-keyvault-core_crate规格书1.md` |
| 范围 | keyvault-core namespace 隔离、DidSdk<Client/Server>、三种 DID 方法、VC 钱包、绑定与测试 |
| 结论 | v2 代码与本地测试完成；GitHub Actions 全绿（提交 `2925627`） |

---

## 1. 新架构

```text
DidSdk<Client> ── vault: KeyVault(client-did/) ── 本地签名/VC 签发
DidSdk<Server> ── vault: None ─────────────────── 外部 Proof 注入/VC 校验
        │
        └── Backend: Mock / Centralized / Chain（只读 resolve_did + get_anchor）
```

- `DidSdk<Client>` 与 `DidSdk<Server>` 是不同类型，方法按类型 impl 隔离。
- VC 钱包（store/get/list/remove/build_vp）在两种模式共享。
- Server 不持有签名私钥；`assemble_vc_with_proof` 接收外部 `Proof`。
- `verify_vc` 解析 issuer（did:key / did:peer / did:web），验证 Ed25519 proof、有效期、anchor。

## 2. keyvault-core 变化

- 新增 `KeyNamespace`（ChainAccount / ParticipantDid / ClientDid）与
  `KeyAlgorithm`（Ed25519 / Sr25519），强制映射。
- `KeyVault::generate(namespace, algorithm)`、`list_keys(Option<namespace>)`、
  `sign_checked(key_id, payload, expected_namespace, expected_algorithm)`。
- `KeyId` 格式：`{namespace_prefix}{local_id}`（如 `client-did/did_key_z...`）。
- `FileKeystore`：
  - 按 namespace 子目录 + `.enc` 文件；
  - `index.json` v2 记录 `{key_id, namespace, algorithm, file, created_at}`；
  - KVLT v2 文件头含 namespace/algorithm；
  - 解锁校验文件头与 index 一致；
  - Argon2id + ChaCha20-Poly1305 + 原子写。
- 新增 SS58：`ss58_to_account_id` / `account_id_to_ss58`（含 checksum）。
- `signing_input` 增加：
  - `participant_registration_v1`
  - `operator_rotation_v1`
  - `controller_did_rotation_v1`
  - `delegation_authorization_v1`

## 3. 兼容性 / 迁移

本次为**破坏性升级**：

1. `DidSdk` 由 trait 变为 `DidSdk<Client>` / `DidSdk<Server>` 类型；
2. `DidRecord` 改为 `method/doc_hash/owner/block_number`；
3. `VerifyResult` 改为 `verified/integrity/address/reason`；
4. `IssueAuthorizationSignature` 改为裸签名字节；
5. VC proof 改为 `Proof { type_, created, verificationMethod, jws }`；
6. keyvault-core 文件格式 v1 → v2（`.enc`，namespace 子目录），旧 keystore 不兼容；
7. 字符串签名格式保持向后兼容（原有 3 个签名输入格式不变）。

## 3.1 本轮新增能力

- `ServerConfig.key_vault: Option<KeyVaultConfig>`：Server 在开发/测试/试运行可配置
  `FileKeystore`，使用 `participant-did/` 密钥签发 VC / 签名；生产留空。
- `VcStore` 加密：每个 VC 文件以 `DVCS` 头 + ChaCha20-Poly1305 落盘；
  密钥来自 `DID_SDK_VC_STORAGE_PASSWORD` 或自动生成的 `.vc_password`（0600），
  Client 与 Server 均不写明文。

## 3.2 Client/Server 双产物

- Rust：`did-sdk-client` / `did-sdk-server` 产品 crate。
- Python：`did-sdk-client` / `did-sdk-server` 两个 wheel（共享 core）。
- Node：`@did-sdk/client` / `@did-sdk/server` 两个 addon（共享 core）。
- CI 构建矩阵按 Client/Server 各 5 平台。

### 密钥策略

- Server 默认 `key_vault: Some(FileKeystore)`，开发/测试/试运行可直接签名；
  `key_vault: None` 或 `key_vault_scheme="none"` 关闭。
- VC 加密默认复用 KeyVault 密码；无 KeyVault 时回退独立密码/自动 `.vc_password`。

## 4. GitHub Actions（v2 提交 `2925627`）

| workflow | run | 结果 |
|---|---|---|
| `ci` | [43216003187](https://github.com/metercai/did-sdk/actions/runs/43216003187) | success |
| `rust-musl` | [43216003000](https://github.com/metercai/did-sdk/actions/runs/43216003000) | 4/4 success |
| `python` | [43216002988](https://github.com/metercai/did-sdk/actions/runs/43216002988) | 10/10 success |
| `node` | [43216003104](https://github.com/metercai/did-sdk/actions/runs/43216003104) | 10/10 success |
| `cross-lang` | [43216003140](https://github.com/metercai/did-sdk/actions/runs/43216003140) | success |

musl 静态日志：

```text
x86_64:  statically linked, stripped / OK: static / ldd: not a dynamic executable
aarch64: statically linked, stripped / OK: static / ldd: not a dynamic executable
```

## 5. 本地验证

```text
cargo test -p keyvault-core           # 9 unit + 16 integration = 25 passed
cargo test -p did-sdk                 # 3 unit + 50 integration = 53 passed, 1 ignored
cargo fmt --all -- --check            # passed
cargo clippy --workspace --exclude did-sdk-python --exclude did-sdk-python-server --exclude did-sdk-node --exclude did-sdk-node-server --all-targets -- -D warnings  # passed
pytest bindings/python/tests          # 9 passed
pytest bindings/python-server/tests   # 1 passed
npm test (bindings/node)              # 8 passed
npm test (bindings/node-server)       # 1 passed
```

覆盖：

- namespace × algorithm 生成/拒绝、跨 namespace `sign_checked`；
- SS58 往返/校验和；
- did:key / did:peer:0/1/2、did:web URL；
- did:key 签名/验签、DID-Signature header；
- Client VC 签发、VP、授权签名；
- Server 外部 proof 组装、VC 校验、篡改拒绝；
- Mock 自动拒绝/延迟、handler 拒绝、Centralized 只读、三后端一致性；
- Python/Node 同组向量与异步 API。

## 6. 待外部条件

1. **真实 chain**：仍缺 identity-chain 节点与 pallet 元数据；
2. **发布**：未发布 crates.io / PyPI / npm；
3. **did:peer 生产编码**：POC 使用简化 `0/2` 内嵌公钥、`1` 文档哈希 + 本地文档；
   对接其他 did:peer 实现时需对齐编码。
4. **Server VC 存储加密**：POC 使用 `vc_storage_path` 明文 JSON；
   规格要求由 KeyVault 或注入存储密钥派生加密，后续接入。
