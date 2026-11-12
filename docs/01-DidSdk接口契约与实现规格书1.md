# DidSdk 接口契约与实现规格书

## 版本 v3：Client / Server 两模式 + Mock / Centralized 两后端 + SD-JWT 选择性披露

> **文档状态（2026-11-13）**：本文档已合并并重构以下输入：
>
> - 《DidSdk 接口契约与实现规格书》原版；
> - R1《did-sdk 移除链上查询与 subxt 依赖的修订》；
> - 《VC 选择性披露特性补充附件》（SD-JWT）。
>
> 与代码提交 `ffd59fd` 同步：无 `Chain` 后端、无 `get_anchor`、无 `subxt` / `scale-value`；
> 支持 `_sd` / `_sd_alg`、Disclosure、选择性 VP、`vp_sd_v1` 与 `verify_vp`。

---

## 0. 定位与设计原则

### 0.1 定位

`did-sdk` 是 **DID 方法 + VC 钱包 + 选择性披露** 的统一能力层。独立身份客户端、
`aimail-sdk`、其他客户端应用直接依赖它；`chain-sdk` / `chain-owner-sdk` 按角色装配
`DidSdk<Server>`。

它支持三种 DID 方法（`did:key`、`did:peer`、`did:web`），通过类型参数在编译期区分两种运行模式：

| 运行模式 | 典型使用者 | DID 方法 | 签名私钥 | VC 能力 |
|---|---|---|---|---|
| `DidSdk<Client>` | 客户端应用、`aimail-sdk` | `did:key` / `did:peer` | 设备安全区（`KeyVault`） | 签发 + 持有 + 呈现 + 选择性披露 |
| `DidSdk<Server>` | `chain-sdk` / `chain-owner-sdk` 服务端 | 固定 `did:web` | 生产不持有；开发/测试/试运行默认 `FileKeystore` | 持有、组装、校验；本地签名器可签发 |

**职责边界**：`did-sdk` 不承担链上查询，不依赖 `subxt`。锚定查询与撤销核对由验证方的
`chain-sdk`（Verifier）完成；`did-sdk` 的签名/验签不读取链上锚定结果。

### 0.2 设计原则

1. **类型参数编译期隔离**。`DidSdk<Client>` / `DidSdk<Server>` 是不同类型；非法方法编译失败。
   不用 Cargo feature 表达互斥模式。
2. **两后端与两模式正交**。`Mock` / `Centralized` 只影响 `resolve_did`；不提供 `Chain` 后端。
3. **无 `dyn DidSdk` trait**。应用使用具体类型 `DidSdk<Client>` / `DidSdk<Server>`。
4. **VC 钱包统一**。两模式共享 store/get/list/remove/build_vp 语义。
5. **私钥安全域**。Client 私钥在 `KeyVault`；Server 生产不持私钥，开发/测试可配置
   `FileKeystore`，生产通过注入 `Proof` 签发。
6. **Server 身份固定 `did:web`**。`DidSdk<Server>` 不生成 DID。
7. **客户端不承担链上查询**。无 `get_anchor`、无 Chain 后端、无 `subxt`。
8. **VC 与 Disclosures 加密存储**。Client/Server 均不落明文。
9. **SD-JWT 最小侵入**。只扩展 VC 的 `credentialSubject` 与 VP 的 `disclosures`；
   链上锚定原语不变（由 chain-sdk 负责）。

### 0.3 两种后端模式

| 模式 | 后端 | 部署形态 | 适用阶段 |
|---|---|---|---|
| `Mock` | 进程内 DID 状态 + 确认策略 | 无外部依赖 | 单元测试 |
| `Centralized` | 中心化模拟链只读 HTTP | 独立 HTTP 服务（可选） | 集成测试、试生产 |

**`did-sdk` 不提供 `Chain` 后端。** 需要 Substrate RPC / 锚定查询/写链时使用 `chain-sdk`。

---

## 1. 类型参数与 API

```rust
pub trait SdkMode: Send + Sync + 'static {
    const IS_CLIENT: bool;
}

pub struct Client;
pub struct Server;
impl SdkMode for Client { const IS_CLIENT: bool = true; }
impl SdkMode for Server { const IS_CLIENT: bool = false; }

pub struct DidSdk<M: SdkMode> {
    backend: Arc<dyn Backend>,
    vault: Option<Arc<dyn KeyVault>>,
    participant_did: Option<String>,
    // http / docs / local_dids / active_did / PhantomData
}
```

`Backend` 只有一种只读能力：

```rust
#[async_trait]
pub trait Backend: Send + Sync {
    async fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError>;

    // Mock 确认策略；默认直接允许
    async fn confirm_signing(&self) -> Result<(), DidSdkError> { Ok(()) }
    async fn confirm_vp(&self) -> Result<(), DidSdkError> { Ok(()) }
    async fn confirm_authorization(&self) -> Result<(), DidSdkError> { Ok(()) }
}
```

### 1.1 两种模式共享 API

```rust
impl<M: SdkMode> DidSdk<M> {
    pub fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError>;

    // VC 钱包
    pub async fn store_vc(&self, vc: VerifiableCredential) -> Result<(), DidSdkError>;
    pub async fn get_vc(&self, anchor_id: &str)
        -> Result<Option<VerifiableCredential>, DidSdkError>;
    pub async fn list_vcs(&self) -> Result<Vec<VerifiableCredential>, DidSdkError>;
    pub async fn remove_vc(&self, anchor_id: &str) -> Result<(), DidSdkError>;
    pub async fn build_vp(
        &self, vcs: Vec<VerifiableCredential>, challenge: &str, domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError>;

    // 选择性披露
    pub async fn store_vc_with_disclosures(
        &self, vc: VerifiableCredential, disclosures: Vec<Disclosure>,
    ) -> Result<(), DidSdkError>;
    pub async fn get_vc_with_disclosures(&self, anchor_id: &str)
        -> Result<Option<(VerifiableCredential, Vec<Disclosure>)>, DidSdkError>;
    pub async fn list_disclosable_attributes(&self, anchor_id: &str)
        -> Result<Vec<String>, DidSdkError>;
    pub async fn build_vp_selective(
        &self, requests: Vec<SelectiveVpRequest>, challenge: &str, domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError>;

    pub fn set_request_handler(&self, handler: Arc<dyn ServerRequestHandler>);
}
```

`get_anchor` 已移除；`get_vc(anchor_id)` 是**本地 VC 存储键**，与链上锚定查询无关。

### 1.2 仅 Client

```rust
impl DidSdk<Client> {
    pub fn generate_did_key(&self) -> Result<String, DidSdkError>;
    pub fn generate_did_peer(&self, numalgo: PeerNumalgo) -> Result<String, DidSdkError>;
    pub async fn sign_with_did_key(
        &self, message: &[u8], ctx: SigningContext,
    ) -> Result<Signature, DidSdkError>;
    pub fn resolve_did_key(&self, did: &str) -> Result<Ed25519PublicKey, DidSdkError>;
    pub fn resolve_did_peer(&self, did: &str) -> Result<DidDocument, DidSdkError>;
    pub fn create_did(&self) -> Result<DidRecord, DidSdkError>;

    pub fn issue_self_asserted_vc(&self, claims: serde_json::Value)
        -> Result<VerifiableCredential, DidSdkError>;
    pub fn issue_selective_vc(
        &self, claims: serde_json::Value, disclosable: &[String],
    ) -> Result<(VerifiableCredential, Vec<Disclosure>), DidSdkError>;

    pub async fn build_did_signature_header(
        &self, from: &str, anchor_id: &str, body_hash: &str, rcpt_hash: &str,
    ) -> Result<String, DidSdkError>;
    pub fn verify_did_signature_header(
        &self, header: &str, from: &str, body_hash: &str, rcpt_hash: &str,
    ) -> Result<VerifyResult, DidSdkError>;

    pub async fn sign_issue_authorization(
        &self, subject_did: &str, vc_type: &str, vc_hash: &str, timestamp: u64,
    ) -> Result<IssueAuthorizationSignature, DidSdkError>;
}
```

### 1.3 仅 Server

```rust
impl DidSdk<Server> {
    pub fn participant_did(&self) -> &str;

    // 可选本地签名器（ServerConfig.key_vault 配置时）
    pub fn has_signer(&self) -> bool;
    pub async fn sign_with_participant_key(
        &self, message: &[u8], ctx: SigningContext,
    ) -> Result<Signature, DidSdkError>;
    pub fn issue_self_asserted_vc(&self, claims: serde_json::Value)
        -> Result<VerifiableCredential, DidSdkError>;
    pub fn issue_selective_vc(
        &self, claims: serde_json::Value, disclosable: &[String],
    ) -> Result<(VerifiableCredential, Vec<Disclosure>), DidSdkError>;

    pub async fn resolve_did_web(&self, did: &str) -> Result<DidDocument, DidSdkError>;

    pub fn assemble_vc_with_proof(
        &self, claims: serde_json::Value, subject: &str, proof: Proof,
    ) -> Result<VerifiableCredential, DidSdkError>;

    pub async fn verify_vc(&self, vc: &VerifiableCredential)
        -> Result<VcVerificationResult, DidSdkError>;

    pub async fn verify_vp(
        &self, vp: &VerifiablePresentation, expected_challenge: &str,
    ) -> Result<VpVerificationResult, DidSdkError>;
}
```

关键约束：

- Client 不存在 `resolve_did_web` / `assemble_vc_with_proof` / `verify_vc` / `verify_vp`。
- Server 不存在 `generate_did_key` / `generate_did_peer` / `sign_with_did_key` /
  `create_did`；配置 `key_vault` 时可用 `sign_with_participant_key` /
  `issue_self_asserted_vc` / `issue_selective_vc`。
- 生产 Server 不接触参与方签名私钥；`assemble_vc_with_proof` 由外部 `Proof` 注入。

### 1.4 数据模型

```rust
pub struct SigningContext {
    pub purpose: String,
    pub payload_summary: String,
    pub requestor: Option<String>,
}

#[serde(transparent)] pub struct Signature(pub Vec<u8>);
#[serde(transparent)] pub struct Ed25519PublicKey(pub [u8; 32]);
#[serde(transparent)] pub struct IssueAuthorizationSignature(pub Vec<u8>);

pub enum DidMethod { Key, Peer, Web }
pub enum PeerNumalgo { Zero, One, Two }

pub struct DidRecord {
    pub did: String,
    pub method: DidMethod,
    pub doc_hash: Option<String>,
    pub owner: Option<String>,
    pub block_number: Option<u64>,
}

pub enum AddressStatus { Active, Revoked, Expired, Pending }
pub enum IntegrityStatus { Valid, Invalid, Revoked, Expired, Unknown }

pub struct VerifyResult {
    pub verified: bool,
    pub integrity: IntegrityStatus,
    pub address: AddressStatus,
    pub reason: Option<String>,
}

pub struct VcVerificationResult {
    pub verified: bool,
    pub issuer_resolved: bool,
    pub issuer_registered: bool,
    pub reason: Option<String>,
}

pub struct Proof {
    #[serde(rename = "type")] pub type_: String,
    pub created: u64,
    #[serde(rename = "verificationMethod")] pub verification_method: String,
    pub jws: String,
}

pub struct VerifiableCredential {
    #[serde(rename = "@context")] pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")] pub types: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")] pub issuance_date: String,
    #[serde(rename = "expirationDate")] pub expiration_date: Option<String>,
    #[serde(rename = "credentialSubject")] pub credential_subject: serde_json::Value,
    pub proof: Option<Proof>,
    pub anchor_id: Option<String>, // 本地存储键
}

pub struct VerifiablePresentation {
    #[serde(rename = "@context")] pub context: Vec<String>,
    #[serde(rename = "type")] pub types: Vec<String>,
    pub holder: String,
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,
    pub challenge: String,
    pub domain: String,
    pub disclosures: Option<Vec<Disclosure>>, // SD-JWT
    pub proof: Option<Proof>,
}

pub struct Disclosure {
    pub salt: String,             // base64url
    pub name: String,
    pub value: serde_json::Value,
}

pub struct SelectiveVpRequest {
    pub credential: VerifiableCredential,
    pub disclose: Vec<String>,    // 默认空 = 全部隐藏
}

pub struct VpVerificationResult {
    pub verified: bool,
    pub holder_resolved: bool,
    pub credentials: Vec<VcVerificationResult>,
    pub disclosure_count: usize,
    pub reason: Option<String>,
}
```

`Disclosure` 的 JSON 形式固定为 `["<salt>", "<name>", <value>]`。

### 1.5 错误码

```rust
#[derive(Debug, thiserror::Error)]
pub enum DidSdkError {
    #[error("Key generation failed: {0}")] KeyGenerationFailed(String),
    #[error("Signing failed: {0}")] SigningFailed(String),
    #[error("User rejected signing")] UserRejected,
    #[error("User confirmation timeout")] Timeout,
    #[error("Key not found: {0}")] KeyNotFound(String),
    #[error("VC not found: {0}")] VcNotFound(String),
    #[error("DID method not supported in this mode: {0}")] UnsupportedDidMethod(String),
    #[error("DID resolution failed: {0}")] DidResolutionFailed(String),
    #[error("VC verification failed: {0}")] VcVerificationFailed(String),
    #[error("disclosure_hash_mismatch: {0}")] DisclosureHashMismatch(String),
    #[error("disclosure_duplicate: {0}")] DisclosureDuplicate(String),
    #[error("disclosure_missing: {0}")] DisclosureMissing(String),
    #[error("sd_alg_unsupported: {0}")] SdAlgUnsupported(String),
    #[error("Backend unavailable: {0}")] BackendUnavailable(String),
    #[error("Invalid argument: {0}")] InvalidArgument(String),
    #[error("Operation not supported on this platform: {0}")] Unsupported(String),
    #[error("Configuration error: {0}")] ConfigError(String),
}
```

### 1.6 服务端请求响应接口（仅 Client）

```rust
#[async_trait]
pub trait ServerRequestHandler: Send + Sync {
    async fn on_challenge(&self, challenge: &str, requestor: &str)
        -> Result<SignatureResponse, DidSdkError>;
    async fn on_vp_request(&self, credential_types: &[String], challenge: &str)
        -> Result<VpResponse, DidSdkError>;
    async fn on_authorization_request(&self, fields: &[String], purpose: &str, requestor: &str)
        -> Result<AuthorizationResponse, DidSdkError>;
}
```

`SignatureResponse` / `VpResponse` / `AuthorizationResponse` 均包含 `approved: bool` 与
`reason: Option<String>`；拒绝映射为 `DidSdkError::UserRejected`。

---

## 2. 三种 DID 方法

| 方法 | 生成/解析 | 离线验签 | 轮换 |
|---|---|---|---|
| `did:key` | Client 生成；从字符串解码 Ed25519 公钥 | 是 | 换 DID |
| `did:peer:0/2` | Client 生成；公钥内嵌 | 是 | 静态 |
| `did:peer:1` | Client 生成；文档哈希 + 本地文档 | 是（需本地文档） | 静态 |
| `did:web` | Server HTTPS `did.json`；Client 可经 Centralized DID 记录解析 | 需文档 | 文档内轮换 |

POC 的 `did:peer` 编码：

- numalgo 0 / 2：`did:peer:<0|2>z<multibase(0xED01 || key)>`；
- numalgo 1：`did:peer:1z<base58btc(blake2b256(document))>`，文档存本地。

`did:web` URL：

- `did:web:example.com` → `https://example.com/.well-known/did.json`；
- `did:web:example.com:user:alice` → `https://example.com/user/alice/did.json`；
- `%3A` 端口解码。

---

## 3. 配置与构造

### 3.1 Client TOML

```toml
[did_sdk]
mode = "mock"                 # mock / centralized
subject_kind = "client"
vc_storage_path = "./vc_store"
cache_ttl_secs = 600          # Centralized DID 缓存

[did_sdk.key_vault]
scheme = "file-keystore"      # file-keystore / memory-keystore
path = "./identity-keys"
password_env = "DID_SDK_KEYVAULT_PASSWORD"

[did_sdk.centralized]
endpoint = "http://127.0.0.1:8080"
```

### 3.2 Server TOML

```toml
[did_sdk]
mode = "centralized"
subject_kind = "server"
participant_did = "did:web:issuer.example.com:mail"
vc_storage_path = "./participant-vc-store"

# 默认存在；生产可删除或显式 key_vault = None
[did_sdk.key_vault]
scheme = "file-keystore"
path = "./participant-keys"

[did_sdk.centralized]
endpoint = "http://127.0.0.1:8080"
```

**`[did_sdk.chain]` 已删除**；`DID_SDK_CHAIN_ENDPOINT`、`DID_SDK_CHAIN_PALLET` 等不再使用。

### 3.3 工厂

```rust
pub fn build_client_sdk(cfg: &ClientConfig) -> Result<Arc<DidSdk<Client>>, DidSdkError>;
pub fn build_server_sdk(cfg: &ServerConfig) -> Result<Arc<DidSdk<Server>>, DidSdkError>;

pub fn build_client_sdk_with_backend(
    cfg: &ClientConfig, backend: Arc<dyn Backend>, vault: Arc<dyn KeyVault>,
) -> Result<Arc<DidSdk<Client>>, DidSdkError>;
pub fn build_server_sdk_with_backend(
    cfg: &ServerConfig, backend: Arc<dyn Backend>,
) -> Result<Arc<DidSdk<Server>>, DidSdkError>;
```

`ServerConfig.key_vault` 默认 `Some(FileKeystore)`；`key_vault = None` 关闭本地签名器。

### 3.4 环境变量

| 变量 | 覆盖项 |
|---|---|
| `DID_SDK_HOME` | 根目录 |
| `DID_SDK_MODE` | `mock` / `centralized` |
| `DID_SDK_CONFIG_FILE` | TOML 路径 |
| `DID_SDK_VC_STORAGE_PATH` | VC 目录 |
| `DID_SDK_KEYVAULT_SCHEME` | file / memory |
| `DID_SDK_KEYVAULT_PATH` | 密钥目录 |
| `DID_SDK_KEYVAULT_PASSWORD` | 密码 |
| `DID_SDK_KEYVAULT_PASSWORD_FILE` | 密码文件 |
| `DID_SDK_CENTRALIZED_ENDPOINT` | Centralized 端点 |
| `DID_SDK_CACHE_TTL_SECS` | DID 缓存 TTL |
| `DID_SDK_VC_STORAGE_PASSWORD` | 无 KeyVault 时的 VC 加密密码 |

### 3.5 双产物

| 产物 | Client | Server |
|---|---|---|
| Rust | `did-sdk-client` | `did-sdk-server` |
| Python | `did-sdk-client` / `did_sdk` | `did-sdk-server` / `did_sdk_server` |
| Node | `@did-sdk/client` | `@did-sdk/server` |

---

## 4. 后端模式一：Mock

`MockBackend` 进程内维护 DID 记录与确认策略：

```rust
impl MockBackend {
    pub fn new() -> Self;
    pub fn with_auto_confirm(self) -> Self;
    pub fn with_auto_reject(self) -> Self;
    pub fn with_signing_delay(self, ms: u64) -> Self;
    pub async fn insert_did(&self, record: DidRecord);
}
```

无 anchor 预置、无 `get_anchor`。

## 5. 后端模式二：Centralized（只读，可选）

`CentralizedBackend` 只调用：

| 操作 | HTTP |
|---|---|
| `resolve_did(did)` | `GET /dids/{did}` |

DID 解析本地 TTL 缓存（默认 600 秒）。**不提供锚定查询**；锚定核对由验证方 `chain-sdk` 完成。
`did:web` 的 HTTPS 文档解析是 DID 解析，不是链上查询。

## 6. 原 Chain 后端（R1 已删除）

`did-sdk` **不提供 Chain 后端**，不依赖 `subxt` / `scale-value`。需要 Substrate RPC 直连、
锚定查询/写链时使用 `chain-sdk`。验收 D16–D18 强制检查：

- Cargo.toml 与 `cargo tree -p did-sdk` 无 `subxt`；
- 无 `get_anchor` / `ChainBackend`；
- 签名/验签不依赖锚定查询结果。

---

## 7. 私钥管理

### 7.1 Client

- `KeyVault` 管理 `client-did/` 的 Ed25519 密钥；
- POC 使用 `FileKeystore`，密码来自环境变量 / 密码文件 / 自动生成 / 可选交互；
- 私钥不出 `KeyVault`；签名前用户确认，拒绝返回 `UserRejected`。

### 7.2 Server

- 默认 `FileKeystore` 管理 `participant-did/` 的 Ed25519 密钥（开发/测试/试运行）；
- 生产可 `key_vault = None`，由 `chain-sdk` / `chain-owner-sdk` 注入 `Proof`；
- 本地签名器仅用于开发/测试/试运行，生产不得依赖它。

### 7.3 边界

- 两模式都不持链账户私钥，不提交 extrinsic；
- 生产 Server 不接触参与方签名私钥；
- VC 存储密钥与签名私钥分离。

## 8. VC 钱包

| 能力 | Client | Server |
|---|---|---|
| `store_vc` / `get_vc` / `list_vcs` / `remove_vc` | 是 | 是 |
| `build_vp` | 是（本地签名） | 有签名器时签名；否则无 proof |
| `issue_self_asserted_vc` | 是 | 配置本地签名器时可用 |
| `assemble_vc_with_proof` | — | 是（外部 proof） |
| `verify_vc` | — | 是（issuer + proof + 有效期；不做链上锚定） |
| `store_vc_with_disclosures` / `get_vc_with_disclosures` | 是 | 是 |
| `list_disclosable_attributes` | 是 | 是 |
| `build_vp_selective` | 是 | 是（有签名器时签名） |
| `verify_vp` | — | 是 |

### 8.1 VC 静态加密

每个 VC 文件：

```text
DVCS | version | nonce(12) | ciphertext | tag(16)
```

- ChaCha20-Poly1305，AAD 为 `DVCS`；
- 密钥默认复用 KeyVault 密码；无 KeyVault 时使用
  `DID_SDK_VC_STORAGE_PASSWORD` 或自动 `.vc_password`（0600）；
- 文件内保存 `{ vc, disclosures }` 信封，VC 与 Disclosures 绑定；
- 旧明文 VC 读取时自动迁移为密文。

### 8.2 SD-JWT 选择性披露

#### 8.2.1 VC 结构

```json
{
  "credentialSubject": {
    "id": "did:key:zHolder",
    "idCardNumber": "110101...",
    "_sd": ["<base64url hash>", "..."],
    "_sd_alg": "sha-256"
  }
}
```

- 必须披露属性保持明文；
- 可披露属性被移入 `_sd`；
- VC proof 覆盖含 `_sd` 的 VC 内容（当前实现通过 `vc_signing_input` 的 VC hash 绑定）。

#### 8.2.2 Disclosure 与哈希

```text
Disclosure = [salt, name, value]
H = SHA-256( base64url(salt) || base64url(name) || base64url(value) )
```

- 每张 VC、每个属性独立 16 字节 CSPRNG 盐；
- `base64url` 无 padding；
- `_sd` 存 `H` 的 base64url，`_sd_alg = "sha-256"`；
- `Disclosure` 不放入 VC 原文，与 VC 同信封加密存储。

#### 8.2.3 签发

```rust
let (vc, disclosures) = sdk.issue_selective_vc(claims, &["name".into(), "gender".into()])?;
sdk.store_vc_with_disclosures(vc, disclosures).await?;
```

Client 与配置了本地签名器的 Server 都支持。

#### 8.2.4 出示

```rust
let vp = sdk.build_vp_selective(
    vec![SelectiveVpRequest {
        credential: vc,
        disclose: vec!["name".into()], // 空 = 全部隐藏
    }],
    "challenge",
    "example.com",
).await?;
```

- 只发送用户选中的 Disclosure；
- VP 的 `disclosures` 字段存在（可为空数组）；
- 签名对象为 `vp_sd_v1`：

```text
VP-SD-v1
{holder}
{challenge}
{domain}
{disclosures_hash}
{vc_hash_1}
{vc_hash_2}
...
```

`disclosures_hash` = Disclosures 数组 canonical JSON 的 SHA-256（hex）；
`vc_hash` = 完整 VC JSON 的 SHA-256（hex）。

#### 8.2.5 验证

`DidSdk<Server>::verify_vp` 顺序：

1. `challenge` 与期望值一致；
2. holder 对 `vp_sd_v1` 的签名；
3. 每个 VC 的 issuer proof / 有效期；
4. 每条 Disclosure 重算哈希，命中某个 VC 的 `_sd`；
5. 拒绝重复属性名；
6. 拒绝不支持的 `_sd_alg`；
7. 锚定/撤销由 `chain-sdk` 另行查询。

错误码：`disclosure_hash_mismatch`、`disclosure_duplicate`、
`disclosure_missing`、`sd_alg_unsupported`。

#### 8.2.6 隐私边界

- **能防**：未披露属性不可见、篡改/伪造、跨 VC 关联、字典攻击；
- **不能防**：同一 VC 跨出示关联、多个验证方合谋拼接、验证方长期存储；
- 需要强不可关联/谓词证明时升级 BBS+；当前不引入。

---

## 9. 两种后端对比

| 维度 | Mock | Centralized |
|---|---|---|
| 外部依赖 | 无 | 中心化服务进程（可选） |
| 配置 | `mode="mock"` | `mode="centralized"` + endpoint |
| 私钥存储 | 内存 | `FileKeystore` |
| 链访问 | 无 | HTTP 只读 DID 解析 |
| 适用阶段 | 单元测试 | 集成测试、试生产 |
| 应用代码改动 | 零 | 零 |

## 10. 安全约束

| 约束 | 说明 |
|---|---|
| 类型参数隔离 | 非法模式调用编译失败 |
| Client 私钥不出 KeyVault | FileKeystore 加密文件 |
| Client 签名前用户确认 | 拒绝返回 `UserRejected` |
| Server 生产不持签名私钥 | 外部 `Proof` 注入 |
| 不持链账户私钥 | 不提交 extrinsic |
| 无链上查询 | 无 `get_anchor` / Chain / `subxt` |
| VC + Disclosures 加密 | `DVCS` 密文，KeyVault 密码派生 |
| SD 哈希覆盖 | `vp_sd_v1` 覆盖 VC 哈希 + Disclosures 哈希 |

---

## 11. 验收清单

### 11.1 did-sdk

| 编号 | 验收项 | 通过标准 |
|---|---|---|
| D1 | 接口契约完整 | 三种 DID 方法、VC 钱包、SD-JWT |
| D2 | 类型参数隔离 | Client/Server 非法方法编译失败 |
| D3 | 两后端切换 | `mode` = mock / centralized |
| D4 | 两后端语义一致 | 同一操作结果/错误码一致 |
| D5 | 三种 DID 方法 | key / peer:0/1/2 / web |
| D6 | Mock 确认策略 | 自动确认/拒绝/延迟 |
| D7 | Centralized 只读 | 只 GET DID |
| D8 | 无 Chain / 无 subxt | Cargo.toml + 依赖树检查 |
| D9 | Client 私钥安全 | KeyVault + 用户确认 |
| D10 | 无链账户私钥 | 不提交 extrinsic |
| D11 | keyvault-core 集成 | client-did / participant-did |
| D12 | VC 钱包统一 | 两模式同一语义 |
| D13 | Server 生产不持签名私钥 | 外部 proof |
| D14 | 两后端一致性测试 | Mock / Centralized |
| D15 | verify_vc | issuer + proof + 有效期 |
| D16 | 无 subxt 依赖 | Cargo.toml / cargo tree |
| D17 | 无 get_anchor | 无链上查询接口 |
| D18 | 锚定职责边界 | 签名/验签不读取锚定 |

### 11.2 SD-JWT

| 编号 | 验收项 | 通过标准 |
|---|---|---|
| I1–I6 | 签发 | 盐、`_sd`、独立盐、Disclosure、加密交付 |
| SD-D1–D5 | 出示 | 绑定存储、选择、筛选、VP 字段、签名覆盖 |
| V1–V7 | 验证 | holder/VC 签名、哈希、隐藏、篡改、重复 |
| P1–P3 | 隐私 | 跨 VC 盐不同、同 VC 可关联、字典防护 |

### 11.3 发布形态

| 编号 | 验收项 | 通过标准 |
|---|---|---|
| S1 | Linux musl 静态 | `statically linked` |
| S2 | UserRejected 三语言 | Rust/Python/Node |
| S3 | 双产物矩阵 | Python/Node 各 5 平台 × Client/Server |

---

## 12. 交付物

1. `did-sdk` core（两模式、两后端、三种 DID 方法、VC 钱包、SD-JWT）；
2. `did-sdk-client` / `did-sdk-server` 产品 crate；
3. `did-sdk-client` / `did-sdk-server` Python wheel；
4. `@did-sdk/client` / `@did-sdk/server` Node addon；
5. `keyvault-core`（namespace、SS58、FileKeystore v2、SD 工具、9 个签名输入）；
6. 测试套件（D1–D18、I/D/V/P、三语言向量）；
7. 文档：本规格、`04-keyvault-core_crate规格书1.md`、SD 附件与互操作约定。

## 13. 与其它文档的关系

| 文档 | 关系 |
|---|---|
| `04-keyvault-core_crate规格书1.md` | 密钥、namespace、SS58、SD 哈希工具 |
| 《ChainSdk 规格书》 | `chain-sdk` 装配 Server 模式，承担锚定查询/写链 |
| 《ChainOwnerSdk 规格书》 | 装配 Server 模式用于持有侧 VC 与 DID 解析 |
| 《VC 选择性披露特性补充附件》 | SD-JWT 设计与隐私边界 |
| `docs/selective-disclosure-interop.md` | 与 chain-sdk 的字节级约定 |

## 14. 实现同步

- 代码提交 `ffd59fd`；CI：`ci` 43268561991、`rust-musl` 43268561636、
  `python` 43268561958、`node` 43268561892、`cross-lang` 43268561597。
- 测试：keyvault-core 28、did-sdk 55、Python 13、Node 11。
- 首个 Release `v0.1.0` 不包含 SD-JWT；SD 能力在 `main`。
