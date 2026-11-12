# DidSdk 接口契约与实现规格书
## DID 方法 + VC 钱包的统一能力层：Client / Server 两种运行模式，两种后端（R1）

> **同步状态（2026-11-12）**：本文档已按 R1 修订与当前代码同步：
> 移除 `Chain` 后端、`get_anchor` 与 `subxt`/`scale-value` 依赖；`Mock` / `Centralized` 两后端。
> Server 默认 `FileKeystore` 本地签名器（可关闭）；VC 密文存储；Client/Server 双产物。
> 锚定查询由验证方的 `chain-sdk` 完成，`did-sdk` 不承担链上查询。

## 0. 定位与设计原则

### 0.1 定位

`did-sdk` 是 DID 方法与 VC 钱包的统一能力层。独立身份客户端、`aimail-sdk`、其他客户端应用直接依赖它；`chain-sdk` 按角色装配它的能力子集。

它同时支持三种 DID 方法（`did:key`、`did:peer`、`did:web`）和 VC 签发/存储管理，通过类型参数在编译期区分两种运行模式；**不承担链上查询，不依赖 `subxt`**：

| 运行模式 | 典型使用者 | DID 方法 | 签名私钥 | VC 能力 |
|---|---|---|---|---|
| `DidSdk<Client>` | 客户端应用、`aimail-sdk` | `did:key` / `did:peer` | 设备安全区（`KeyVault`） | 完整（签发 + 持有 + 呈现） |
| `DidSdk<Server>` | 被 `chain-sdk` / `chain-owner-sdk` 装配到服务端 | 固定 `did:web` | 生产不持有；开发/测试/试运行可选 `FileKeystore` | 持有侧（存储/查询参与方收到的 VC）；本地签名器可签发 |

### 0.2 设计原则

1. 两种运行模式用类型参数编译期二选一。`DidSdk<Client>` 与 `DidSdk<Server>` 是不同类型，非法方法在类型检查阶段被拒绝。不用 Cargo feature 表达互斥模式（feature 为 additive，会在下游依赖图引入静默冲突）。
2. 两种后端模式（Mock / Centralized）与两种运行模式正交。同一运行模式可选择任一后端，改配置并重启。`did-sdk` 不提供 `Chain` 后端。
3. 应用使用 `DidSdk<Client>` / `DidSdk<Server>` 具体类型（当前实现无 `dyn DidSdkApi`），具体模式类型在构造时确定。
4. VC 管理统一。无论 `Client` 还是 `Server`，VC 的存储/查询/生命周期语义只有一套。
5. 签名私钥安全域不可跨越。`Client` 模式下签名私钥在设备安全区；`Server` 默认可用 `FileKeystore` 本地签名器（开发/测试/试运行），生产可配置 `key_vault = None`，由注入的 `Signer` 完成签发。
6. 服务端参与方的身份是 `did:web`，由 `chain-sdk` / `chain-owner-sdk` 装配时锁定；`DidSdk<Server>` 不生成 DID。
7. **客户端不承担链上查询**。`DidSdk` 不暴露 `get_anchor`，不依赖 `subxt`；锚定状态核对由验证方 `chain-sdk` 完成。

### 0.3 两种后端模式

| 模式 | 后端 | 部署形态 | 适用阶段 |
|---|---|---|---|
| `Mock` | 进程内状态 | 无外部依赖 | 单元测试 |
| `Centralized` | 中心化模拟链 | 独立 HTTP 服务 | 集成测试、试生产；可选锚定预览 |

## 1. 类型参数与模式

```rust
pub trait SdkMode: Send + Sync + 'static {}
pub struct Client;
pub struct Server;
impl SdkMode for Client {}
impl SdkMode for Server {}

pub struct DidSdk<M: SdkMode> {
    backend: Box<dyn Backend>,
    vault: Option<Arc<dyn KeyVault>>,   // Client 必有；Server 默认 Some(FileKeystore)，可关闭
    _mode: PhantomData<M>,
}
```

### 1.1 模式特定能力（编译期隔离）

```rust
// ===== 两种模式共享 =====
impl<M: SdkMode> DidSdk<M> {
    pub fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError>;
    // get_anchor 已移除：锚定查询归属 chain-sdk（Verifier）

    // VC 钱包（持有侧，两模式共享）
    pub async fn store_vc(&self, vc: VerifiableCredential) -> Result<(), DidSdkError>;
    pub async fn get_vc(&self, anchor_id: &str) -> Result<Option<VerifiableCredential>, DidSdkError>;
    pub async fn list_vcs(&self) -> Result<Vec<VerifiableCredential>, DidSdkError>;
    pub async fn remove_vc(&self, anchor_id: &str) -> Result<(), DidSdkError>;
    pub async fn build_vp(
        &self, vcs: Vec<VerifiableCredential>, challenge: &str, domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError>;
}

// ===== 仅 Client：本地密钥、用户确认式签名 =====
impl DidSdk<Client> {
    pub fn generate_did_key(&self) -> Result<String, DidSdkError>;
    pub fn generate_did_peer(&self, numalgo: PeerNumalgo) -> Result<String, DidSdkError>;
    pub async fn sign_with_did_key(
        &self, message: &[u8], ctx: SigningContext,
    ) -> Result<Signature, DidSdkError>;
    pub fn resolve_did_key(&self, did: &str) -> Result<Ed25519PublicKey, DidSdkError>;
    pub fn resolve_did_peer(&self, did: &str) -> Result<DidDocument, DidSdkError>;
    pub fn create_did(&self) -> Result<DidRecord, DidSdkError>;

    pub fn issue_self_asserted_vc(
        &self, claims: serde_json::Value,
    ) -> Result<VerifiableCredential, DidSdkError>;

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

// ===== 仅 Server：did:web 解析、持有侧、签名注入 =====
impl DidSdk<Server> {
    // 不生成 DID；did:web 由运维预先部署，由 chain-sdk / chain-owner-sdk 注入
    pub fn participant_did(&self) -> &str;

    // 可选本地签名器（开发/测试/试运行；key_vault 配置时）
    pub fn has_signer(&self) -> bool;
    pub async fn sign_with_participant_key(
        &self, message: &[u8], ctx: SigningContext,
    ) -> Result<Signature, DidSdkError>;
    pub fn issue_self_asserted_vc(
        &self, claims: serde_json::Value,
    ) -> Result<VerifiableCredential, DidSdkError>;

    // did:web 解析（HTTPS 文档）
    pub async fn resolve_did_web(&self, did: &str) -> Result<DidDocument, DidSdkError>;

    // 组装 VC（proof 由外部 Signer 注入；did-sdk 不持有参与方签名私钥）
    pub fn assemble_vc_with_proof(
        &self, claims: serde_json::Value, subject: &str, proof: Proof,
    ) -> Result<VerifiableCredential, DidSdkError>;

    // 校验他人 VC（验 issuer 签名 + 有效期；不做链上锚定查询）
    pub async fn verify_vc(
        &self, vc: &VerifiableCredential,
    ) -> Result<VcVerificationResult, DidSdkError>;
}
```

关键约束：

- `DidSdk<Client>` 在类型层面不存在服务端专用方法（`resolve_did_web` / `assemble_vc_with_proof` / `verify_vc`）。
- `DidSdk<Server>` 在类型层面不存在本地生成 DID 方法（`generate_did_key` / `generate_did_peer` / `sign_with_did_key`）；配置本地签名器时提供 `sign_with_participant_key` / `issue_self_asserted_vc` 用于开发/测试/试运行。
- `assemble_vc_with_proof` 接受已签好的 `Proof`，签名字节由调用方（`chain-sdk` / `chain-owner-sdk` 的 `Signer`）产生。生产环境 `did-sdk` 不接触参与方签名私钥；开发/测试/试运行可配置 `FileKeystore`。

### 1.2 数据模型

```rust
pub struct SigningContext {
    pub purpose: String,
    pub payload_summary: String,
    pub requestor: Option<String>,
}

pub struct Signature(pub Vec<u8>);
pub struct Ed25519PublicKey(pub [u8; 32]);
pub struct IssueAuthorizationSignature(pub Vec<u8>);

pub struct DidRecord {
    pub did: String,
    pub method: DidMethod,        // Key / Peer / Web
    pub doc_hash: Option<String>, // did:key 无文档哈希；did:web 为文档哈希
    pub owner: Option<String>,
    pub block_number: Option<u64>,
}

pub enum DidMethod { Key, Peer, Web }
pub enum PeerNumalgo { Zero, One, Two }

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
    pub anchor_valid: bool,
    pub reason: Option<String>,
}

pub struct Proof {
    pub type_: String,
    pub created: u64,
    pub verification_method: String,
    pub jws: String,
}
```

### 1.3 错误码

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
    #[error("Backend unavailable: {0}")] BackendUnavailable(String),
    #[error("Invalid argument: {0}")] InvalidArgument(String),
}
```

### 1.4 服务端请求响应接口（仅 Client）

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

`Server` 模式无交互式用户，不实现该 trait。

## 2. 三种 DID 方法

| 方法 | 模式 | 解析方式 | 离线验签 | 轮换 |
|---|---|---|---|---|
| `did:key` | Client | 从 DID 字符串解码公钥 | 是，零网络 | 换 DID |
| `did:peer:0/2` | Client | 公钥内嵌于 DID | 是，零网络 | 静态 |
| `did:peer:1` | Client | DID 为创世文档哈希，需文档（可随凭证携带）本地重建验证 | 是，零网络 | 静态 |
| `did:web` | Server（亦可供 Client 解析他人 DID） | HTTPS 获取 `/.well-known/did.json` 或路径映射文档 | 否，需网络 | 文档内轮换，DID 不变 |

`did:peer` 的能力与局限：离线验签成立（`0/2` 内嵌公钥、`1` 文档哈希自包含），但解析限定参与方之间，不可公开发现；numalgo 4 静态不支持轮换。POC 不默认启用，仅作为客户端未来选项记录。

`did:web` 的依赖与风险：解析依赖 DNS + TLS，继承域名声誉；共享托管、域名过期、证书疏忽会削弱控制保证。Server 模式固定 `did:web`，由 `chain-sdk` / `chain-owner-sdk` 装配时锁定。

## 3. 配置与构造

```toml
# Client（客户端）
[did_sdk]
mode = "centralized"          # 后端：mock / centralized
subject_kind = "client"
vc_storage_path = "./vc_store"

[did_sdk.key_vault]
scheme = "file-keystore"
path = "./identity-keys"
password_env = "DID_KEYSTORE_PASSWORD"

[did_sdk.centralized]
endpoint = "http://localhost:8080"
```

```toml
# Server（服务端，由 chain-sdk / chain-owner-sdk 装配）
[did_sdk]
mode = "centralized"
subject_kind = "server"
participant_did = "did:web:issuer.example.com:mail"
vc_storage_path = "./participant-vc-store"
# 默认启用 FileKeystore 本地签名器；生产可 key_vault = None
```

工厂函数：

```rust
pub fn build_client_sdk(cfg: &ClientConfig) -> Result<Arc<DidSdk<Client>>, ConfigError>;
pub fn build_server_sdk(cfg: &ServerConfig) -> Result<Arc<DidSdk<Server>>, ConfigError>;
```

同一个编译产物，后端模式改 `mode` 并重启；运行模式由构造时调用的工厂函数决定（类型参数）。

## 4. 后端模式一：Mock

`MockBackend` 进程内维护链状态预置、VC 存储（内存）。语义与真实实现一致。

```rust
impl MockBackend {
    pub fn with_auto_confirm(&mut self) -> Self;          // 仅 Client
    pub fn with_auto_reject(&mut self) -> Self;            // 仅 Client
    pub fn with_signing_delay(&mut self, ms: u64) -> Self; // 仅 Client
}
```

## 5. 后端模式二：Centralized

`CentralizedBackend` 通过 HTTP 访问中心化模拟链单一端点，只调只读接口：

| 操作 | HTTP |
|---|---|
| `resolve_did(did)` | `GET /dids/{did}` |

DID 解析本地 TTL 缓存（默认 600 秒）。`did:web` 解析直连 HTTPS，不经中心化服务。
**不提供锚定查询**；锚定核对由验证方 `chain-sdk` 完成。

## 6. 原 Chain 后端（R1 已删除）

**`did-sdk` 不提供 `Chain` 后端，也不依赖 `subxt` / `scale-value`。** 需要 Substrate RPC 直连或锚定查询/写链的场景，使用 `chain-sdk`（Verifier）的 Chain 后端。

## 7. 私钥管理

### 7.1 Client 模式

- 通过 `keyvault-core` 的 `KeyVault` trait 管理 `did:key` / `did:peer` 私钥；POC 用 `FileKeystore`。
- 加密文件存于 `path`，启动用 `password_env` 解锁。
- 签名在内存完成，私钥不出 `KeyVault`。
- 签名前必须用户确认（`ServerRequestHandler` 或 UI 回调），拒绝返回 `UserRejected`。
- 生产演进 `keyvault-device`（Keychain / Keystore / TPM / Secure Enclave）。

### 7.2 Server 模式

- 生产环境 `did-sdk` 不持有参与方签名私钥，`key_vault = None`。
- 开发/测试/试运行默认 `FileKeystore` 本地签名器（`participant-did/`），可直接签发 VC。
- 生产环境参与方的 `did:web` 私钥由 `chain-sdk` / `chain-owner-sdk` 在服务端安全域管理。
- 签发 VC 时，签名由调用方注入 `Proof`（`assemble_vc_with_proof`）。
- 持有侧 VC 存储默认复用 KeyVault 密码加密（`DVCS` 密文）；无 KeyVault 时使用 `DID_SDK_VC_STORAGE_PASSWORD` / 自动 `.vc_password`。

### 7.3 边界

- `did-sdk<Client>` 只管理客户端设备安全区密钥，永不接触链账户私钥。
- 生产 `DidSdk<Server>` 不接触任何签名私钥；开发/测试/试运行可配置 `FileKeystore`。
- VC 存储在 `did-sdk`，签名私钥在各自安全域，二者分离。

## 8. VC 钱包

两种模式共享一套 VC 存储语义：

| 能力 | Client | Server |
|---|---|---|
| `store_vc` | 是 | 是（参与方接收的资质 VC） |
| `get_vc` / `list_vcs` / `remove_vc` | 是 | 是 |
| `build_vp` | 是 | 有本地签名器时签名；否则无 proof |
| `issue_self_asserted_vc` | 是（本地签名） | 配置本地签名器时可用 |
| `assemble_vc_with_proof` | — | 是（外部 proof 注入） |
| `verify_vc` | 可经 `resolve_did` 实现 | 是（issuer 解析 + 签名 + 有效期；不做链上锚定查询） |

存储加密密钥默认复用 `KeyVault` 密码（Server 默认 `FileKeystore`）；无 KeyVault 时使用 `DID_SDK_VC_STORAGE_PASSWORD` 或自动 `.vc_password`。文件为 `DVCS` 密文。

## 9. 两种后端模式对比

| 维度 | Mock | Centralized |
|---|---|---|
| 外部依赖 | 无 | 中心化服务进程（可选） |
| 配置项 | `mode="mock"` | `mode="centralized"`+`endpoint` |
| 私钥存储（Client） | 内存 | `FileKeystore` |
| 链访问 | 无 | HTTP 只读 DID 解析（可选锚定预览） |
| 信任模型 | 信任测试代码 | 信任服务运营方 |
| 适用阶段 | 单元测试 | 集成测试、试生产 |
| 应用代码改动 | 零 | 零 |

## 10. 安全约束

| 约束 | 说明 |
|---|---|
| 两种运行模式编译期隔离 | 类型参数，非法调用在类型检查阶段被拒绝 |
| Client 私钥不出 `KeyVault` | POC 在 `FileKeystore` 加密文件；生产在设备安全区 |
| Client 签名前用户确认 | 用户拒绝返回 `UserRejected` |
| Server 不持签名私钥 | 签发通过注入 `Proof` 完成 |
| 不接触链账户私钥 | 两种模式均不持有链账户私钥；不提交 extrinsic |
| 不承担链上查询 | 无 `get_anchor`、无 `Chain` 后端、无 `subxt`；锚定核对归 `chain-sdk` |
| VC 存储加密 | 密钥由 `KeyVault` 或注入的存储密钥派生 |

## 11. 验收清单

| 编号 | 验收项 | 通过标准 |
|---|---|---|
| D1 | 接口契约完整 | 覆盖三种 DID 方法、VC 钱包；不承担链上查询 |
| D2 | 类型参数编译期隔离 | `DidSdk<Client>` 无服务端专用方法；`DidSdk<Server>` 无本地生成密钥方法；非法调用编译失败 |
| D3 | 两后端模式切换 | 同一二进制经 `mode` 字段在 mock / centralized 间切换，需重启 |
| D4 | 两后端语义一致 | 同一操作结果与错误码一致 |
| D5 | 三种 DID 方法 | `did:key` 离线可验；`did:peer:0/1/2` 离线可验；`did:web` 可解析 |
| D6 | Mock 自动确认/拒绝/延迟 | 仅 Client 可配置 |
| D7 | Centralized 只读 | 只调中心化服务只读接口（DID 解析） |
| D8 | 无 Chain 后端/无 subxt | `cargo tree -p did-sdk` 无 subxt；无 Chain 后端 |
| D9 | Client 私钥安全 | 私钥不出 `KeyVault`；签名前用户确认 |
| D10 | 零链账户私钥 | 两模式均不持链账户私钥，不提交 extrinsic |
| D11 | `keyvault-core` 集成 | Client 经 `FileKeystore` 管理密钥 |
| D12 | VC 钱包统一 | 两种模式同一套 store/get/list/remove/build_vp 语义 |
| D13 | Server 生产不持签名私钥 | `assemble_vc_with_proof` 接受外部 proof；开发/测试可配置 FileKeystore |
| D14 | 一致性测试 | 同一用例在两后端下结果一致 |
| D15 | Server 校验他人 VC | `verify_vc` 校验 issuer 签名/有效期/注册状态；不做链上锚定查询 |
| D16 | 无 `subxt` 依赖 | `cargo tree -p did-sdk` 与 Cargo.toml 均无 subxt |
| D17 | 无链上查询接口 | 无 `get_anchor`、无 ChainBackend |
| D18 | 锚定职责边界 | 签名/验签不依赖锚定查询结果 |

## 12. 交付物

1. `did-sdk` crate 源码（类型参数两模式、Mock/Centralized 两后端、三种 DID 方法、VC 钱包）；
2. `SdkMode` / `Client` / `Server` 类型定义；
3. 数据模型与错误码；
4. 配置文件示例（Client / Server × 两后端）；
5. 工厂函数；
6. `keyvault-core` 集成（Client）；
7. `did:key` / `did:peer` / `did:web` 解析与签名实现；
8. `DID-Signature` 头构造实现；
9. VC 钱包（两模式共享 + Server 注入 proof + Server 校验他人 VC）；
10. 一致性测试套件；
11. 验收记录（D1–D18）；
12. Client / Server 双产物（Rust crate / Python wheel / Node addon）。

## 13. 与其它文档的关系

| 文档 | 关系 |
|---|---|
| 文档一：总体架构与任务书 | 本文档是其配套规格书 |
| 文档三：ChainSdk 规格书 | `chain-sdk` 按角色装配本 crate 的能力子集 |
| 文档四：ChainOwnerSdk 规格书 | `chain-owner-sdk` 装配本 crate 的 Server 模式用于持有侧 VC 管理与 DID 解析 |
| 文档五：keyvault-core 规格书 | Client 依赖其 `KeyVault` trait |
| 文档七：中心化模拟链规格书 | `CentralizedBackend` 访问其只读接口 |
