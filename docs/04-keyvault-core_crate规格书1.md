# keyvault-core crate 规格书
## 私钥管理共享 crate：KeyVault trait + FileKeystore 实现 + 多 namespace 隔离

> **同步状态（2026-11-13）**：本文档与当前代码同步。已实现三 namespace
> （`chain-account/`、`participant-did/`、`client-did/`）、Ed25519/Sr25519、
> SS58、FileKeystore v2（`.enc` + index v2）、`sign_checked`、`sd` 盐化哈希工具与 9 个签名输入（含 vp_v1 / vp_sd_v1）。
> 详见 `docs/implementation-report.md` 与 `docs/acceptance-checklist.md`。

## 0. 定位与设计原则

### 0.1 定位

`keyvault-core` 是**私钥管理共享 crate**，被 `did-sdk`、`chain-sdk`、`chain-owner-sdk` 共同依赖。它提供：

- **`KeyVault` trait**：统一的私钥管理抽象；
- **`FileKeystore` 实现**：POC 阶段加密落盘实现；
- **`MemoryKeystore`**：测试 / Mock / 显式内存模式，不落盘；
- **namespace 隔离机制**：强制区分服务端两类密钥（链账户 / 参与方 did）；
- **密码学原语**：Ed25519、sr25519、base58、multibase；
- **签名对象构造**：`DID-Signature` 七行、`IssuedVc` 五行等协议层构造函数。

### 0.2 设计原则

1. **抽象统一，实现分离**。`KeyVault` trait 统一；POC 提供 `FileKeystore` 与 `MemoryKeystore`；未来扩展 `keyvault-device`（设备安全区）和 `keyvault-server`（KMS/HSM）作为额外 crate。
2. **私钥永不离开 `KeyVault`**。`KeyVault::sign` 只返回签名结果，不返回私钥。
3. **namespace 强制隔离**。服务端两类密钥（`chain-account/` 链账户 sr25519、`participant-did/` 参与方 did:web ed25519）物理隔离，跨 namespace 调用被拒绝。
4. **签名对象构造与存储无关**。`signing_input` 模块的构造函数接收参数，返回待签名字节，不涉及存储。
5. **POC 阶段加密落盘只做 `FileKeystore`**；`MemoryKeystore` 仅用于测试/Mock。设备安全区和 KMS/HSM 的实现留待生产阶段扩展。

### 0.3 依赖关系

```text
did-sdk ─────────┐
chain-sdk ───────┼──► keyvault-core（KeyVault trait + FileKeystore + namespace）
chain-owner-sdk ─┘
```

### 0.4 两类密钥与 namespace

| namespace | 密钥类型 | 持有方 | 用途 |
|---|---|---|---|
| `chain-account/` | sr25519 | 服务端参与方（含链主） | 签 extrinsic、Centralized 请求体 |
| `participant-did/` | ed25519 | 服务端参与方（含链主） | 签治理声明、VC、参与方断言 |
| `client-did/` | ed25519 | 客户端用户 | 签 DID-Signature、VP、授权声明（仅 `did-sdk<Client>`） |

**POC 阶段**：`keyvault-core` 不区分调用方主体，namespace 由 `KeyId` 前缀表达，由调用方（`chain-sdk` / `chain-owner-sdk` / `did-sdk`）通过 `KeyVault` 使用；跨 namespace 签名调用由 `KeyVault` 内部校验拒绝。

## 1. `KeyVault` trait

```rust
#[async_trait]
pub trait KeyVault: Send + Sync {
    /// 生成新密钥对。algorithm 由调用方指定，返回带 namespace 前缀的 KeyId。
    async fn generate(
        &self,
        namespace: KeyNamespace,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyId, KeyVaultError>;

    /// 加载已有密钥
    async fn load(&self, key_id: &KeyId) -> Result<(), KeyVaultError>;

    /// 对任意字节签名；私钥在 KeyVault 内部使用，不返回。
    /// 实现强制校验 key_id 的 namespace 与 algorithm 一致。
    async fn sign(
        &self,
        key_id: &KeyId,
        payload: &[u8],
    ) -> Result<Signature, KeyVaultError>;

    /// 获取公钥
    async fn public_key(&self, key_id: &KeyId) -> Result<PublicKey, KeyVaultError>;

    /// 列出所有 KeyId（可按 namespace 过滤）
    async fn list_keys(&self, namespace: Option<KeyNamespace>)
        -> Result<Vec<KeyId>, KeyVaultError>;

    /// 删除密钥（POC 阶段可选）
    async fn delete(&self, key_id: &KeyId) -> Result<(), KeyVaultError>;

    /// 内部方法：按 namespace + algorithm 预期校验 key_id 并签名。
    /// chain-sdk / chain-owner-sdk 不直接调用，由 ParticipantSigner 封装调用。
    async fn sign_checked(
        &self,
        key_id: &KeyId,
        payload: &[u8],
        expected_namespace: KeyNamespace,
        expected_algorithm: KeyAlgorithm,
    ) -> Result<Signature, KeyVaultError>;
}

/// namespace 前缀
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyNamespace {
    ChainAccount,     // "chain-account/"
    ParticipantDid,   // "participant-did/"
    ClientDid,        // "client-did/"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
    Sr25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(pub String);
// 格式："{namespace_prefix}{local_id}"
// 例：
//   chain-account/chain-owner-operator
//   participant-did/did_web_identity_example_com
//   client-did/did_key_z6Mk...

#[derive(Debug, Clone)]
pub struct Signature(pub Vec<u8>);

#[derive(Debug, Clone)]
pub enum PublicKey {
    Ed25519([u8; 32]),
    Sr25519([u8; 32]),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyVaultError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),
    #[error("Invalid password")]
    InvalidPassword,
    #[error("KeyVault locked")]
    Locked,
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("Namespace violation: key {key} is {actual:?}, expected {expected:?}")]
    NamespaceViolation {
        key: String,
        actual: KeyNamespace,
        expected: KeyNamespace,
    },
    #[error("Algorithm mismatch: key {key} is {actual:?}, expected {expected:?}")]
    AlgorithmMismatch {
        key: String,
        actual: KeyAlgorithm,
        expected: KeyAlgorithm,
    },
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Operation not supported on this platform")]
    Unsupported,
    #[error("User rejected signing")]
    UserRejected,
}
```

### 1.1 namespace 与算法的强制映射

`KeyVault` 实现层**强制**以下映射，任何不一致的调用返回错误：

| namespace | 唯一允许的 algorithm |
|---|---|
| `ChainAccount` | `Sr25519` |
| `ParticipantDid` | `Ed25519` |
| `ClientDid` | `Ed25519` |

- `generate(namespace, algorithm)` 时校验组合合法，否则 `AlgorithmMismatch`。
- `sign(key_id, payload)` 时根据 `key_id` 前缀推断 namespace，再与存储中记录的 algorithm 比对；不一致时拒绝。
- `sign_checked(key_id, payload, expected_ns, expected_alg)` 由 `ParticipantSigner` / `DidSdk` 调用，拒绝跨 namespace 使用：
  - `chain-sdk` 的 `sign_extrinsic` 传 `expected_ns = ChainAccount`；
  - `chain-sdk` / `chain-owner-sdk` 的 `sign_participant_assertion` 传 `expected_ns = ParticipantDid`；
  - `did-sdk<Client>` 的 `sign_with_did_key` 传 `expected_ns = ClientDid`。

**这三个调用入口是三段式硬绑定在 SDK 层的落点**：服务端无法把 `participant-did/` 的密钥用于 extrinsic 签名，也无法把 `chain-account/` 的密钥用于 did 断言签名。

## 2. `FileKeystore` / `MemoryKeystore` 实现

### 2.1 存储布局

`FileKeystore` 将加密的密钥对存储在指定目录下；`MemoryKeystore` 使用进程内 `HashMap`，接口相同但不加密落盘。

`FileKeystore` 按 namespace 分子目录，每个密钥一个文件：

```text
./keystore/
├── index.json
├── chain-account/
│   └── chain-owner-operator.enc
├── participant-did/
│   ├── did_web_identity_example_com.enc
│   └── did_web_mail_example_com.enc
└── client-did/
    └── did_key_z6Mk....enc
```

`index.json` 记录每个 `KeyId` 的 `{namespace, algorithm, filename, created_at}`，用于快速定位和算法校验。

### 2.2 加密文件格式

```text
[magic: 4 bytes "KVLT"]
[version: 1 byte]
[namespace: 1 byte (0x01 = ChainAccount, 0x02 = ParticipantDid, 0x03 = ClientDid)]
[algorithm: 1 byte (0x01 = Ed25519, 0x02 = Sr25519)]
[salt: 16 bytes]
[nonce: 12 bytes]
[ciphertext: variable]
[tag: 16 bytes]
```

- **加密算法**：ChaCha20-Poly1305（AEAD）；
- **KDF**：Argon2id（密码 + salt → 32 字节密钥）；
- **明文**：密钥对私钥 32 字节（外加派生信息）。

`FileKeystore` 解锁时校验文件头的 namespace/algorithm 与 `index.json` 记录一致，不一致即拒绝加载。

### 2.3 实现要点

```rust
pub struct FileKeystore {
    path: PathBuf,
    password: SecretString,
    unlocked: RwLock<HashMap<KeyId, (KeyNamespace, KeyAlgorithm, Keypair)>>,
    index: RwLock<KeystoreIndex>,
}

impl FileKeystore {
    pub fn new(path: PathBuf, password: SecretString) -> Result<Self, KeyVaultError> {
        // 创建目录、加载索引、用密码解锁所有密钥到内存
        // 解锁时逐个校验文件头与索引的 namespace/algorithm 一致
    }
}

#[async_trait]
impl KeyVault for FileKeystore {
    async fn generate(
        &self,
        namespace: KeyNamespace,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyId, KeyVaultError> {
        // 1. 校验 namespace × algorithm 组合合法（查 §1.1 映射表）
        // 2. 按 algorithm 生成密钥对
        // 3. 写入 namespace 子目录下的加密文件
        // 4. 更新索引
        // 5. 加入 unlocked 缓存
    }

    async fn sign(&self, key_id: &KeyId, payload: &[u8]) -> Result<Signature, KeyVaultError> {
        // 从 unlocked 缓存获取密钥对，签名
    }

    async fn sign_checked(
        &self,
        key_id: &KeyId,
        payload: &[u8],
        expected_namespace: KeyNamespace,
        expected_algorithm: KeyAlgorithm,
    ) -> Result<Signature, KeyVaultError> {
        // 1. 解析 key_id 前缀得到 actual namespace
        // 2. actual != expected → NamespaceViolation
        // 3. 从缓存拿 algorithm，若 != expected → AlgorithmMismatch
        // 4. 签名
    }
    // ...
}
```

### 2.4 密码管理

**密码不得硬编码在配置文件中**。`FileKeystore` 的密码通过以下方式之一获取：

| 方式 | 配置 | 适用场景 |
|---|---|---|
| 环境变量 | `password_env = "CHAIN_KEYSTORE_PASSWORD"` | POC、自动化部署 |
| 启动时交互输入 | `password_prompt = true` | 手动启动、高安全 |
| 从文件读取 | `password_file = "/run/secrets/keystore-pass"` | K8s Secret、Docker Secret |

## 3. 密码学原语

```rust
pub mod crypto {
    pub use ed25519_dalek;
    pub use schnorrkel;  // sr25519
    pub mod multibase;
    pub mod base58;
    pub mod blake2;

    /// 从 multibase 后缀解码 Ed25519 公钥
    pub fn decode_did_key_pubkey(did: &str) -> Result<[u8; 32], KeyVaultError>;

    /// 生成 did:key 标识符
    pub fn encode_did_key(pubkey: &[u8; 32]) -> String;

    /// 从 SS58 地址推导 AccountId32
    pub fn ss58_to_account_id(ss58: &str) -> Result<[u8; 32], KeyVaultError>;

    /// 从 AccountId32 生成 SS58 地址（默认网络前缀）
    pub fn account_id_to_ss58(account_id: &[u8; 32], prefix: u16) -> String;
}
```

**与 namespace 的配合**：

- `decode_did_key_pubkey` / `encode_did_key` 只处理 Ed25519 公钥，用于 `participant-did/` 和 `client-did/` 场景；
- `ss58_to_account_id` / `account_id_to_ss58` 只处理 sr25519 公钥，用于 `chain-account/` 场景；
- 两套原语不互相混用，调用方按 namespace 选择。

## 4. 签名对象构造

```rust
pub mod signing_input {
    /// DID-Signature-v1 七行签名对象（客户端）
    pub fn did_signature_v1(
        did: &str,
        from: &str,
        timestamp: u64,
        anchor_ref: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> Vec<u8>;

    /// IssuedVc-v1 五行签名对象（路径三）
    pub fn issued_vc_v1(
        issuer_did: &str,
        subject_did: &str,
        vc_type: &str,
        vc_hash: &str,
    ) -> Vec<u8>;

    /// GatewayAccess-v1 五行签名对象（HTTP 鉴权）
    pub fn gateway_access_v1(
        did: &str,
        agent_email: &str,
        challenge: &str,
    ) -> Vec<u8>;

    /// VP-v1 签名对象（普通 VP，非 SD）
    pub fn vp_v1(
        holder: &str,
        challenge: &str,
        domain: &str,
        vc_hashes: &[String],
    ) -> Vec<u8>;

    /// 参与方注册绑定声明（服务端 ChainOwner 治理）
    pub fn participant_registration_v1(
        participant_id: u32,
        controller_did: &str,
        operator: &str,
        chain_role: &str,      // "Verifier" / "Issuer" / "ChainOwner"
        business_types: &[String],
        authorized_domains: &[String],
    ) -> Vec<u8>;

    /// operator 轮换声明
    pub fn operator_rotation_v1(
        participant_id: u32,
        new_operator: &str,
        timestamp: u64,
    ) -> Vec<u8>;

    /// controller_did 轮换声明
    pub fn controller_did_rotation_v1(
        participant_id: u32,
        new_controller_did: &str,
        timestamp: u64,
    ) -> Vec<u8>;

    /// 委托锚定授权声明（路径三，用户 A 签）
    pub fn delegation_authorization_v1(
        vc_hash: &str,
        delegate_did: &str,
        delegate_operator: &str,
        timestamp: u64,
    ) -> Vec<u8>;

    /// 选择性披露 VP 签名对象（SD-JWT 附件）
    pub fn vp_sd_v1(
        holder: &str,
        challenge: &str,
        domain: &str,
        disclosures_hash: &str,
        vc_hashes: &[String],
    ) -> Vec<u8>;
}

pub mod sd {
    pub const SALT_LENGTH: usize = 16;
    pub fn generate_salt() -> Result<[u8; 16], KeyVaultError>;
    pub fn base64url_encode(data: &[u8]) -> String;
    pub fn base64url_decode(value: &str) -> Result<Vec<u8>, KeyVaultError>;
    pub fn disclosure_hash(salt: &[u8], name: &str, value: &serde_json::Value)
        -> Result<[u8; 32], KeyVaultError>;
    pub fn disclosure_hash_string(salt: &[u8], name: &str, value: &serde_json::Value)
        -> Result<String, KeyVaultError>;
}
```

**这些构造函数是纯函数**，接收参数，返回待签名字节，不涉及存储。`did-sdk`、`chain-sdk`、`chain-owner-sdk` 都调用它们。

### 4.1 SD-JWT 工具

`sd` 模块与 `vp_sd_v1` 服务于选择性披露：

- 每个可披露属性生成 16 字节 CSPRNG 盐；
- `H = SHA-256(base64url(salt) || base64url(name) || base64url(value))`；
- `base64url` 无 padding；
- `Disclosure = [salt, name, value]`；
- `vp_sd_v1` 文本布局：

```text
VP-SD-v1
{holder}
{challenge}
{domain}
{disclosures_hash}
{vc_hash_1}
...
```

`disclosures_hash` 是 Disclosures 数组 canonical JSON 的 SHA-256（hex）；
`vc_hash` 是完整 VC JSON 的 SHA-256（hex）。链上锚定仍使用完整 VC JSON 的 SHA-256，
由 `chain-sdk` 负责；R1 后 `did-sdk` 不提供 `AnchorRecord` / `get_anchor`。

## 5. 与三类 SDK 的配合

### 5.1 `did-sdk<Client>`

- namespace：`client-did/`；
- algorithm：`Ed25519`；
- 调用入口：`sign_with_did_key` → `KeyVault::sign_checked(key_id, payload, ClientDid, Ed25519)`；
- 用途：签 DID-Signature、VP、签发授权声明。

### 5.2 `did-sdk<Server>`

- 生产环境不加载 `KeyVault`；开发/测试/试运行可配置 `FileKeystore` 本地签名器；
- 持有侧 VC 钱包与 DID 解析；
- 生产签发 VC 时由 `chain-sdk` / `chain-owner-sdk` 注入 `Proof`。

### 5.3 `chain-sdk` / `chain-owner-sdk`

- namespace：`chain-account/`（sr25519）+ `participant-did/`（ed25519）；
- 调用入口：
  - `sign_extrinsic` → `KeyVault::sign_checked(key_id, payload, ChainAccount, Sr25519)`；
  - `sign_participant_assertion` → `KeyVault::sign_checked(key_id, payload, ParticipantDid, Ed25519)`；
- **三类签名对象不同**：extrinsic 直接用 Substrate 的签名 payload；`sign_participant_assertion` 使用 `signing_input` 模块的 `participant_registration_v1` / `issued_vc_v1` / `delegation_authorization_v1` 等。

### 5.4 跨 namespace 拒绝矩阵

| 调用入口 | 期望 namespace | 期望 algorithm | 若 key 是 `participant-did/` | 若 key 是 `chain-account/` |
|---|---|---|---|---|
| `sign_extrinsic` | `ChainAccount` | `Sr25519` | `NamespaceViolation` | 签名成功 |
| `sign_participant_assertion` | `ParticipantDid` | `Ed25519` | 签名成功 | `NamespaceViolation` |
| `sign_with_did_key`（Client） | `ClientDid` | `Ed25519` | `NamespaceViolation` | `NamespaceViolation` |

**这张表是 §0.6 安全域边界在 `keyvault-core` 层面的落点。**

## 6. 未来扩展

### 6.1 `keyvault-device`（设备安全区）

生产阶段新增 crate，实现 `KeyVault` trait，后端为：

| 平台 | 实现 |
|---|---|
| iOS / macOS | Keychain / Secure Enclave |
| Android | Keystore / StrongBox |
| Windows | TPM / DPAPI |
| Linux | Secret Service / TPM |

`did-sdk<Client>` 依赖 `keyvault-device` 替代 `FileKeystore`。`DidSdk` trait 不变，只改配置的 `scheme`。

### 6.2 `keyvault-server`（KMS/HSM）

生产阶段新增 crate，实现 `KeyVault` trait，后端为：

| 后端 | 说明 |
|---|---|
| AWS KMS | 私钥永不离开 KMS |
| 阿里云 KMS | 同上 |
| 腾讯云 KMS | 同上 |
| PKCS#11 HSM | 机房部署，高安全 |
| 远程签名服务 | 链主提供，中小发行方使用 |

`chain-sdk` / `chain-owner-sdk` 依赖 `keyvault-server` 替代 `FileKeystore`。`ChainSdk` / `ChainOwnerSdk` trait 不变，只改配置的 `scheme`。

**namespace 隔离在 `keyvault-server` 中的落点**：不同 namespace 映射为不同 KMS key alias（如 `alias/chain-account-operator-1`、`alias/participant-did-email-binding`），不同 alias 不同 IAM 策略，云侧审计独立。

## 7. 验收清单

| 编号 | 验收项 | 通过标准 |
|---|---|---|
| K1 | `KeyVault` trait 完整 | 覆盖 generate / load / sign / sign_checked / public_key / list_keys / delete |
| K2 | `FileKeystore` 生成密钥 | 按 namespace × algorithm 合法组合生成，加密写入对应子目录 |
| K3 | `FileKeystore` 加载密钥 | 正确密码解锁；错误密码返回 `InvalidPassword` |
| K4 | `FileKeystore` 签名 | 签名可被对应公钥验证 |
| K5 | 私钥不出 KeyVault | 无导出接口；`sign` 只返回签名 |
| K6 | 密码管理 | 支持环境变量、交互输入、文件读取三种方式 |
| K7 | 密码学原语 | `decode_did_key_pubkey` / `encode_did_key` / `ss58_to_account_id` / `account_id_to_ss58` 正确 |
| K8 | 签名对象构造 | `did_signature_v1` / `issued_vc_v1` / `gateway_access_v1` / `vp_v1` / `vp_sd_v1` / `participant_registration_v1` / `operator_rotation_v1` / `controller_did_rotation_v1` / `delegation_authorization_v1` 输出与协议规范一致 |
| K9 | 跨 crate 共享 | `did-sdk` / `chain-sdk` / `chain-owner-sdk` 都正确依赖并使用 |
| K10 | namespace 强制隔离 | `generate` 拒绝非法 namespace × algorithm 组合；`sign` 拒绝文件头与索引不一致 |
| K11 | 跨 namespace 签名拒绝 | `sign_checked` 在 namespace 不匹配时返回 `NamespaceViolation`；在 algorithm 不匹配时返回 `AlgorithmMismatch` |
| K12 | 三类签名入口隔离 | `sign_extrinsic` 用 `chain-account/` 密钥；`sign_participant_assertion` 用 `participant-did/` 密钥；`sign_with_did_key` 用 `client-did/` 密钥；交叉调用全部拒绝 |
| K13 | 签名对象与链上字段一致 | `participant_registration_v1` 等构造函数字段与协议/链上字段一致；R1 后 `did-sdk` 不持有 `AnchorRecord` |

## 8. 交付物

1. `keyvault-core` crate 源码；
2. `KeyVault` trait 定义（含 `sign_checked`）；
3. `KeyNamespace` / `KeyAlgorithm` / `KeyId` 定义；
4. `FileKeystore` 实现（含 namespace 子目录、加密文件格式、解锁校验）；
5. 密码学原语模块（含 SS58 转换）；
6. 签名对象构造模块（9 个构造函数）+ `sd` 盐化哈希工具；
7. 配置文件示例（三种密码管理方式）；
8. 单元测试（生成、加载、签名、错误密码、密钥不存在、namespace 隔离、跨 namespace 拒绝）；
9. 验收记录（K1–K13）。

## 9. 与其它文档的关系

| 文档 | 关系 |
|---|---|
| 文档一：总体架构与任务书 | 本文档是其配套规格书 |
| 文档二：DidSdk 规格书 | `did-sdk<Client>` 依赖其 `KeyVault` 管理 `client-did/` 私钥；`did-sdk<Server>` 生产不加载 KeyVault，开发/测试可配置 FileKeystore |
| 文档三：ChainSdk 规格书 | `chain-sdk` 依赖其 `KeyVault` 管理 `chain-account/` 与 `participant-did/` 两类密钥 |
| 文档四：ChainOwnerSdk 规格书 | `chain-owner-sdk` 依赖其 `KeyVault` 管理链主两类密钥 |
