use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use schnorrkel::SecretKey;

/// 密钥标识。`did:key` 形式（`did:key:z6Mk...`）是 POC 的默认形式。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(pub String);

/// 原始签名字节。编码方式由调用方决定；KeyVault 层不假设格式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

/// 公钥枚举。仅包含公钥材料，可安全序列化/打印。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKey {
    /// Ed25519 公钥。
    Ed25519([u8; 32]),
    /// sr25519 公钥（Ristretto 压缩点）。
    Sr25519([u8; 32]),
}

/// 私钥对枚举。
///
/// 故意不实现 `Clone` / `Serialize` / `Debug`，避免私钥被复制到外部或写入日志。
/// 只在 `KeyVault` 内部使用。
pub enum Keypair {
    /// Ed25519 私钥。
    Ed25519(SigningKey),
    /// sr25519 私钥。
    Sr25519(SecretKey),
}

/// KeyVault 错误。
///
/// `UserRejected` 为未来的 `keyvault-device`（Secure Enclave / TPM / 生物识别）
/// 预留；当前 `FileKeystore` 永不返回它，`MockDidSdk` 用它实现自动拒绝。
#[derive(Debug, thiserror::Error)]
pub enum KeyVaultError {
    /// 指定 key 不存在。
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    /// 指定 key 已存在。
    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),
    /// 密码错误或无法解密。
    #[error("Invalid password")]
    InvalidPassword,
    /// 密钥库处于锁定状态。
    #[error("KeyVault locked")]
    Locked,
    /// 签名操作失败。
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    /// 文件系统 I/O 错误。
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    /// 密钥格式非法。
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    /// 解密失败。
    #[error("Decryption failed")]
    DecryptionFailed,
    /// JSON 序列化/反序列化错误。
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    /// 当前平台不支持该操作。
    #[error("Operation not supported on this platform")]
    Unsupported,
    /// 用户拒绝签名。
    ///
    /// `FileKeystore` 当前不触发；`MockDidSdk` 与未来的 `keyvault-device`
    /// 会返回此变体，`did-sdk` 层需把它映射为 `DidSdkError::UserRejected`。
    #[error("User rejected signing")]
    UserRejected,
}

/// 私钥管理抽象。
///
/// 实现者负责安全存储与签名；trait 不暴露任何导出私钥的方法。
#[async_trait]
pub trait KeyVault: Send + Sync {
    /// 生成一把新 key 并返回其 `KeyId`。
    async fn generate(&self) -> Result<KeyId, KeyVaultError>;

    /// 确认 key 存在且可用（`FileKeystore` 会在此校验密码）。
    async fn load(&self, key_id: &KeyId) -> Result<(), KeyVaultError>;

    /// 对原始字节签名。
    async fn sign(&self, key_id: &KeyId, payload: &[u8]) -> Result<Signature, KeyVaultError>;

    /// 获取公钥。
    async fn public_key(&self, key_id: &KeyId) -> Result<PublicKey, KeyVaultError>;

    /// 列出所有 key。
    async fn list_keys(&self) -> Result<Vec<KeyId>, KeyVaultError>;

    /// 删除 key。
    async fn delete(&self, key_id: &KeyId) -> Result<(), KeyVaultError>;
}
