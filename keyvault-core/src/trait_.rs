use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use schnorrkel::SecretKey;

/// namespace 前缀，用于强制隔离三类密钥。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyNamespace {
    /// 服务端链账户密钥（sr25519）。
    ChainAccount,
    /// 服务端参与方 did:web 密钥（ed25519）。
    ParticipantDid,
    /// 客户端 DID 密钥（ed25519）。
    ClientDid,
}

impl KeyNamespace {
    /// KeyId 前缀。
    pub fn prefix(self) -> &'static str {
        match self {
            Self::ChainAccount => "chain-account/",
            Self::ParticipantDid => "participant-did/",
            Self::ClientDid => "client-did/",
        }
    }

    /// 物理子目录名（不含斜杠）。
    pub fn dir_name(self) -> &'static str {
        match self {
            Self::ChainAccount => "chain-account",
            Self::ParticipantDid => "participant-did",
            Self::ClientDid => "client-did",
        }
    }

    /// 从 KeyId 字符串解析 namespace。
    pub fn from_key_id(key_id: &str) -> Option<Self> {
        if key_id.starts_with(Self::ChainAccount.prefix()) {
            Some(Self::ChainAccount)
        } else if key_id.starts_with(Self::ParticipantDid.prefix()) {
            Some(Self::ParticipantDid)
        } else if key_id.starts_with(Self::ClientDid.prefix()) {
            Some(Self::ClientDid)
        } else {
            None
        }
    }

    /// 文件中使用的单字节表示。
    pub fn as_u8(self) -> u8 {
        match self {
            Self::ChainAccount => 0x01,
            Self::ParticipantDid => 0x02,
            Self::ClientDid => 0x03,
        }
    }

    /// 从文件字节解析。
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::ChainAccount),
            0x02 => Some(Self::ParticipantDid),
            0x03 => Some(Self::ClientDid),
            _ => None,
        }
    }

    /// 该 namespace 唯一允许的算法。
    pub fn allowed_algorithm(self) -> KeyAlgorithm {
        match self {
            Self::ChainAccount => KeyAlgorithm::Sr25519,
            Self::ParticipantDid | Self::ClientDid => KeyAlgorithm::Ed25519,
        }
    }
}

/// 密钥算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    /// Ed25519。
    Ed25519,
    /// sr25519。
    Sr25519,
}

impl KeyAlgorithm {
    /// 文件中使用的单字节表示。
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Ed25519 => 0x01,
            Self::Sr25519 => 0x02,
        }
    }

    /// 从文件字节解析。
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Ed25519),
            0x02 => Some(Self::Sr25519),
            _ => None,
        }
    }
}

/// 密钥标识。格式为 `"{namespace_prefix}{local_id}"`。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(pub String);

impl KeyId {
    /// 构造带 namespace 前缀的 KeyId。
    pub fn new(namespace: KeyNamespace, local_id: &str) -> Self {
        Self(format!("{}{}", namespace.prefix(), local_id))
    }

    /// 解析 namespace。
    pub fn namespace(&self) -> Option<KeyNamespace> {
        KeyNamespace::from_key_id(&self.0)
    }

    /// 去掉 namespace 前缀后的局部 id。
    pub fn local_id(&self) -> Option<&str> {
        self.namespace()
            .map(|namespace| self.0.strip_prefix(namespace.prefix()).unwrap_or(""))
    }
}

/// 原始签名字节。编码方式由调用方决定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

/// 公钥枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKey {
    /// Ed25519 公钥。
    Ed25519([u8; 32]),
    /// sr25519 公钥。
    Sr25519([u8; 32]),
}

/// 私钥对枚举。故意不实现 `Clone` / `Serialize` / `Debug`。
pub enum Keypair {
    /// Ed25519 私钥。
    Ed25519(SigningKey),
    /// sr25519 私钥。
    Sr25519(SecretKey),
}

/// KeyVault 错误。
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
    IoError(String),
    /// 密钥格式非法。
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    /// 解密失败。
    #[error("Decryption failed")]
    DecryptionFailed,
    /// JSON 序列化错误。
    #[error("Serialization error: {0}")]
    SerializationError(String),
    /// 当前平台不支持。
    #[error("Operation not supported on this platform")]
    Unsupported,
    /// 用户拒绝签名（为未来设备安全区预留）。
    #[error("User rejected signing")]
    UserRejected,
    /// 跨 namespace 使用密钥。
    #[error("Namespace violation: key {key} is {actual:?}, expected {expected:?}")]
    NamespaceViolation {
        /// KeyId。
        key: String,
        /// 实际 namespace。
        actual: KeyNamespace,
        /// 期望 namespace。
        expected: KeyNamespace,
    },
    /// 算法不匹配。
    #[error("Algorithm mismatch: key {key} is {actual:?}, expected {expected:?}")]
    AlgorithmMismatch {
        /// KeyId。
        key: String,
        /// 实际算法。
        actual: KeyAlgorithm,
        /// 期望算法。
        expected: KeyAlgorithm,
    },
}

impl From<std::io::Error> for KeyVaultError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error.to_string())
    }
}

impl From<serde_json::Error> for KeyVaultError {
    fn from(error: serde_json::Error) -> Self {
        Self::SerializationError(error.to_string())
    }
}

/// 私钥管理抽象。
#[async_trait]
pub trait KeyVault: Send + Sync {
    /// 生成密钥对；algorithm 必须符合 namespace 映射。
    async fn generate(
        &self,
        namespace: KeyNamespace,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyId, KeyVaultError>;

    /// 加载密钥。
    async fn load(&self, key_id: &KeyId) -> Result<(), KeyVaultError>;

    /// 签名；实现会校验 KeyId 前缀与存储记录一致。
    async fn sign(&self, key_id: &KeyId, payload: &[u8]) -> Result<Signature, KeyVaultError>;

    /// 公钥。
    async fn public_key(&self, key_id: &KeyId) -> Result<PublicKey, KeyVaultError>;

    /// 列出密钥，可按 namespace 过滤。
    async fn list_keys(&self, namespace: Option<KeyNamespace>)
    -> Result<Vec<KeyId>, KeyVaultError>;

    /// 删除密钥。
    async fn delete(&self, key_id: &KeyId) -> Result<(), KeyVaultError>;

    /// 带 namespace + algorithm 预期校验的签名入口。
    async fn sign_checked(
        &self,
        key_id: &KeyId,
        payload: &[u8],
        expected_namespace: KeyNamespace,
        expected_algorithm: KeyAlgorithm,
    ) -> Result<Signature, KeyVaultError>;
}
