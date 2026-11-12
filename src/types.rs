//! 公开数据模型（更新版规格：Client/Server + 三种 DID 方法）。

use serde::de::Error as _;
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::DidSdkError;

/// 签名上下文。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningContext {
    /// 签名目的。
    pub purpose: String,
    /// 载荷摘要。
    pub payload_summary: String,
    /// 请求方。
    pub requestor: Option<String>,
}

/// 原始签名字节。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Signature(pub Vec<u8>);

/// Ed25519 公钥。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Ed25519PublicKey(pub [u8; 32]);

/// 签发授权签名（裸签名字节）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct IssueAuthorizationSignature(pub Vec<u8>);

/// DID 方法。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DidMethod {
    /// did:key。
    Key,
    /// did:peer。
    Peer,
    /// did:web。
    Web,
}

/// did:peer numalgo。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PeerNumalgo {
    /// numalgo 0。
    Zero,
    /// numalgo 1。
    One,
    /// numalgo 2。
    Two,
}

/// DID 记录。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidRecord {
    /// DID 字符串。
    pub did: String,
    /// DID 方法。
    pub method: DidMethod,
    /// 文档哈希；did:key/peer:0/2 为 None，did:web/peer:1 可有值。
    pub doc_hash: Option<String>,
    /// owner DID。
    pub owner: Option<String>,
    /// 链上区块号（若适用）。
    pub block_number: Option<u64>,
}

/// DID 文档（W3C 精简子集）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DidDocument {
    /// 文档 id。
    pub id: String,
    /// 别名。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<String>,
    /// 验证方法。
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,
    /// 认证引用。
    #[serde(default)]
    pub authentication: Vec<String>,
    /// 断言引用。
    #[serde(default)]
    pub assertion_method: Vec<String>,
    /// 服务端点。
    #[serde(default)]
    pub service: Vec<Service>,
}

/// DID 文档验证方法。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationMethod {
    /// 方法 id。
    pub id: String,
    /// 类型。
    #[serde(rename = "type")]
    pub type_: String,
    /// controller。
    pub controller: String,
    /// 公钥 multibase。
    #[serde(rename = "publicKeyMultibase", skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    /// 公钥 JWK。
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
}

/// DID 文档服务端点。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    /// 服务 id。
    pub id: String,
    /// 服务类型。
    #[serde(rename = "type")]
    pub type_: String,
    /// 端点。
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: serde_json::Value,
}

/// DID/Anchor 状态。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AddressStatus {
    /// 有效。
    Active,
    /// 已撤销。
    Revoked,
    /// 已过期。
    Expired,
    /// 待确认。
    Pending,
}

/// 完整性状态。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    /// 有效。
    Valid,
    /// 无效。
    Invalid,
    /// 已撤销。
    Revoked,
    /// 已过期。
    Expired,
    /// 未知。
    Unknown,
}

/// DID-Signature 验证结果。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyResult {
    /// 是否通过。
    pub verified: bool,
    /// 完整性。
    pub integrity: IntegrityStatus,
    /// 地址状态。
    pub address: AddressStatus,
    /// 失败原因。
    pub reason: Option<String>,
}

/// VC 验证结果。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VcVerificationResult {
    /// 是否通过。
    pub verified: bool,
    /// issuer DID 是否解析成功。
    pub issuer_resolved: bool,
    /// issuer 是否已注册/可解析。
    pub issuer_registered: bool,
    /// 失败原因。
    pub reason: Option<String>,
}

/// Selective-disclosure disclosure：`[salt(base64url), claim_name, claim_value]`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    /// 盐（base64url，无 padding）。
    pub salt: String,
    /// 属性名。
    pub name: String,
    /// 属性值。
    pub value: serde_json::Value,
}

impl Disclosure {
    /// 生成新盐并创建 Disclosure。
    pub fn generate(
        name: impl Into<String>,
        value: serde_json::Value,
    ) -> Result<Self, DidSdkError> {
        let salt = keyvault_core::sd::generate_salt()
            .map_err(|error| DidSdkError::SigningFailed(error.to_string()))?;
        Ok(Self {
            salt: keyvault_core::sd::base64url_encode(&salt),
            name: name.into(),
            value,
        })
    }

    /// 重算 `_sd` 中的哈希字符串。
    pub fn hash_string(&self) -> Result<String, DidSdkError> {
        let salt = keyvault_core::sd::base64url_decode(&self.salt)
            .map_err(|error| DidSdkError::InvalidArgument(error.to_string()))?;
        keyvault_core::sd::disclosure_hash_string(&salt, &self.name, &self.value)
            .map_err(|error| DidSdkError::SigningFailed(error.to_string()))
    }
}

impl Serialize for Disclosure {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(3)?;
        tuple.serialize_element(&self.salt)?;
        tuple.serialize_element(&self.name)?;
        tuple.serialize_element(&self.value)?;
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for Disclosure {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (salt, name, value) = <(String, String, serde_json::Value)>::deserialize(deserializer)?;
        if salt.is_empty() || name.is_empty() {
            return Err(D::Error::custom("disclosure salt/name must not be empty"));
        }
        Ok(Self { salt, name, value })
    }
}

/// 选择性 VP 请求：只披露 `disclose` 中列出的属性。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectiveVpRequest {
    /// VC。
    pub credential: VerifiableCredential,
    /// 要披露的属性名（默认空 = 全部隐藏）。
    #[serde(default)]
    pub disclose: Vec<String>,
}

/// VP 验证结果（selective disclosure 扩展）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VpVerificationResult {
    /// 是否通过。
    pub verified: bool,
    /// holder DID 是否解析成功。
    pub holder_resolved: bool,
    /// 各 VC 的验证结果。
    pub credentials: Vec<VcVerificationResult>,
    /// 已核验的 Disclosure 数量。
    pub disclosure_count: usize,
    /// 失败原因。
    pub reason: Option<String>,
}

/// VC/VP proof（外部 Signer 注入）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proof {
    /// proof 类型。
    #[serde(rename = "type")]
    pub type_: String,
    /// 创建时间（Unix 秒）。
    pub created: u64,
    /// 验证方法。
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    /// JWS/签名字符串（POC 使用 base58btc 编码的裸签名）。
    pub jws: String,
}

/// W3C 风格 Verifiable Credential。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiableCredential {
    /// JSON-LD context。
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// VC id。
    pub id: String,
    /// 类型列表。
    #[serde(rename = "type")]
    pub types: Vec<String>,
    /// 签发者 DID。
    pub issuer: String,
    /// 签发时间（RFC3339 UTC）。
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    /// 过期时间（RFC3339 UTC）。
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,
    /// 主体声明。
    #[serde(rename = "credentialSubject")]
    pub credential_subject: serde_json::Value,
    /// proof。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    /// 本地存储锚点 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_id: Option<String>,
}

/// Verifiable Presentation。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiablePresentation {
    /// JSON-LD context。
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// 类型列表。
    #[serde(rename = "type")]
    pub types: Vec<String>,
    /// holder DID。
    pub holder: String,
    /// VC。
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,
    /// challenge。
    pub challenge: String,
    /// domain。
    pub domain: String,
    /// Selective-disclosure disclosures；`None` 表示非选择性披露 VP。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosures: Option<Vec<Disclosure>>,
    /// proof。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl DidRecord {
    /// 由 DID 构造记录。
    pub fn new(did: String, method: DidMethod) -> Self {
        Self {
            did,
            method,
            doc_hash: None,
            owner: None,
            block_number: None,
        }
    }
}
