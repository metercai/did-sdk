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

/// 委托锚定授权声明（路径三：用户 A 授权链主代提交锚定）。
///
/// `signature` 覆盖的是 `DelegationAuthorization-v1` 待签名字节
/// （见 [`DelegationAuthorization::signing_input`]），**不覆盖**本结构的 JSON 外壳。
/// 链主收到 [`DelegationAuthorization::to_bytes`] 的 JSON 字节后，可用
/// `signer_did` 的 `did:key` 自包含公钥独立验签。
///
/// 与 [`IssueAuthorizationSignature`] 的区别：后者是发行方对 VC 签发的授权
/// （`IssuedVc-v1`），本类型是用户对“链主代提交某个 VC 锚定”的委托授权
/// （`DelegationAuthorization-v1`），两者互不替代。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationAuthorization {
    /// 固定 1，便于未来演进。
    pub version: u8,
    /// 被授权锚定的 VC 哈希（通常由 [`crate::anchor_payload_hash`] 计算）。
    pub vc_hash: String,
    /// 链主 did:web。
    pub delegate_did: String,
    /// 链主 operator（SS58）。
    pub delegate_operator: String,
    /// Unix 秒；参与签名，服务端据此做新鲜度校验。
    pub timestamp: u64,
    /// 用户 A 的 did:key（自包含公钥）。
    pub signer_did: String,
    /// Ed25519 裸签名（对 `DelegationAuthorization-v1` 输入）。
    ///
    /// JSON 编码为 64 个字节值的数组（`Vec<u8>` 的 serde 默认表示）。
    pub signature: Vec<u8>,
}

impl DelegationAuthorization {
    /// 当前（也是唯一）支持的声明版本。
    pub const VERSION: u8 = 1;

    /// 重算待签名字节：
    /// `delegation_authorization_v1(vc_hash, delegate_did, delegate_operator, timestamp)`。
    ///
    /// 直接调用 `keyvault-core` 的参考实现，不自行拼接格式字符串。
    pub fn signing_input(&self) -> Vec<u8> {
        keyvault_core::signing_input::delegation_authorization_v1(
            &self.vc_hash,
            &self.delegate_did,
            &self.delegate_operator,
            self.timestamp,
        )
    }

    /// 序列化为紧凑 UTF-8 JSON 字节，供链主 `submit_delegated_anchor` 的
    /// `authorization_signature: &[u8]` 参数直接携带。
    ///
    /// 写前会校验版本、必填字段与 `signer_did` 的 `did:key` 约束。
    /// 紧凑 JSON 不保证字段顺序（本实现由结构体字段顺序固定），
    /// 签名也不覆盖 JSON 外壳。
    pub fn to_bytes(&self) -> Result<Vec<u8>, DidSdkError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| DidSdkError::InvalidArgument(format!("serialize delegation: {error}")))
    }

    /// 从 [`DelegationAuthorization::to_bytes`] 的字节反序列化并校验。
    ///
    /// 拒绝：`version != 1`、空字段、非 `did:` 的 `delegate_did`、
    /// 非 `did:key:` 的 `signer_did`、`timestamp == 0`、空签名。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DidSdkError> {
        let authorization: Self = serde_json::from_slice(bytes).map_err(|error| {
            DidSdkError::InvalidArgument(format!("parse delegation authorization: {error}"))
        })?;
        authorization.validate()?;
        Ok(authorization)
    }

    /// 用 `signer_did` 的 `did:key` 自包含公钥验签；
    /// 同时校验版本、字段与 `did:key` 约束。
    ///
    /// 链主侧仍应独立验签（不信任客户端），本方法主要用于客户端自检与测试。
    pub fn verify(&self) -> Result<(), DidSdkError> {
        self.validate()?;
        let public_key =
            keyvault_core::crypto::decode_did_key_pubkey(&self.signer_did).map_err(|error| {
                DidSdkError::InvalidArgument(format!("invalid signer_did: {error}"))
            })?;
        if self.signature.len() != 64 {
            return Err(DidSdkError::VcVerificationFailed(format!(
                "delegation authorization signature must be 64 bytes, got {}",
                self.signature.len()
            )));
        }
        if keyvault_core::crypto::ed25519::verify(
            &public_key,
            &self.signing_input(),
            &self.signature,
        ) {
            Ok(())
        } else {
            Err(DidSdkError::VcVerificationFailed(
                "delegation authorization signature mismatch".into(),
            ))
        }
    }

    fn validate(&self) -> Result<(), DidSdkError> {
        if self.version != Self::VERSION {
            return Err(DidSdkError::InvalidArgument(format!(
                "unsupported delegation authorization version: {}",
                self.version
            )));
        }
        if self.vc_hash.is_empty() {
            return Err(DidSdkError::InvalidArgument("empty vc_hash".into()));
        }
        if self.delegate_did.is_empty() {
            return Err(DidSdkError::InvalidArgument("empty delegate_did".into()));
        }
        if !self.delegate_did.starts_with("did:") {
            return Err(DidSdkError::InvalidArgument(format!(
                "delegate_did must start with the did: scheme: {}",
                self.delegate_did
            )));
        }
        if self.delegate_operator.is_empty() {
            return Err(DidSdkError::InvalidArgument(
                "empty delegate_operator".into(),
            ));
        }
        if self.timestamp == 0 {
            return Err(DidSdkError::InvalidArgument("timestamp must be > 0".into()));
        }
        if self.signer_did.is_empty() {
            return Err(DidSdkError::InvalidArgument("empty signer_did".into()));
        }
        if !self.signer_did.starts_with("did:key:") {
            return Err(DidSdkError::InvalidArgument(format!(
                "signer_did must be did:key: {}, not did:peer or did:web",
                self.signer_did
            )));
        }
        if self.signature.is_empty() {
            return Err(DidSdkError::InvalidArgument("empty signature".into()));
        }
        Ok(())
    }
}

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
