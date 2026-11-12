//! 公开数据模型。
//!
//! 所有类型都派生 `Serialize + Deserialize + Clone + Debug`；绑定层直接复用
//! 这些 JSON 形状，避免三语言各写一套。

use serde::{Deserialize, Serialize};

/// 签名上下文，用于审计/UI 提示；不参与待签名字节。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningContext {
    /// 签名目的（例如 `login` / `issue-vc`）。
    pub purpose: String,
    /// 载荷摘要，用于 UI 展示。
    pub payload_summary: String,
    /// 请求方标识（可选）。
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
    /// 签名有效。
    Valid,
    /// 签名无效。
    Invalid,
    /// 已撤销。
    Revoked,
    /// 已过期。
    Expired,
    /// 未知。
    Unknown,
}

/// DID 记录。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidRecord {
    /// DID 字符串（POC 为 `did:key:z...`）。
    pub did: String,
    /// Ed25519 公钥。
    pub public_key: Ed25519PublicKey,
    /// 创建时间（Unix 秒）。
    pub created_at: u64,
    /// 更新时间（Unix 秒）。
    pub updated_at: u64,
    /// 关联的 anchor（若已锚定）。
    pub anchor_id: Option<String>,
    /// 状态。
    pub status: AddressStatus,
}

/// DID-Signature 验证结果。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyResult {
    /// 是否有效。
    pub valid: bool,
    /// 完整性状态。
    pub integrity: IntegrityStatus,
    /// 被验证的 DID（解析成功时）。
    pub did: Option<String>,
    /// header 中的时间戳。
    pub timestamp: Option<u64>,
    /// 失败原因（成功时为 `None`）。
    pub reason: Option<String>,
}

/// VC/VP 的 proof。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VcProof {
    /// proof 类型。
    #[serde(rename = "type")]
    pub proof_type: String,
    /// 创建时间（RFC3339）。
    pub created: String,
    /// 验证方法（`did#key-1`）。
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    /// proof 目的。
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    /// base58btc 编码的签名。
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// W3C 风格的 Verifiable Credential。
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
    pub proof: Option<VcProof>,
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
    /// 出示的 VC。
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,
    /// 挑战值。
    pub challenge: String,
    /// 域名。
    pub domain: String,
    /// proof。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<VcProof>,
}

/// Anchor 记录。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorRecord {
    /// Anchor id。
    pub anchor_id: String,
    /// 关联 DID。
    pub did: String,
    /// 状态。
    pub status: AddressStatus,
    /// 创建时间（Unix 秒）。
    pub created_at: u64,
    /// 更新时间（Unix 秒）。
    pub updated_at: u64,
    /// 过期时间（Unix 秒）。
    pub expires_at: Option<u64>,
    /// 链/中心化服务返回的附加字段。
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// 签发授权签名。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssueAuthorizationSignature {
    /// 签发者 DID。
    pub issuer_did: String,
    /// 主体 DID。
    pub subject_did: String,
    /// VC 类型。
    pub vc_type: String,
    /// VC hash。
    pub vc_hash: String,
    /// 时间戳（Unix 秒）。
    pub timestamp: u64,
    /// base58btc 编码的 Ed25519 签名。
    pub signature: String,
}

impl DidRecord {
    /// 由 DID 与公钥构造一个 active 记录。
    pub fn new_active(did: String, public_key: Ed25519PublicKey, timestamp: u64) -> Self {
        Self {
            did,
            public_key,
            created_at: timestamp,
            updated_at: timestamp,
            anchor_id: None,
            status: AddressStatus::Active,
        }
    }
}
