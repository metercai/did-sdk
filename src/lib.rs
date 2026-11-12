//! did-sdk: 一个 SDK，三种模式（Mock / Centralized / Chain）。
//!
//! 应用只依赖 [`DidSdk`] trait；通过 [`config::build_did_sdk`] 按配置构造具体实现。

pub mod config;
pub mod error;
pub mod server_request;
pub mod types;

mod centralized;
mod chain;
mod core;
mod did_signature;
mod mock;
mod storage;
mod vc;

use std::sync::Arc;

use async_trait::async_trait;

pub use config::{
    ConfigOverrides, DidSdkConfig, DidSdkMode, build_did_sdk, build_vault, resolve_config,
};
pub use error::DidSdkError;
pub use types::*;

pub use centralized::CentralizedDidSdk;
pub use chain::ChainModeDidSdk;
pub use mock::{ConfirmPolicy, MockDidSdk};

/// 三模式统一接口。
#[async_trait]
pub trait DidSdk: Send + Sync {
    /// 生成一把新的 Ed25519 key，返回 `did:key:...`。
    async fn generate_did_key(&self) -> Result<String, DidSdkError>;

    /// 用 active key 对原始消息签名。
    async fn sign_with_did_key(
        &self,
        message: &[u8],
        ctx: SigningContext,
    ) -> Result<Signature, DidSdkError>;

    /// 从 `did:key` 解析 Ed25519 公钥（本地，无网络）。
    fn resolve_did_key(&self, did: &str) -> Result<Ed25519PublicKey, DidSdkError>;

    /// 创建一个 DID 记录（生成新 key；Mock 记录在进程内，其他模式为本地记录）。
    async fn create_did(&self) -> Result<DidRecord, DidSdkError>;

    /// 解析 DID；不存在时返回 `Ok(None)`。
    async fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError>;

    /// 签发 self-asserted VC。
    async fn issue_self_asserted_vc(
        &self,
        claims: serde_json::Value,
    ) -> Result<VerifiableCredential, DidSdkError>;

    /// 存储 VC。
    async fn store_vc(&self, vc: VerifiableCredential) -> Result<(), DidSdkError>;

    /// 按 anchor id 获取 VC。
    async fn get_vc(&self, anchor_id: &str) -> Result<Option<VerifiableCredential>, DidSdkError>;

    /// 列出本地 VC。
    async fn list_vcs(&self) -> Result<Vec<VerifiableCredential>, DidSdkError>;

    /// 删除本地 VC。
    async fn remove_vc(&self, anchor_id: &str) -> Result<(), DidSdkError>;

    /// 构造并签名 VP。
    async fn build_vp(
        &self,
        vcs: Vec<VerifiableCredential>,
        challenge: &str,
        domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError>;

    /// 构造 DID-Signature header。
    async fn build_did_signature_header(
        &self,
        from: &str,
        anchor_id: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> Result<String, DidSdkError>;

    /// 验证 DID-Signature header（本地 did:key，无网络）。
    fn verify_did_signature_header(
        &self,
        header: &str,
        from: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> Result<VerifyResult, DidSdkError>;

    /// 签发 VC 授权签名。
    async fn sign_issue_authorization(
        &self,
        subject_did: &str,
        vc_type: &str,
        vc_hash: &str,
        timestamp: u64,
    ) -> Result<IssueAuthorizationSignature, DidSdkError>;

    /// 获取 Anchor。
    async fn get_anchor(&self, anchor_id: &str) -> Result<AnchorRecord, DidSdkError>;

    /// 安装用户确认 handler。
    fn set_request_handler(&self, handler: Arc<dyn server_request::ServerRequestHandler>);
}
