//! 服务端请求的用户确认回调。
//!
//! 应用可实现该 trait 接入 UI / 生物识别 / 设备安全区。返回
//! [`crate::DidSdkError::UserRejected`] 表示用户拒绝；返回 `Timeout` 表示确认超时。

use async_trait::async_trait;

use crate::DidSdkError;

/// 构造 DID-Signature header 前的确认上下文。
#[derive(Debug, Clone)]
pub struct ChallengeContext {
    /// 签名者 DID。
    pub did: String,
    /// 请求方（email/agent 标识）。
    pub from: String,
    /// anchor 引用。
    pub anchor_id: String,
    /// body hash。
    pub body_hash: String,
    /// receipt hash。
    pub rcpt_hash: String,
}

/// 构造 VP 前的确认上下文。
#[derive(Debug, Clone)]
pub struct VpRequestContext {
    /// holder DID。
    pub holder: String,
    /// challenge。
    pub challenge: String,
    /// domain。
    pub domain: String,
    /// 待出示 VC 的 anchor id。
    pub vc_ids: Vec<String>,
}

/// 签发授权签名前的确认上下文。
#[derive(Debug, Clone)]
pub struct AuthorizationRequestContext {
    /// 主体 DID。
    pub subject_did: String,
    /// VC 类型。
    pub vc_type: String,
    /// VC hash。
    pub vc_hash: String,
    /// 时间戳（Unix 秒）。
    pub timestamp: u64,
}

/// 用户确认回调。
#[async_trait]
pub trait ServerRequestHandler: Send + Sync {
    /// 确认 DID-Signature 请求。
    async fn on_challenge(&self, ctx: &ChallengeContext) -> Result<(), DidSdkError>;

    /// 确认 VP 出示请求。
    async fn on_vp_request(&self, ctx: &VpRequestContext) -> Result<(), DidSdkError>;

    /// 确认签发授权请求。
    async fn on_authorization_request(
        &self,
        ctx: &AuthorizationRequestContext,
    ) -> Result<(), DidSdkError>;
}

/// POC 默认实现：总是确认。
#[derive(Debug, Default, Clone, Copy)]
pub struct AutoConfirmHandler;

#[async_trait]
impl ServerRequestHandler for AutoConfirmHandler {
    async fn on_challenge(&self, _ctx: &ChallengeContext) -> Result<(), DidSdkError> {
        Ok(())
    }

    async fn on_vp_request(&self, _ctx: &VpRequestContext) -> Result<(), DidSdkError> {
        Ok(())
    }

    async fn on_authorization_request(
        &self,
        _ctx: &AuthorizationRequestContext,
    ) -> Result<(), DidSdkError> {
        Ok(())
    }
}
