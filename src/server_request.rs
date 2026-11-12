//! 客户端交互式确认回调（仅 Client 模式）。

use async_trait::async_trait;

use crate::DidSdkError;

/// 签名确认响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureResponse {
    /// 用户是否同意。
    pub approved: bool,
    /// 拒绝原因。
    pub reason: Option<String>,
}

/// VP 出示确认响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpResponse {
    /// 用户是否同意。
    pub approved: bool,
    /// 拒绝原因。
    pub reason: Option<String>,
}

/// 授权签名确认响应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationResponse {
    /// 用户是否同意。
    pub approved: bool,
    /// 拒绝原因。
    pub reason: Option<String>,
}

fn ensure_approved(approved: bool, reason: Option<String>) -> Result<(), DidSdkError> {
    if approved {
        Ok(())
    } else {
        let _ = reason;
        Err(DidSdkError::UserRejected)
    }
}

/// 用户确认回调。Server 模式无交互式用户，不实现该 trait。
#[async_trait]
pub trait ServerRequestHandler: Send + Sync {
    /// 确认挑战签名。
    async fn on_challenge(
        &self,
        challenge: &str,
        requestor: &str,
    ) -> Result<SignatureResponse, DidSdkError>;

    /// 确认 VP 出示。
    async fn on_vp_request(
        &self,
        credential_types: &[String],
        challenge: &str,
    ) -> Result<VpResponse, DidSdkError>;

    /// 确认授权签名。
    async fn on_authorization_request(
        &self,
        fields: &[String],
        purpose: &str,
        requestor: &str,
    ) -> Result<AuthorizationResponse, DidSdkError>;
}

/// POC 默认实现：总是确认。
#[derive(Debug, Default, Clone, Copy)]
pub struct AutoConfirmHandler;

#[async_trait]
impl ServerRequestHandler for AutoConfirmHandler {
    async fn on_challenge(
        &self,
        _challenge: &str,
        _requestor: &str,
    ) -> Result<SignatureResponse, DidSdkError> {
        Ok(SignatureResponse {
            approved: true,
            reason: None,
        })
    }

    async fn on_vp_request(
        &self,
        _credential_types: &[String],
        _challenge: &str,
    ) -> Result<VpResponse, DidSdkError> {
        Ok(VpResponse {
            approved: true,
            reason: None,
        })
    }

    async fn on_authorization_request(
        &self,
        _fields: &[String],
        _purpose: &str,
        _requestor: &str,
    ) -> Result<AuthorizationResponse, DidSdkError> {
        Ok(AuthorizationResponse {
            approved: true,
            reason: None,
        })
    }
}

pub(crate) fn approve_signature(response: SignatureResponse) -> Result<(), DidSdkError> {
    ensure_approved(response.approved, response.reason)
}

pub(crate) fn approve_vp(response: VpResponse) -> Result<(), DidSdkError> {
    ensure_approved(response.approved, response.reason)
}

pub(crate) fn approve_authorization(response: AuthorizationResponse) -> Result<(), DidSdkError> {
    ensure_approved(response.approved, response.reason)
}
