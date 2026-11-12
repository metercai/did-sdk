//! `did-sdk` 统一错误类型。

/// SDK 对外错误。
///
/// 绑定层按变体映射：
/// - `UserRejected` → Python `UserRejectedError` / Node `err.code === "UserRejected"`；
/// - `VcNotFound` / `AnchorNotFound` → `NotFoundError` / `err.code === "NotFound"`；
/// - `InvalidArgument` → Python `ValueError` / Node `err.code === "InvalidArgument"`；
/// - 其他 → `DidSdkError` / `err.code === "DidSdkError"`。
#[derive(Debug, thiserror::Error)]
pub enum DidSdkError {
    /// key 生成失败。
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    /// 签名失败。
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    /// 用户拒绝签名。
    ///
    /// 来源有三：
    /// 1. `ServerRequestHandler::on_challenge` / `on_vp_request` /
    ///    `on_authorization_request` 返回拒绝；
    /// 2. `MockDidSdk` 的自动拒绝策略；
    /// 3. `keyvault_core::KeyVaultError::UserRejected`（未来设备安全区）。
    #[error("User rejected signing")]
    UserRejected,
    /// 用户确认超时。
    #[error("User confirmation timeout")]
    Timeout,
    /// key 不存在。
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    /// VC 不存在。
    #[error("VC not found: {0}")]
    VcNotFound(String),
    /// Anchor 不存在。
    #[error("Anchor not found: {0}")]
    AnchorNotFound(String),
    /// Anchor 已撤销。
    #[error("Anchor revoked: {0}")]
    AnchorRevoked(String),
    /// Anchor 已过期。
    #[error("Anchor expired: {0}")]
    AnchorExpired(String),
    /// 链/中心化服务不可用。
    #[error("Chain unavailable: {0}")]
    ChainUnavailable(String),
    /// 参数非法。
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    /// 当前平台不支持。
    #[error("Operation not supported on this platform: {0}")]
    Unsupported(String),
    /// 配置错误。
    #[error("Configuration error: {0}")]
    ConfigError(String),
}
