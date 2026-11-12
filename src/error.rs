//! `did-sdk` 统一错误类型。

/// SDK 对外错误。
#[derive(Debug, thiserror::Error)]
pub enum DidSdkError {
    /// key 生成失败。
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    /// 签名失败。
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    /// 用户拒绝签名。
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
    /// 当前运行模式不支持该 DID 方法。
    #[error("DID method not supported in this mode: {0}")]
    UnsupportedDidMethod(String),
    /// DID 解析失败。
    #[error("DID resolution failed: {0}")]
    DidResolutionFailed(String),
    /// VC 验证失败。
    #[error("VC verification failed: {0}")]
    VcVerificationFailed(String),
    /// Disclosure 哈希不匹配。
    #[error("disclosure_hash_mismatch: {0}")]
    DisclosureHashMismatch(String),
    /// 同一属性重复披露。
    #[error("disclosure_duplicate: {0}")]
    DisclosureDuplicate(String),
    /// 请求/缺少必要的 Disclosure。
    #[error("disclosure_missing: {0}")]
    DisclosureMissing(String),
    /// 不支持的 `_sd_alg`。
    #[error("sd_alg_unsupported: {0}")]
    SdAlgUnsupported(String),
    /// 后端/存储不可用。
    #[error("Backend unavailable: {0}")]
    BackendUnavailable(String),
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
