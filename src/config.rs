//! 配置解析：内置默认值 + 环境变量 + 可选 TOML + 显式覆盖。
//!
//! 优先级：**显式 overrides > 环境变量 > TOML 文件 > 内置默认值**。
//! 密码单独一条链：`DID_SDK_KEYVAULT_PASSWORD` → `password_file` →
//! 自动生成（仅当允许）→ 报错。

use std::path::PathBuf;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::DidSdkError;

/// 运行模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DidSdkMode {
    /// 进程内 Mock，无外部依赖。
    #[default]
    Mock,
    /// 中心化服务只读 HTTP。
    Centralized,
    /// Substrate 链只读 storage。
    Chain,
}

/// 密钥库配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyVaultConfig {
    /// `file-keystore` 或 `memory-keystore`。
    pub scheme: String,
    /// 密钥库目录。
    pub path: PathBuf,
    /// 密码环境变量名。
    pub password_env: String,
    /// 密码文件路径。
    pub password_file: PathBuf,
    /// 是否允许自动生成密码（POC 免配置）。
    pub allow_auto_generate_password: bool,
}

impl Default for KeyVaultConfig {
    fn default() -> Self {
        let home = default_home();
        Self {
            scheme: "file-keystore".into(),
            path: home.join("identity-keys"),
            password_env: "DID_SDK_KEYVAULT_PASSWORD".into(),
            password_file: home.join("keyvault.password"),
            allow_auto_generate_password: true,
        }
    }
}

/// SDK 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DidSdkConfig {
    /// 运行模式。
    pub mode: DidSdkMode,
    /// VC 本地存储目录。
    pub vc_storage_path: PathBuf,
    /// 密钥库配置。
    pub key_vault: KeyVaultConfig,
    /// Centralized 端点。
    pub centralized_endpoint: String,
    /// Chain 端点。
    pub chain_endpoint: String,
    /// Anchor 缓存 TTL（秒）。
    pub cache_ttl_secs: u64,
    /// 已解析的密码；不序列化、不打印。
    #[serde(skip)]
    pub resolved_password: Option<SecretString>,
}

impl Default for DidSdkConfig {
    fn default() -> Self {
        let home = default_home();
        Self {
            mode: DidSdkMode::Mock,
            vc_storage_path: home.join("vc_store"),
            key_vault: KeyVaultConfig::default(),
            centralized_endpoint: "http://127.0.0.1:8080".into(),
            chain_endpoint: "ws://127.0.0.1:9944".into(),
            cache_ttl_secs: 600,
            resolved_password: None,
        }
    }
}

/// 显式覆盖：Rust 调用者、Python/Node 构造函数传入。
#[derive(Debug, Default, Clone, Deserialize)]
pub struct ConfigOverrides {
    /// 模式字符串。
    pub mode: Option<String>,
    /// VC 存储目录。
    pub vc_storage_path: Option<PathBuf>,
    /// 密钥库目录。
    pub key_vault_path: Option<PathBuf>,
    /// 密钥库 scheme。
    pub key_vault_scheme: Option<String>,
    /// 密钥库密码（最高优先）。
    pub key_vault_password: Option<String>,
    /// Centralized 端点。
    pub centralized_endpoint: Option<String>,
    /// Chain 端点。
    pub chain_endpoint: Option<String>,
    /// 缓存 TTL。
    pub cache_ttl_secs: Option<u64>,
    /// 密码文件路径。
    pub key_vault_password_file: Option<PathBuf>,
}

fn default_home() -> PathBuf {
    if let Ok(value) = std::env::var("DID_SDK_HOME") {
        if !value.is_empty() {
            return PathBuf::from(value);
        }
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("did-sdk")
}

fn parse_mode(value: &str) -> Option<DidSdkMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "mock" => Some(DidSdkMode::Mock),
        "centralized" => Some(DidSdkMode::Centralized),
        "chain" => Some(DidSdkMode::Chain),
        _ => None,
    }
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    mode: Option<DidSdkMode>,
    vc_storage_path: Option<PathBuf>,
    key_vault: Option<FileKeyVaultConfig>,
    centralized_endpoint: Option<String>,
    chain_endpoint: Option<String>,
    cache_ttl_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct FileKeyVaultConfig {
    scheme: Option<String>,
    path: Option<PathBuf>,
    password_env: Option<String>,
    password_file: Option<PathBuf>,
    allow_auto_generate_password: Option<bool>,
}

/// 解析配置。
pub fn resolve_config(overrides: ConfigOverrides) -> Result<DidSdkConfig, DidSdkError> {
    let mut config = DidSdkConfig::default();
    apply_config_file(&mut config)?;
    apply_env(&mut config);
    apply_overrides(&mut config, overrides);
    if config.resolved_password.is_none() {
        config.resolved_password = Some(resolve_password(&config.key_vault)?);
    }
    Ok(config)
}

fn apply_config_file(config: &mut DidSdkConfig) -> Result<(), DidSdkError> {
    let path = match std::env::var("DID_SDK_CONFIG_FILE") {
        Ok(value) if !value.is_empty() => Some(PathBuf::from(value)),
        _ => {
            let default_path = default_home().join("did-sdk.toml");
            default_path.exists().then_some(default_path)
        }
    };
    let Some(path) = path else {
        return Ok(());
    };
    if !path.exists() {
        return Ok(());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| DidSdkError::ConfigError(format!("read {}: {e}", path.display())))?;
    let file: FileConfig = toml::from_str(&raw)
        .map_err(|e| DidSdkError::ConfigError(format!("parse {}: {e}", path.display())))?;
    merge_file(config, file);
    Ok(())
}

fn merge_file(config: &mut DidSdkConfig, file: FileConfig) {
    if let Some(mode) = file.mode {
        config.mode = mode;
    }
    if let Some(path) = file.vc_storage_path {
        config.vc_storage_path = path;
    }
    if let Some(endpoint) = file.centralized_endpoint {
        config.centralized_endpoint = endpoint;
    }
    if let Some(endpoint) = file.chain_endpoint {
        config.chain_endpoint = endpoint;
    }
    if let Some(ttl) = file.cache_ttl_secs {
        config.cache_ttl_secs = ttl;
    }
    if let Some(key_vault) = file.key_vault {
        if let Some(scheme) = key_vault.scheme {
            config.key_vault.scheme = scheme;
        }
        if let Some(path) = key_vault.path {
            config.key_vault.path = path;
        }
        if let Some(password_env) = key_vault.password_env {
            config.key_vault.password_env = password_env;
        }
        if let Some(password_file) = key_vault.password_file {
            config.key_vault.password_file = password_file;
        }
        if let Some(allow) = key_vault.allow_auto_generate_password {
            config.key_vault.allow_auto_generate_password = allow;
        }
    }
}

fn apply_env(config: &mut DidSdkConfig) {
    if let Ok(value) = std::env::var("DID_SDK_MODE") {
        if let Some(mode) = parse_mode(&value) {
            config.mode = mode;
        }
    }
    if let Ok(value) = std::env::var("DID_SDK_VC_STORAGE_PATH") {
        config.vc_storage_path = value.into();
    }
    if let Ok(value) = std::env::var("DID_SDK_KEYVAULT_PATH") {
        config.key_vault.path = value.into();
    }
    if let Ok(value) = std::env::var("DID_SDK_KEYVAULT_SCHEME") {
        config.key_vault.scheme = value;
    }
    if let Ok(value) = std::env::var("DID_SDK_KEYVAULT_PASSWORD_FILE") {
        config.key_vault.password_file = value.into();
    }
    if let Ok(value) = std::env::var("DID_SDK_CENTRALIZED_ENDPOINT") {
        config.centralized_endpoint = value;
    }
    if let Ok(value) = std::env::var("DID_SDK_CHAIN_ENDPOINT") {
        config.chain_endpoint = value;
    }
    if let Ok(value) = std::env::var("DID_SDK_CACHE_TTL_SECS") {
        if let Ok(ttl) = value.parse() {
            config.cache_ttl_secs = ttl;
        }
    }
}

fn apply_overrides(config: &mut DidSdkConfig, overrides: ConfigOverrides) {
    if let Some(mode) = overrides.mode.as_deref().and_then(parse_mode) {
        config.mode = mode;
    }
    if let Some(path) = overrides.vc_storage_path {
        config.vc_storage_path = path;
    }
    if let Some(path) = overrides.key_vault_path {
        config.key_vault.path = path;
    }
    if let Some(scheme) = overrides.key_vault_scheme {
        config.key_vault.scheme = scheme;
    }
    if let Some(endpoint) = overrides.centralized_endpoint {
        config.centralized_endpoint = endpoint;
    }
    if let Some(endpoint) = overrides.chain_endpoint {
        config.chain_endpoint = endpoint;
    }
    if let Some(ttl) = overrides.cache_ttl_secs {
        config.cache_ttl_secs = ttl;
    }
    if let Some(path) = overrides.key_vault_password_file {
        config.key_vault.password_file = path;
    }
    if let Some(password) = overrides.key_vault_password {
        config.resolved_password = Some(SecretString::from(password));
    }
}

fn resolve_password(config: &KeyVaultConfig) -> Result<SecretString, DidSdkError> {
    use keyvault_core::{PasswordSource, resolve_password as kv_resolve};

    if let Ok(password) = std::env::var(&config.password_env) {
        if !password.is_empty() {
            return Ok(SecretString::from(password));
        }
    }

    let source = if config.password_file.exists() {
        PasswordSource::File(config.password_file.clone())
    } else if config.allow_auto_generate_password {
        PasswordSource::AutoGenerate {
            target_file: config.password_file.clone(),
        }
    } else {
        return Err(DidSdkError::ConfigError(
            "keystore password unavailable: set DID_SDK_KEYVAULT_PASSWORD or password_file".into(),
        ));
    };
    kv_resolve(&source).map_err(|e| DidSdkError::ConfigError(e.to_string()))
}

/// 构建 KeyVault。
pub fn build_vault(config: &DidSdkConfig) -> Result<Arc<dyn keyvault_core::KeyVault>, DidSdkError> {
    match config.key_vault.scheme.as_str() {
        "file-keystore" => {
            let password = config.resolved_password.as_ref().ok_or_else(|| {
                DidSdkError::ConfigError("keystore password was not resolved".into())
            })?;
            let password = SecretString::from(password.expose_secret().to_owned());
            let vault = keyvault_core::FileKeystore::new(config.key_vault.path.clone(), password)
                .map_err(|e| DidSdkError::ConfigError(e.to_string()))?;
            Ok(Arc::new(vault))
        }
        "memory-keystore" => Ok(Arc::new(keyvault_core::MemoryKeystore::new())),
        // 预留：未来接入 keyvault-device / keyvault-server 时在此加分支，
        // 并通过 Cargo feature 门控，避免默认构建拉入平台安全区依赖。
        other => Err(DidSdkError::Unsupported(format!(
            "key_vault.scheme = {other}"
        ))),
    }
}

/// 三模式统一工厂。
pub fn build_did_sdk(config: &DidSdkConfig) -> Result<Arc<dyn crate::DidSdk>, DidSdkError> {
    let vault = build_vault(config)?;
    match config.mode {
        DidSdkMode::Mock => Ok(Arc::new(crate::mock::MockDidSdk::new(
            vault,
            config.clone(),
        )?)),
        DidSdkMode::Centralized => Ok(Arc::new(crate::centralized::CentralizedDidSdk::new(
            vault,
            config.clone(),
        )?)),
        DidSdkMode::Chain => Ok(Arc::new(crate::chain::ChainModeDidSdk::new(
            vault,
            config.clone(),
        )?)),
    }
}
