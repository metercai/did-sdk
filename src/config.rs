//! 配置解析与工厂函数。

use std::path::PathBuf;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{CentralizedBackend, ChainBackend, Client, DidSdkError, MockBackend, Server};

/// 后端模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DidSdkMode {
    /// 进程内 Mock。
    #[default]
    Mock,
    /// 中心化只读 HTTP。
    Centralized,
    /// Substrate 只读 storage。
    Chain,
}

/// 密钥库配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct KeyVaultConfig {
    /// scheme。
    pub scheme: String,
    /// 目录。
    pub path: PathBuf,
    /// 密码环境变量名。
    pub password_env: String,
    /// 密码文件。
    pub password_file: PathBuf,
    /// 是否允许自动生成密码。
    pub allow_auto_generate_password: bool,
    /// 是否交互式提示密码。
    pub password_prompt: bool,
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
            password_prompt: false,
        }
    }
}

/// Client 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    /// 后端模式。
    pub mode: DidSdkMode,
    /// VC 存储目录。
    pub vc_storage_path: PathBuf,
    /// 密钥库。
    pub key_vault: KeyVaultConfig,
    /// Centralized 端点。
    pub centralized_endpoint: String,
    /// Chain 端点。
    pub chain_endpoint: String,
    /// Anchor 缓存 TTL。
    pub cache_ttl_secs: u64,
    /// 已解析密码。
    #[serde(skip)]
    pub resolved_password: Option<SecretString>,
}

impl Default for ClientConfig {
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

/// Server 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// 后端模式。
    pub mode: DidSdkMode,
    /// 服务端参与方 did:web。
    pub participant_did: String,
    /// VC 存储目录。
    pub vc_storage_path: PathBuf,
    /// 可选本地签名器（开发/测试/试运行）；生产环境留空。
    pub key_vault: Option<KeyVaultConfig>,
    /// 已解析密码（仅 key_vault 为 Some 时）。
    #[serde(skip)]
    pub resolved_password: Option<SecretString>,
    /// Centralized 端点。
    pub centralized_endpoint: String,
    /// Chain 端点。
    pub chain_endpoint: String,
    /// Anchor 缓存 TTL。
    pub cache_ttl_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let home = default_home();
        Self {
            mode: DidSdkMode::Chain,
            participant_did: String::new(),
            vc_storage_path: home.join("participant-vc-store"),
            key_vault: None,
            resolved_password: None,
            centralized_endpoint: "http://127.0.0.1:8080".into(),
            chain_endpoint: "ws://127.0.0.1:9944".into(),
            cache_ttl_secs: 600,
        }
    }
}

/// 兼容旧名称：默认指 Client 配置。
pub type DidSdkConfig = ClientConfig;

/// 显式覆盖。
#[derive(Debug, Default, Clone, Deserialize)]
pub struct ConfigOverrides {
    /// 模式字符串。
    pub mode: Option<String>,
    /// VC 目录。
    pub vc_storage_path: Option<PathBuf>,
    /// key 目录。
    pub key_vault_path: Option<PathBuf>,
    /// scheme。
    pub key_vault_scheme: Option<String>,
    /// 密码。
    pub key_vault_password: Option<String>,
    /// Centralized 端点。
    pub centralized_endpoint: Option<String>,
    /// Chain 端点。
    pub chain_endpoint: Option<String>,
    /// TTL。
    pub cache_ttl_secs: Option<u64>,
    /// 密码文件。
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
    did_sdk: Option<FileSection>,
    mode: Option<DidSdkMode>,
    vc_storage_path: Option<PathBuf>,
    key_vault: Option<FileKeyVaultConfig>,
    centralized_endpoint: Option<String>,
    chain_endpoint: Option<String>,
    cache_ttl_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct FileSection {
    mode: Option<DidSdkMode>,
    vc_storage_path: Option<PathBuf>,
    key_vault: Option<FileKeyVaultConfig>,
    centralized: Option<EndpointSection>,
    chain: Option<EndpointSection>,
    cache_ttl_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct EndpointSection {
    endpoint: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FileKeyVaultConfig {
    scheme: Option<String>,
    path: Option<PathBuf>,
    password_env: Option<String>,
    password_file: Option<PathBuf>,
    allow_auto_generate_password: Option<bool>,
    password_prompt: Option<bool>,
}

/// 解析 Client 配置。
pub fn resolve_config(overrides: ConfigOverrides) -> Result<ClientConfig, DidSdkError> {
    let mut config = ClientConfig::default();
    apply_config_file(&mut config)?;
    apply_env(&mut config);
    apply_overrides(&mut config, overrides);
    if config.resolved_password.is_none() {
        config.resolved_password = Some(resolve_password(&config)?);
    }
    Ok(config)
}

fn apply_config_file(config: &mut ClientConfig) -> Result<(), DidSdkError> {
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
        .map_err(|error| DidSdkError::ConfigError(format!("read {}: {error}", path.display())))?;
    let file: FileConfig = toml::from_str(&raw)
        .map_err(|error| DidSdkError::ConfigError(format!("parse {}: {error}", path.display())))?;
    merge_file(config, file);
    Ok(())
}

fn merge_file(config: &mut ClientConfig, file: FileConfig) {
    apply_file_section(config, file.did_sdk);
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
        merge_key_vault(&mut config.key_vault, key_vault);
    }
}

fn apply_file_section(config: &mut ClientConfig, section: Option<FileSection>) {
    let Some(section) = section else {
        return;
    };
    if let Some(mode) = section.mode {
        config.mode = mode;
    }
    if let Some(path) = section.vc_storage_path {
        config.vc_storage_path = path;
    }
    if let Some(ttl) = section.cache_ttl_secs {
        config.cache_ttl_secs = ttl;
    }
    if let Some(endpoint) = section.centralized.and_then(|value| value.endpoint) {
        config.centralized_endpoint = endpoint;
    }
    if let Some(endpoint) = section.chain.and_then(|value| value.endpoint) {
        config.chain_endpoint = endpoint;
    }
    if let Some(key_vault) = section.key_vault {
        merge_key_vault(&mut config.key_vault, key_vault);
    }
}

fn merge_key_vault(target: &mut KeyVaultConfig, key_vault: FileKeyVaultConfig) {
    if let Some(scheme) = key_vault.scheme {
        target.scheme = scheme;
    }
    if let Some(path) = key_vault.path {
        target.path = path;
    }
    if let Some(name) = key_vault.password_env {
        target.password_env = name;
    }
    if let Some(path) = key_vault.password_file {
        target.password_file = path;
    }
    if let Some(allow) = key_vault.allow_auto_generate_password {
        target.allow_auto_generate_password = allow;
    }
    if let Some(prompt) = key_vault.password_prompt {
        target.password_prompt = prompt;
    }
}

fn apply_env(config: &mut ClientConfig) {
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

fn apply_overrides(config: &mut ClientConfig, overrides: ConfigOverrides) {
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

fn resolve_keyvault_password(config: &KeyVaultConfig) -> Result<SecretString, DidSdkError> {
    use keyvault_core::{PasswordSource, resolve_password as kv_resolve};

    if config.password_prompt {
        return kv_resolve(&PasswordSource::Prompt)
            .map_err(|error| DidSdkError::ConfigError(error.to_string()));
    }
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
    kv_resolve(&source).map_err(|error| DidSdkError::ConfigError(error.to_string()))
}

fn resolve_password(config: &ClientConfig) -> Result<SecretString, DidSdkError> {
    resolve_keyvault_password(&config.key_vault)
}

fn build_vault(config: &ClientConfig) -> Result<Arc<dyn keyvault_core::KeyVault>, DidSdkError> {
    let password = config
        .resolved_password
        .clone()
        .ok_or_else(|| DidSdkError::ConfigError("keystore password was not resolved".into()))?;
    build_vault_with(&config.key_vault, &password)
}

fn build_vault_with(
    config: &KeyVaultConfig,
    password: &SecretString,
) -> Result<Arc<dyn keyvault_core::KeyVault>, DidSdkError> {
    match config.scheme.as_str() {
        "file-keystore" => {
            let password = SecretString::from(password.expose_secret().to_owned());
            let vault = keyvault_core::FileKeystore::new(config.path.clone(), password)
                .map_err(|error| DidSdkError::ConfigError(error.to_string()))?;
            Ok(Arc::new(vault))
        }
        "memory-keystore" => Ok(Arc::new(keyvault_core::MemoryKeystore::new())),
        other => Err(DidSdkError::Unsupported(format!(
            "key_vault.scheme = {other}"
        ))),
    }
}

fn build_backend(
    mode: DidSdkMode,
    centralized_endpoint: &str,
    chain_endpoint: &str,
    ttl_secs: u64,
) -> Result<Arc<dyn crate::backend::Backend>, DidSdkError> {
    match mode {
        DidSdkMode::Mock => Ok(Arc::new(MockBackend::new())),
        DidSdkMode::Centralized => Ok(Arc::new(CentralizedBackend::new(
            centralized_endpoint.to_string(),
            ttl_secs,
        )?)),
        DidSdkMode::Chain => Ok(Arc::new(ChainBackend::new(
            chain_endpoint.to_string(),
            ttl_secs,
        ))),
    }
}

/// 构建 Client SDK。
pub fn build_client_sdk(
    config: &ClientConfig,
) -> Result<Arc<crate::DidSdk<crate::Client>>, DidSdkError> {
    let vault = build_vault(config)?;
    let backend = build_backend(
        config.mode,
        &config.centralized_endpoint,
        &config.chain_endpoint,
        config.cache_ttl_secs,
    )?;
    build_client_sdk_with_backend(config, backend, vault)
}

/// 用调用方提供的 backend/vault 构建 Client（测试与高级装配）。
pub fn build_client_sdk_with_backend(
    config: &ClientConfig,
    backend: Arc<dyn crate::backend::Backend>,
    vault: Arc<dyn keyvault_core::KeyVault>,
) -> Result<Arc<crate::DidSdk<crate::Client>>, DidSdkError> {
    Ok(Arc::new(crate::DidSdk::<Client>::new(
        backend,
        Some(vault),
        None,
        config.vc_storage_path.clone(),
    )?))
}

/// 构建 Server SDK。
pub fn build_server_sdk(
    config: &ServerConfig,
) -> Result<Arc<crate::DidSdk<crate::Server>>, DidSdkError> {
    if config.participant_did.is_empty() {
        return Err(DidSdkError::ConfigError(
            "server participant_did is required".into(),
        ));
    }
    let backend = build_backend(
        config.mode,
        &config.centralized_endpoint,
        &config.chain_endpoint,
        config.cache_ttl_secs,
    )?;
    build_server_sdk_with_backend(config, backend)
}

/// 用调用方提供的 backend 构建 Server（测试与高级装配）。
pub fn build_server_sdk_with_backend(
    config: &ServerConfig,
    backend: Arc<dyn crate::backend::Backend>,
) -> Result<Arc<crate::DidSdk<crate::Server>>, DidSdkError> {
    if config.participant_did.is_empty() {
        return Err(DidSdkError::ConfigError(
            "server participant_did is required".into(),
        ));
    }
    let vault = match &config.key_vault {
        Some(key_vault) => {
            let password = match &config.resolved_password {
                Some(password) => password.clone(),
                None => resolve_keyvault_password(key_vault)?,
            };
            Some(build_vault_with(key_vault, &password)?)
        }
        None => None,
    };
    Ok(Arc::new(crate::DidSdk::<Server>::new(
        backend,
        vault,
        Some(config.participant_did.clone()),
        config.vc_storage_path.clone(),
    )?))
}

/// 兼容旧调用：构建 Client。
pub fn build_did_sdk(
    config: &ClientConfig,
) -> Result<Arc<crate::DidSdk<crate::Client>>, DidSdkError> {
    build_client_sdk(config)
}
