//! 密码来源解析。
//!
//! 密码优先级（由 `did-sdk` 配置层组织）：
//! `DID_SDK_KEYVAULT_PASSWORD` → `password_file` → 自动生成 → 报错。

use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use crate::KeyVaultError;
use crate::fsutil::{create_private_file, read_trimmed};

/// 密码来源。
pub enum PasswordSource {
    /// 从环境变量读取（缺失即错误，不回退）。
    Env(String),
    /// 从文件读取（去掉行尾换行）。
    File(PathBuf),
    /// 调用方直接提供。
    Direct(SecretString),
    /// 从标准输入交互读取（POC；终端可能回显，生产应使用无回显实现）。
    Prompt,
    /// 环境变量缺失且文件不存在时，生成随机密码并写入 0600 文件（POC 免配置）。
    AutoGenerate {
        /// 目标密码文件路径。
        target_file: PathBuf,
    },
}

/// 解析密码。
///
/// - `Env`：变量缺失或为空时返回 `IoError`；
/// - `File`：文件不存在/为空时返回错误；
/// - `Direct`：原样返回；
/// - `AutoGenerate`：文件已存在则读取（不覆盖），否则生成 32 字节随机数并
///   base58 编码写入；Unix 权限 `0600`。
pub fn resolve_password(source: &PasswordSource) -> Result<SecretString, KeyVaultError> {
    match source {
        PasswordSource::Env(name) => {
            let value = std::env::var(name).map_err(|_| {
                KeyVaultError::IoError(format!("environment variable {name} is not set"))
            })?;
            if value.is_empty() {
                return Err(KeyVaultError::InvalidPassword);
            }
            Ok(SecretString::from(value))
        }
        PasswordSource::File(path) => {
            let value = read_trimmed(path).map_err(|e| match e.kind() {
                std::io::ErrorKind::InvalidData => KeyVaultError::InvalidPassword,
                _ => KeyVaultError::IoError(e.to_string()),
            })?;
            Ok(SecretString::from(value))
        }
        PasswordSource::Direct(secret) => Ok(SecretString::from(secret.expose_secret().to_owned())),
        PasswordSource::Prompt => prompt_password(),
        PasswordSource::AutoGenerate { target_file } => auto_generate(target_file),
    }
}

fn prompt_password() -> Result<SecretString, KeyVaultError> {
    use std::io::Write as _;
    eprint!("KeyVault password: ");
    std::io::stderr().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    let value = value.trim_end_matches(['\r', '\n']).to_string();
    if value.is_empty() {
        return Err(KeyVaultError::InvalidPassword);
    }
    Ok(SecretString::from(value))
}

fn auto_generate(target_file: &Path) -> Result<SecretString, KeyVaultError> {
    if target_file.exists() {
        let value = read_trimmed(target_file)?;
        return Ok(SecretString::from(value));
    }

    let mut random = [0u8; 32];
    getrandom::fill(&mut random)
        .map_err(|e| KeyVaultError::SigningFailed(format!("entropy unavailable: {e}")))?;
    let password = bs58::encode(random).into_string();
    random.fill(0);

    if create_private_file(target_file, password.as_bytes())? {
        tracing::warn!(
            path = %target_file.display(),
            "did-sdk generated a new keyvault password file (POC convenience); \
             set DID_SDK_KEYVAULT_PASSWORD or password_file in production"
        );
        Ok(SecretString::from(password))
    } else {
        // 另一个进程抢先创建：读取它写入的值。
        let value = read_trimmed(target_file)?;
        Ok(SecretString::from(value))
    }
}
