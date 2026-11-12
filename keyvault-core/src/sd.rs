//! SD-JWT 选择性披露原语：盐值、base64url、盐化哈希。
//!
//! 哈希公式（与附件一致）：
//! `SHA-256(base64url(salt) || base64url(name) || base64url(value))`。

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::KeyVaultError;

/// 默认盐长度（字节）。
pub const SALT_LENGTH: usize = 16;

/// 生成 16 字节 CSPRNG 盐。
pub fn generate_salt() -> Result<[u8; SALT_LENGTH], KeyVaultError> {
    let mut salt = [0u8; SALT_LENGTH];
    getrandom::fill(&mut salt)
        .map_err(|error| KeyVaultError::SigningFailed(format!("entropy: {error}")))?;
    Ok(salt)
}

/// base64url（无 padding）。
pub fn base64url_encode(data: &[u8]) -> String {
    multibase::encode(multibase::Base::Base64Url, data)
        .split_once('u')
        .map(|(_, value)| value.to_string())
        .unwrap_or_default()
}

/// base64url 解码（无 padding）。
pub fn base64url_decode(value: &str) -> Result<Vec<u8>, KeyVaultError> {
    let (_, bytes) = multibase::decode(format!("u{value}"))
        .map_err(|error| KeyVaultError::SerializationError(format!("base64url: {error}")))?;
    Ok(bytes)
}

fn normalized_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// 用盐字节计算 Disclosure 的 SHA-256（返回原始 32 字节）。
pub fn disclosure_hash(salt: &[u8], name: &str, value: &Value) -> Result<[u8; 32], KeyVaultError> {
    let mut hasher = Sha256::new();
    hasher.update(base64url_encode(salt).as_bytes());
    hasher.update(base64url_encode(name.as_bytes()).as_bytes());
    hasher.update(base64url_encode(normalized_value(value).as_bytes()).as_bytes());
    Ok(hasher.finalize().into())
}

/// 用 base64url 盐字符串计算 Disclosure 哈希。
pub fn disclosure_hash_b64(
    salt_b64: &str,
    name: &str,
    value: &Value,
) -> Result<[u8; 32], KeyVaultError> {
    let salt = base64url_decode(salt_b64)?;
    disclosure_hash(&salt, name, value)
}

/// 计算 Disclosure 哈希的 base64url 表示（写入 `_sd`）。
pub fn disclosure_hash_string(
    salt: &[u8],
    name: &str,
    value: &Value,
) -> Result<String, KeyVaultError> {
    Ok(base64url_encode(&disclosure_hash(salt, name, value)?))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn hash_formula_is_stable() {
        let value = serde_json::json!("Alice");
        let first = disclosure_hash_string(b"salt-16-bytes-xx", "name", &value).unwrap();
        let second = disclosure_hash_string(b"salt-16-bytes-xx", "name", &value).unwrap();
        assert_eq!(first, second);
        assert_ne!(
            first,
            disclosure_hash_string(b"salt-16-bytes-xy", "name", &value).unwrap()
        );
    }

    #[test]
    fn base64url_roundtrip() {
        let data = [0u8, 1, 2, 250, 251, 252];
        let encoded = base64url_encode(&data);
        assert!(!encoded.contains('='));
        assert_eq!(base64url_decode(&encoded).unwrap(), data);
    }
}
