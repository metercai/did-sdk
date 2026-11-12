//! base58btc 编解码的薄封装。

use crate::KeyVaultError;

/// 将字节编码为 base58btc 字符串。
pub fn encode(data: &[u8]) -> String {
    bs58::encode(data).into_string()
}

/// 解码 base58btc 字符串。
pub fn decode(input: &str) -> Result<Vec<u8>, KeyVaultError> {
    bs58::decode(input)
        .into_vec()
        .map_err(|e| KeyVaultError::InvalidKeyFormat(format!("invalid base58: {e}")))
}
