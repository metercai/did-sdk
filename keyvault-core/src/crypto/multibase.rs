//! `did:key` 编解码。
//!
//! Ed25519 的 multicodec 前缀为 `0xED 0x01`，后接 32 字节公钥；
//! 使用 multibase base58btc（前缀字符 `z`）。
//! 完整字符串形如 `did:key:z6Mk...`。

use multibase::Base;

use crate::KeyVaultError;

/// `did:key:` 前缀。
pub const DID_KEY_PREFIX: &str = "did:key:";

/// 根据 32 字节 Ed25519 公钥生成 `did:key` 字符串。
pub fn encode_did_key(pubkey: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(34);
    data.extend_from_slice(&[0xED, 0x01]);
    data.extend_from_slice(pubkey);
    format!(
        "{DID_KEY_PREFIX}{}",
        multibase::encode(Base::Base58Btc, data)
    )
}

/// 从 `did:key` 字符串解析 Ed25519 公钥。
///
/// 只接受 `0xED 0x01` 前缀的 32 字节公钥；其他 multicodec 或长度返回
/// [`KeyVaultError::InvalidKeyFormat`]。
pub fn decode_did_key_pubkey(did: &str) -> Result<[u8; 32], KeyVaultError> {
    let encoded = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or_else(|| KeyVaultError::InvalidKeyFormat(format!("not a did:key: {did}")))?;
    let (base, data) = multibase::decode(encoded)
        .map_err(|e| KeyVaultError::InvalidKeyFormat(format!("invalid multibase: {e}")))?;
    if base != Base::Base58Btc {
        return Err(KeyVaultError::InvalidKeyFormat(format!(
            "unsupported multibase {base:?}"
        )));
    }
    if data.len() != 34 || data[0] != 0xED || data[1] != 0x01 {
        return Err(KeyVaultError::InvalidKeyFormat(
            "unsupported did:key multicodec (expected Ed25519 0xED01)".into(),
        ));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&data[2..]);
    Ok(pubkey)
}
