//! KVLT 加密密钥文件格式。
//!
//! ```text
//! magic(4) | version(1) | key_type(1) | salt(16) | nonce(12) | ciphertext(*) | tag(16)
//! ```
//! 头部前 22 字节（magic|version|key_type|salt）作为 AEAD 的 AAD。

use crate::KeyVaultError;

/// 文件魔数。
pub const MAGIC: &[u8; 4] = b"KVLT";
/// 当前格式版本。
pub const VERSION: u8 = 0x01;
/// Argon2id salt 长度。
pub const SALT_LEN: usize = 16;
/// ChaCha20-Poly1305 nonce 长度。
pub const NONCE_LEN: usize = 12;
/// Poly1305 tag 长度。
pub const TAG_LEN: usize = 16;
/// 头部长度：magic + version + key_type + salt。
pub const HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN;
/// 最小文件长度：头部 + nonce + tag（空明文也至少这么多）。
pub const MIN_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

/// 密钥类型字节。
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519（32 字节 seed）。
    Ed25519 = 0x01,
    /// sr25519（64 字节 secret）。
    Sr25519 = 0x02,
}

impl KeyType {
    /// 转为文件中的单字节表示。
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// 从文件字节解析；未知值返回 `None`。
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Ed25519),
            0x02 => Some(Self::Sr25519),
            _ => None,
        }
    }
}

/// 解码后的 KVLT 文件内容。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// 密钥类型。
    pub key_type: KeyType,
    /// Argon2id salt。
    pub salt: [u8; SALT_LEN],
    /// ChaCha20-Poly1305 nonce。
    pub nonce: [u8; NONCE_LEN],
    /// 密文（不含 tag）。
    pub ciphertext: Vec<u8>,
    /// Poly1305 tag。
    pub tag: [u8; TAG_LEN],
}

/// 计算 AAD：`magic | version | key_type | salt`。
pub fn header_aad(key_type: KeyType, salt: &[u8; SALT_LEN]) -> [u8; HEADER_LEN] {
    let mut aad = [0u8; HEADER_LEN];
    aad[..4].copy_from_slice(MAGIC);
    aad[4] = VERSION;
    aad[5] = key_type.as_u8();
    aad[6..].copy_from_slice(salt);
    aad
}

/// 编码为 KVLT 文件字节。
pub fn encode(
    key_type: KeyType,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(key_type.as_u8());
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out.extend_from_slice(tag);
    out
}

/// 解码 KVLT 文件字节并校验 magic/version/长度。
pub fn decode(bytes: &[u8]) -> Result<Decoded, KeyVaultError> {
    if bytes.len() < MIN_LEN {
        return Err(KeyVaultError::InvalidKeyFormat(format!(
            "KVLT file too short: {} bytes",
            bytes.len()
        )));
    }
    if &bytes[..4] != MAGIC {
        return Err(KeyVaultError::InvalidKeyFormat("bad KVLT magic".into()));
    }
    if bytes[4] != VERSION {
        return Err(KeyVaultError::InvalidKeyFormat(format!(
            "unsupported KVLT version: {}",
            bytes[4]
        )));
    }
    let key_type = KeyType::from_u8(bytes[5]).ok_or_else(|| {
        KeyVaultError::InvalidKeyFormat(format!("unknown key type: 0x{:02x}", bytes[5]))
    })?;

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[6..6 + SALT_LEN]);

    let nonce_start = 6 + SALT_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[nonce_start..nonce_start + NONCE_LEN]);

    let ciphertext_start = nonce_start + NONCE_LEN;
    let tag_start = bytes.len() - TAG_LEN;
    if tag_start < ciphertext_start {
        return Err(KeyVaultError::InvalidKeyFormat(
            "KVLT length mismatch".into(),
        ));
    }
    let ciphertext = bytes[ciphertext_start..tag_start].to_vec();

    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&bytes[tag_start..]);

    Ok(Decoded {
        key_type,
        salt,
        nonce,
        ciphertext,
        tag,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn roundtrip() {
        let salt = [7u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let tag = [3u8; TAG_LEN];
        let encoded = encode(KeyType::Ed25519, &salt, &nonce, b"cipher", &tag);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.key_type, KeyType::Ed25519);
        assert_eq!(decoded.salt, salt);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.ciphertext, b"cipher");
        assert_eq!(decoded.tag, tag);
    }

    #[test]
    fn rejects_short_or_bad_magic() {
        assert!(decode(b"short").is_err());
        let mut encoded = encode(KeyType::Ed25519, &[0; 16], &[0; 12], b"x", &[0; 16]);
        encoded[0] = b'X';
        assert!(decode(&encoded).is_err());
    }
}
