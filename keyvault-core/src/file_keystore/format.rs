//! KVLT 加密密钥文件格式（v2，含 namespace/algorithm）。
//!
//! ```text
//! magic(4) | version(1) | namespace(1) | algorithm(1) | salt(16) | nonce(12) | ciphertext(*) | tag(16)
//! ```
//! 头部（magic|version|namespace|algorithm|salt）作为 AEAD 的 AAD。

use crate::{KeyAlgorithm, KeyNamespace, KeyVaultError};

/// 文件魔数。
pub const MAGIC: &[u8; 4] = b"KVLT";
/// 当前格式版本。
pub const VERSION: u8 = 0x02;
/// Argon2id salt 长度。
pub const SALT_LEN: usize = 16;
/// ChaCha20-Poly1305 nonce 长度。
pub const NONCE_LEN: usize = 12;
/// Poly1305 tag 长度。
pub const TAG_LEN: usize = 16;
/// 头部长度：magic + version + namespace + algorithm + salt。
pub const HEADER_LEN: usize = 4 + 1 + 1 + 1 + SALT_LEN;
/// 最小文件长度：头部 + nonce + tag。
pub const MIN_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

/// 解码后的 KVLT 文件内容。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// namespace。
    pub namespace: KeyNamespace,
    /// algorithm。
    pub algorithm: KeyAlgorithm,
    /// Argon2id salt。
    pub salt: [u8; SALT_LEN],
    /// ChaCha20-Poly1305 nonce。
    pub nonce: [u8; NONCE_LEN],
    /// 密文（不含 tag）。
    pub ciphertext: Vec<u8>,
    /// Poly1305 tag。
    pub tag: [u8; TAG_LEN],
}

/// 计算 AAD：`magic | version | namespace | algorithm | salt`。
pub fn header_aad(
    namespace: KeyNamespace,
    algorithm: KeyAlgorithm,
    salt: &[u8; SALT_LEN],
) -> [u8; HEADER_LEN] {
    let mut aad = [0u8; HEADER_LEN];
    aad[..4].copy_from_slice(MAGIC);
    aad[4] = VERSION;
    aad[5] = namespace.as_u8();
    aad[6] = algorithm.as_u8();
    aad[7..].copy_from_slice(salt);
    aad
}

/// 编码为 KVLT 文件字节。
pub fn encode(
    namespace: KeyNamespace,
    algorithm: KeyAlgorithm,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MIN_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(namespace.as_u8());
    out.push(algorithm.as_u8());
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
    let namespace = KeyNamespace::from_u8(bytes[5]).ok_or_else(|| {
        KeyVaultError::InvalidKeyFormat(format!("unknown namespace: 0x{:02x}", bytes[5]))
    })?;
    let algorithm = KeyAlgorithm::from_u8(bytes[6]).ok_or_else(|| {
        KeyVaultError::InvalidKeyFormat(format!("unknown algorithm: 0x{:02x}", bytes[6]))
    })?;

    let salt_start = 7;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[salt_start..salt_start + SALT_LEN]);

    let nonce_start = salt_start + SALT_LEN;
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
        namespace,
        algorithm,
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
        let encoded = encode(
            KeyNamespace::ClientDid,
            KeyAlgorithm::Ed25519,
            &salt,
            &nonce,
            b"cipher",
            &tag,
        );
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.namespace, KeyNamespace::ClientDid);
        assert_eq!(decoded.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(decoded.salt, salt);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.ciphertext, b"cipher");
        assert_eq!(decoded.tag, tag);
    }

    #[test]
    fn rejects_short_or_bad_magic() {
        assert!(decode(b"short").is_err());
        let mut encoded = encode(
            KeyNamespace::ClientDid,
            KeyAlgorithm::Ed25519,
            &[0; 16],
            &[0; 12],
            b"x",
            &[0; 16],
        );
        encoded[0] = b'X';
        assert!(decode(&encoded).is_err());
    }
}

#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = super::decode(&bytes);
        }
    }
}
