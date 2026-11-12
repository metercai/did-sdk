//! Ed25519 签名与验签。

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

/// 验证 Ed25519 签名。任何解析失败都返回 `false`，不 panic。
pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(sig) else {
        return false;
    };
    verifying_key.verify_strict(msg, &signature).is_ok()
}

/// 用固定 32 字节种子做确定性签名（仅用于 golden vector 与测试）。
pub fn sign_with_seed(seed: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(seed);
    signing_key.sign(msg).to_bytes().to_vec()
}
