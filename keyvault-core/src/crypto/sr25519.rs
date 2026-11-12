//! sr25519（schnorrkel）验签。
//!
//! 签名上下文固定为 `b"substrate"`，与 Substrate 生态一致。

use schnorrkel::{PublicKey, Signature, signing_context};

/// 验证 sr25519 签名。任何解析失败都返回 `false`，不 panic。
pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(public_key) = PublicKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::from_bytes(sig) else {
        return false;
    };
    let context = signing_context(b"substrate");
    public_key.verify(context.bytes(msg), &signature).is_ok()
}
