//! BLAKE2b-256 哈希。

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

/// 计算 BLAKE2b 的 256 位摘要。
pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
