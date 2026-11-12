//! 密码学原语与编码工具。

pub mod base58;
pub mod blake2;
pub mod ed25519;
pub mod multibase;
pub mod sr25519;

pub use multibase::{decode_did_key_pubkey, encode_did_key};
