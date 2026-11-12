//! keyvault-core: 私钥管理抽象与加密文件实现。
//!
//! - [`KeyVault`] 不暴露任何导出私钥的方法；
//! - [`MemoryKeystore`] 用于测试、Mock 模式和显式内存模式；
//! - [`FileKeystore`] 使用 Argon2id + ChaCha20-Poly1305 加密落盘；
//! - [`crypto`] 提供 did:key、Ed25519、sr25519、BLAKE2b 等原语；
//! - [`signing_input`] 是三语言共享的签名对象构造唯一实现。

pub mod crypto;
pub mod signing_input;
/// KeyVault trait 与错误类型。
pub mod trait_;

mod file_keystore;
mod fsutil;
mod memory_keystore;

pub use file_keystore::{
    FileKeystore,
    password::{PasswordSource, resolve_password},
};
pub use memory_keystore::MemoryKeystore;
pub use trait_::{
    KeyAlgorithm, KeyId, KeyNamespace, KeyVault, KeyVaultError, Keypair, PublicKey, Signature,
};
