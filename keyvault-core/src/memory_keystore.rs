//! 内存密钥库：测试、Mock 模式与显式 `scheme = "memory-keystore"` 使用。

use std::collections::HashMap;

use async_lock::RwLock;
use async_trait::async_trait;
use ed25519_dalek::Signer as _;
use zeroize::Zeroize;

use crate::crypto::encode_did_key;
use crate::{KeyId, KeyVault, KeyVaultError, Keypair, PublicKey, Signature};

/// 内存密钥库。进程退出后密钥丢失，不落盘。
#[derive(Default)]
pub struct MemoryKeystore {
    keys: RwLock<HashMap<KeyId, Keypair>>,
}

impl MemoryKeystore {
    /// 创建空的内存密钥库。
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KeyVault for MemoryKeystore {
    async fn generate(&self) -> Result<KeyId, KeyVaultError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| KeyVaultError::SigningFailed(format!("entropy unavailable: {e}")))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        seed.zeroize();

        let public = signing_key.verifying_key().to_bytes();
        let key_id = KeyId(encode_did_key(&public));
        self.keys
            .write()
            .await
            .insert(key_id.clone(), Keypair::Ed25519(signing_key));
        Ok(key_id)
    }

    async fn load(&self, key_id: &KeyId) -> Result<(), KeyVaultError> {
        if self.keys.read().await.contains_key(key_id) {
            Ok(())
        } else {
            Err(KeyVaultError::KeyNotFound(key_id.0.clone()))
        }
    }

    async fn sign(&self, key_id: &KeyId, payload: &[u8]) -> Result<Signature, KeyVaultError> {
        let guard = self.keys.read().await;
        let keypair = guard
            .get(key_id)
            .ok_or_else(|| KeyVaultError::KeyNotFound(key_id.0.clone()))?;
        match keypair {
            Keypair::Ed25519(signing_key) => {
                Ok(Signature(signing_key.sign(payload).to_bytes().to_vec()))
            }
            Keypair::Sr25519(secret_key) => {
                let public_key = secret_key.to_public();
                let signature = secret_key.sign_simple(b"substrate", payload, &public_key);
                Ok(Signature(signature.to_bytes().to_vec()))
            }
        }
    }

    async fn public_key(&self, key_id: &KeyId) -> Result<PublicKey, KeyVaultError> {
        let guard = self.keys.read().await;
        let keypair = guard
            .get(key_id)
            .ok_or_else(|| KeyVaultError::KeyNotFound(key_id.0.clone()))?;
        match keypair {
            Keypair::Ed25519(signing_key) => {
                Ok(PublicKey::Ed25519(signing_key.verifying_key().to_bytes()))
            }
            Keypair::Sr25519(secret_key) => {
                Ok(PublicKey::Sr25519(secret_key.to_public().to_bytes()))
            }
        }
    }

    async fn list_keys(&self) -> Result<Vec<KeyId>, KeyVaultError> {
        let mut keys: Vec<KeyId> = self.keys.read().await.keys().cloned().collect();
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(keys)
    }

    async fn delete(&self, key_id: &KeyId) -> Result<(), KeyVaultError> {
        self.keys.write().await.remove(key_id);
        Ok(())
    }
}
