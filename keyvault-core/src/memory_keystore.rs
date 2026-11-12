//! 内存密钥库：测试、Mock 模式与显式 `scheme = "memory-keystore"` 使用。

use std::collections::HashMap;

use async_lock::RwLock;
use async_trait::async_trait;
use ed25519_dalek::Signer as _;
use zeroize::Zeroize;

use crate::crypto::{account_id_to_ss58, encode_did_key};
use crate::{
    KeyAlgorithm, KeyId, KeyNamespace, KeyVault, KeyVaultError, Keypair, PublicKey, Signature,
};

type Entry = (KeyNamespace, KeyAlgorithm, Keypair);

/// 内存密钥库。进程退出后密钥丢失，不落盘。
#[derive(Default)]
pub struct MemoryKeystore {
    keys: RwLock<HashMap<KeyId, Entry>>,
}

impl MemoryKeystore {
    /// 创建空的内存密钥库。
    pub fn new() -> Self {
        Self::default()
    }

    fn generate_ed25519() -> Result<(Keypair, String), KeyVaultError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| KeyVaultError::SigningFailed(format!("entropy unavailable: {e}")))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        seed.zeroize();
        let public = signing_key.verifying_key().to_bytes();
        let local_id = encode_did_key(&public)
            .strip_prefix("did:key:")
            .unwrap_or_default()
            .to_string();
        Ok((Keypair::Ed25519(signing_key), format!("did_key_{local_id}")))
    }

    fn generate_sr25519() -> Result<(Keypair, String), KeyVaultError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| KeyVaultError::SigningFailed(format!("entropy unavailable: {e}")))?;
        let mini = schnorrkel::MiniSecretKey::from_bytes(&seed)
            .map_err(|e| KeyVaultError::SigningFailed(format!("invalid sr25519 seed: {e}")))?;
        seed.zeroize();
        let secret = mini.expand(schnorrkel::ExpansionMode::Ed25519);
        let public = secret.to_public().to_bytes();
        let local_id = account_id_to_ss58(&public, 42);
        Ok((Keypair::Sr25519(secret), local_id))
    }
}

#[async_trait]
impl KeyVault for MemoryKeystore {
    async fn generate(
        &self,
        namespace: KeyNamespace,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyId, KeyVaultError> {
        if namespace.allowed_algorithm() != algorithm {
            return Err(KeyVaultError::AlgorithmMismatch {
                key: namespace.prefix().to_string(),
                actual: namespace.allowed_algorithm(),
                expected: algorithm,
            });
        }
        let (keypair, local_id) = match algorithm {
            KeyAlgorithm::Ed25519 => Self::generate_ed25519()?,
            KeyAlgorithm::Sr25519 => Self::generate_sr25519()?,
        };
        let key_id = KeyId::new(namespace, &local_id);
        self.keys
            .write()
            .await
            .insert(key_id.clone(), (namespace, algorithm, keypair));
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
        let (namespace, algorithm, keypair) = guard
            .get(key_id)
            .ok_or_else(|| KeyVaultError::KeyNotFound(key_id.0.clone()))?;
        let actual_namespace = key_id.namespace().ok_or_else(|| {
            KeyVaultError::InvalidKeyFormat(format!("missing namespace prefix: {}", key_id.0))
        })?;
        if *namespace != actual_namespace {
            return Err(KeyVaultError::NamespaceViolation {
                key: key_id.0.clone(),
                actual: *namespace,
                expected: actual_namespace,
            });
        }
        sign_with(keypair, *algorithm, payload)
    }

    async fn public_key(&self, key_id: &KeyId) -> Result<PublicKey, KeyVaultError> {
        let guard = self.keys.read().await;
        let (_, _, keypair) = guard
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

    async fn list_keys(
        &self,
        namespace: Option<KeyNamespace>,
    ) -> Result<Vec<KeyId>, KeyVaultError> {
        let guard = self.keys.read().await;
        let mut keys: Vec<KeyId> = guard
            .iter()
            .filter(|(_, (entry_namespace, _, _))| {
                namespace.is_none_or(|expected| entry_namespace == &expected)
            })
            .map(|(key_id, _)| key_id.clone())
            .collect();
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(keys)
    }

    async fn delete(&self, key_id: &KeyId) -> Result<(), KeyVaultError> {
        self.keys.write().await.remove(key_id);
        Ok(())
    }

    async fn sign_checked(
        &self,
        key_id: &KeyId,
        payload: &[u8],
        expected_namespace: KeyNamespace,
        expected_algorithm: KeyAlgorithm,
    ) -> Result<Signature, KeyVaultError> {
        let actual_namespace = key_id.namespace().ok_or_else(|| {
            KeyVaultError::InvalidKeyFormat(format!("missing namespace prefix: {}", key_id.0))
        })?;
        if actual_namespace != expected_namespace {
            return Err(KeyVaultError::NamespaceViolation {
                key: key_id.0.clone(),
                actual: actual_namespace,
                expected: expected_namespace,
            });
        }
        let guard = self.keys.read().await;
        let (_, algorithm, keypair) = guard
            .get(key_id)
            .ok_or_else(|| KeyVaultError::KeyNotFound(key_id.0.clone()))?;
        if *algorithm != expected_algorithm {
            return Err(KeyVaultError::AlgorithmMismatch {
                key: key_id.0.clone(),
                actual: *algorithm,
                expected: expected_algorithm,
            });
        }
        sign_with(keypair, *algorithm, payload)
    }
}

fn sign_with(
    keypair: &Keypair,
    algorithm: KeyAlgorithm,
    payload: &[u8],
) -> Result<Signature, KeyVaultError> {
    match (algorithm, keypair) {
        (KeyAlgorithm::Ed25519, Keypair::Ed25519(signing_key)) => {
            Ok(Signature(signing_key.sign(payload).to_bytes().to_vec()))
        }
        (KeyAlgorithm::Sr25519, Keypair::Sr25519(secret_key)) => {
            let public_key = secret_key.to_public();
            let signature = secret_key.sign_simple(b"substrate", payload, &public_key);
            Ok(Signature(signature.to_bytes().to_vec()))
        }
        _ => Err(KeyVaultError::AlgorithmMismatch {
            key: String::new(),
            actual: algorithm,
            expected: algorithm,
        }),
    }
}
