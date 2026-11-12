//! 加密文件密钥库（namespace 隔离版本）。
//!
//! 每个 key 一个 KVLT `.enc` 文件，按 namespace 子目录存放；`index.json`
//! 保存 `{key_id, namespace, algorithm, file, created_at}`。密码惰性校验。

use std::collections::HashMap;
use std::path::PathBuf;

use argon2::{Algorithm, Argon2, Params, Version};
use async_lock::RwLock;
use async_trait::async_trait;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use ed25519_dalek::Signer as _;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

use crate::crypto::blake2::blake2b256;
use crate::crypto::{account_id_to_ss58, encode_did_key, ss58_to_account_id};
use crate::fsutil::{atomic_write, now_unix};
use crate::{
    KeyAlgorithm, KeyId, KeyNamespace, KeyVault, KeyVaultError, Keypair, PublicKey, Signature,
};

pub mod format;
pub mod index;
pub mod password;

use format::SALT_LEN;
use index::KeyEntry;

const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const DERIVED_KEY_LEN: usize = 32;
const DEFAULT_SS58_PREFIX: u16 = 42;

type UnlockedEntry = (KeyNamespace, KeyAlgorithm, Keypair);

/// 文件密钥库。
pub struct FileKeystore {
    pub(crate) path: PathBuf,
    pub(crate) password: SecretString,
    pub(crate) unlocked: RwLock<HashMap<KeyId, UnlockedEntry>>,
    pub(crate) index: RwLock<index::KeyIndex>,
}

impl FileKeystore {
    /// 构造密钥库：创建 namespace 子目录并加载索引；密码在首次使用时校验。
    pub fn new(path: PathBuf, password: SecretString) -> Result<Self, KeyVaultError> {
        for namespace in [
            KeyNamespace::ChainAccount,
            KeyNamespace::ParticipantDid,
            KeyNamespace::ClientDid,
        ] {
            std::fs::create_dir_all(path.join(namespace.dir_name()))?;
        }
        let key_index = index::load(&path.join("index.json"))?;
        Ok(Self {
            path,
            password,
            unlocked: RwLock::new(HashMap::new()),
            index: RwLock::new(key_index),
        })
    }

    fn index_path(&self) -> PathBuf {
        self.path.join("index.json")
    }

    fn key_path(&self, namespace: KeyNamespace, file: &str) -> PathBuf {
        self.path.join(namespace.dir_name()).join(file)
    }

    fn file_name(key_id: &KeyId) -> String {
        let local = key_id.local_id().unwrap_or(&key_id.0);
        let mut base: String = local
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                    character
                } else {
                    '_'
                }
            })
            .collect();
        if base.len() > 96 {
            base.truncate(96);
        }
        let suffix = hex::encode(blake2b256(key_id.0.as_bytes()));
        format!("{base}-{}.enc", &suffix[..16])
    }

    fn derive_key(&self, salt: &[u8; SALT_LEN]) -> Result<[u8; 32], KeyVaultError> {
        let params = Params::new(
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(DERIVED_KEY_LEN),
        )
        .map_err(|error| KeyVaultError::SigningFailed(format!("invalid Argon2 params: {error}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(self.password.expose_secret().as_bytes(), salt, &mut key)
            .map_err(|error| KeyVaultError::SigningFailed(format!("Argon2 failed: {error}")))?;
        Ok(key)
    }

    fn encrypt_plaintext(
        &self,
        namespace: KeyNamespace,
        algorithm: KeyAlgorithm,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyVaultError> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|error| {
            KeyVaultError::SigningFailed(format!("entropy unavailable: {error}"))
        })?;
        let mut nonce_bytes = [0u8; format::NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|error| {
            KeyVaultError::SigningFailed(format!("entropy unavailable: {error}"))
        })?;

        let mut key = self.derive_key(&salt)?;
        let aad = format::header_aad(namespace, algorithm, &salt);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &aad, &mut ciphertext)
            .map_err(|error| KeyVaultError::SigningFailed(format!("encryption failed: {error}")))?;
        key.zeroize();
        let mut tag_bytes = [0u8; format::TAG_LEN];
        tag_bytes.copy_from_slice(&tag);
        let bytes = format::encode(
            namespace,
            algorithm,
            &salt,
            &nonce_bytes,
            &ciphertext,
            &tag_bytes,
        );
        ciphertext.zeroize();
        Ok(bytes)
    }

    fn decrypt_plaintext(&self, decoded: &format::Decoded) -> Result<Vec<u8>, KeyVaultError> {
        let mut key = self.derive_key(&decoded.salt)?;
        let aad = format::header_aad(decoded.namespace, decoded.algorithm, &decoded.salt);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut plaintext = decoded.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&decoded.nonce),
                &aad,
                &mut plaintext,
                Tag::from_slice(&decoded.tag),
            )
            .map_err(|_| KeyVaultError::InvalidPassword)?;
        key.zeroize();
        Ok(plaintext)
    }

    fn generate_keypair(algorithm: KeyAlgorithm) -> Result<(Keypair, String), KeyVaultError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|error| {
            KeyVaultError::SigningFailed(format!("entropy unavailable: {error}"))
        })?;
        let result = match algorithm {
            KeyAlgorithm::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                let public = signing_key.verifying_key().to_bytes();
                let local_id = encode_did_key(&public)
                    .strip_prefix("did:key:")
                    .unwrap_or_default()
                    .to_string();
                (Keypair::Ed25519(signing_key), format!("did_key_{local_id}"))
            }
            KeyAlgorithm::Sr25519 => {
                let mini = schnorrkel::MiniSecretKey::from_bytes(&seed).map_err(|error| {
                    KeyVaultError::SigningFailed(format!("invalid sr25519 seed: {error}"))
                })?;
                let secret = mini.expand(schnorrkel::ExpansionMode::Ed25519);
                let public = secret.to_public().to_bytes();
                (
                    Keypair::Sr25519(secret),
                    account_id_to_ss58(&public, DEFAULT_SS58_PREFIX),
                )
            }
        };
        seed.zeroize();
        Ok(result)
    }

    fn validate_public_key(
        key_id: &KeyId,
        algorithm: KeyAlgorithm,
        keypair: &Keypair,
    ) -> Result<(), KeyVaultError> {
        let Some(local_id) = key_id.local_id() else {
            return Err(KeyVaultError::InvalidKeyFormat(format!(
                "missing namespace prefix: {}",
                key_id.0
            )));
        };
        match (algorithm, keypair) {
            (KeyAlgorithm::Ed25519, Keypair::Ed25519(signing_key)) => {
                if let Some(encoded) = local_id.strip_prefix("did_key_") {
                    let expected = signing_key.verifying_key().to_bytes();
                    let actual =
                        crate::crypto::decode_did_key_pubkey(&format!("did:key:{encoded}"))
                            .map_err(|error| {
                                KeyVaultError::InvalidKeyFormat(format!(
                                    "invalid did:key local id: {error}"
                                ))
                            })?;
                    if actual != expected {
                        return Err(KeyVaultError::InvalidKeyFormat(
                            "key file does not match KeyId".into(),
                        ));
                    }
                }
                Ok(())
            }
            (KeyAlgorithm::Sr25519, Keypair::Sr25519(secret_key)) => {
                if let Ok(actual) = ss58_to_account_id(local_id) {
                    if actual != secret_key.to_public().to_bytes() {
                        return Err(KeyVaultError::InvalidKeyFormat(
                            "key file does not match KeyId".into(),
                        ));
                    }
                }
                Ok(())
            }
            _ => Err(KeyVaultError::AlgorithmMismatch {
                key: key_id.0.clone(),
                actual: algorithm,
                expected: algorithm,
            }),
        }
    }

    async fn unlock(&self, key_id: &KeyId) -> Result<UnlockedEntry, KeyVaultError> {
        let actual_namespace = key_id.namespace().ok_or_else(|| {
            KeyVaultError::InvalidKeyFormat(format!("missing namespace prefix: {}", key_id.0))
        })?;
        let index = self.index.read().await;
        let entry = index
            .find(&key_id.0)
            .ok_or_else(|| KeyVaultError::KeyNotFound(key_id.0.clone()))?
            .clone();
        if entry.namespace != actual_namespace {
            return Err(KeyVaultError::NamespaceViolation {
                key: key_id.0.clone(),
                actual: entry.namespace,
                expected: actual_namespace,
            });
        }
        let raw = std::fs::read(self.key_path(entry.namespace, &entry.file))?;
        let decoded = format::decode(&raw)?;
        if decoded.namespace != entry.namespace {
            return Err(KeyVaultError::InvalidKeyFormat(
                "file namespace does not match index".into(),
            ));
        }
        if decoded.algorithm != entry.algorithm {
            return Err(KeyVaultError::InvalidKeyFormat(
                "file algorithm does not match index".into(),
            ));
        }
        let mut plaintext = self.decrypt_plaintext(&decoded)?;
        let keypair = match entry.algorithm {
            KeyAlgorithm::Ed25519 => {
                if plaintext.len() != 32 {
                    plaintext.zeroize();
                    return Err(KeyVaultError::InvalidKeyFormat(
                        "Ed25519 key must be 32 bytes".into(),
                    ));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&plaintext);
                plaintext.zeroize();
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                seed.zeroize();
                Keypair::Ed25519(signing_key)
            }
            KeyAlgorithm::Sr25519 => {
                let secret_key =
                    schnorrkel::SecretKey::from_bytes(&plaintext).map_err(|error| {
                        KeyVaultError::InvalidKeyFormat(format!("invalid sr25519 key: {error}"))
                    })?;
                plaintext.zeroize();
                Keypair::Sr25519(secret_key)
            }
        };
        Self::validate_public_key(key_id, entry.algorithm, &keypair)?;
        Ok((entry.namespace, entry.algorithm, keypair))
    }
}

#[async_trait]
impl KeyVault for FileKeystore {
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
        let (keypair, local_id) = Self::generate_keypair(algorithm)?;
        let key_id = KeyId::new(namespace, &local_id);
        {
            let index = self.index.read().await;
            if index.find(&key_id.0).is_some() {
                return Err(KeyVaultError::KeyAlreadyExists(key_id.0));
            }
        }

        let file_name = Self::file_name(&key_id);
        let path = self.key_path(namespace, &file_name);
        let seed = match &keypair {
            Keypair::Ed25519(signing_key) => signing_key.to_bytes().to_vec(),
            Keypair::Sr25519(secret_key) => secret_key.to_bytes().to_vec(),
        };
        let file_bytes = self.encrypt_plaintext(namespace, algorithm, &seed)?;
        let mut seed = seed;
        seed.zeroize();
        atomic_write(&path, &file_bytes)?;

        let mut index = self.index.write().await;
        index.upsert(KeyEntry {
            key_id: key_id.0.clone(),
            namespace,
            algorithm,
            file: file_name,
            created_at: now_unix(),
        });
        index::save(&self.index_path(), &index)?;
        drop(index);

        self.unlocked
            .write()
            .await
            .insert(key_id.clone(), (namespace, algorithm, keypair));
        Ok(key_id)
    }

    async fn load(&self, key_id: &KeyId) -> Result<(), KeyVaultError> {
        let mut guard = self.unlocked.write().await;
        if guard.contains_key(key_id) {
            return Ok(());
        }
        let (namespace, algorithm, keypair) = self.unlock(key_id).await?;
        guard.insert(key_id.clone(), (namespace, algorithm, keypair));
        Ok(())
    }

    async fn sign(&self, key_id: &KeyId, payload: &[u8]) -> Result<Signature, KeyVaultError> {
        let mut guard = self.unlocked.write().await;
        if !guard.contains_key(key_id) {
            let entry = self.unlock(key_id).await?;
            guard.insert(key_id.clone(), entry);
        }
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
        let mut guard = self.unlocked.write().await;
        if !guard.contains_key(key_id) {
            let entry = self.unlock(key_id).await?;
            guard.insert(key_id.clone(), entry);
        }
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
        let index = self.index.read().await;
        let mut keys: Vec<KeyId> = index
            .keys
            .iter()
            .filter(|entry| namespace.is_none_or(|expected| entry.namespace == expected))
            .map(|entry| KeyId(entry.key_id.clone()))
            .collect();
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(keys)
    }

    async fn delete(&self, key_id: &KeyId) -> Result<(), KeyVaultError> {
        let index_path = self.index_path();
        let mut index = self.index.write().await;
        if let Some(entry) = index.find(&key_id.0).cloned() {
            let path = self.key_path(entry.namespace, &entry.file);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(KeyVaultError::IoError(error.to_string())),
            }
            index.remove(&key_id.0);
            index::save(&index_path, &index)?;
        }
        drop(index);
        self.unlocked.write().await.remove(key_id);
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
        let algorithm = {
            let index = self.index.read().await;
            index
                .find(&key_id.0)
                .ok_or_else(|| KeyVaultError::KeyNotFound(key_id.0.clone()))?
                .algorithm
        };
        if algorithm != expected_algorithm {
            return Err(KeyVaultError::AlgorithmMismatch {
                key: key_id.0.clone(),
                actual: algorithm,
                expected: expected_algorithm,
            });
        }
        self.sign(key_id, payload).await
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
