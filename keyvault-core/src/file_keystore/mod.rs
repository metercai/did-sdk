//! 加密文件密钥库。
//!
//! 每个 key 一个 KVLT 文件，`index.json` 保存公开元数据；密码惰性校验
//! （首次 `load` / `sign` / `public_key` 时解密）。`FileKeystore` 永不返回
//! `KeyVaultError::UserRejected`；用户确认属于上层 `did-sdk` 的职责。

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
use crate::crypto::encode_did_key;
use crate::fsutil::{atomic_write, now_unix};
use crate::{KeyId, KeyVault, KeyVaultError, Keypair, PublicKey, Signature};

pub mod format;
pub mod index;
pub mod password;

use format::{KeyType, SALT_LEN};
use index::KeyEntry;

/// Argon2id 内存成本（KiB）。
const ARGON2_M_COST: u32 = 65536;
/// Argon2id 迭代次数。
const ARGON2_T_COST: u32 = 3;
/// Argon2id 并行度。
const ARGON2_P_COST: u32 = 1;
/// 派生密钥长度。
const DERIVED_KEY_LEN: usize = 32;

/// 文件密钥库。
pub struct FileKeystore {
    pub(crate) path: PathBuf,
    pub(crate) password: SecretString,
    pub(crate) unlocked: RwLock<HashMap<KeyId, Keypair>>,
}

impl FileKeystore {
    /// 构造密钥库：创建目录，加载索引；密码在首次使用时校验。
    pub fn new(path: PathBuf, password: SecretString) -> Result<Self, KeyVaultError> {
        std::fs::create_dir_all(path.join("keys"))?;
        Ok(Self {
            path,
            password,
            unlocked: RwLock::new(HashMap::new()),
        })
    }

    fn index_path(&self) -> PathBuf {
        self.path.join("index.json")
    }

    fn keys_dir(&self) -> PathBuf {
        self.path.join("keys")
    }

    /// 由 key_id 计算文件名：blake2b256(key_id) 的 hex + `.kvlt`。
    fn key_file_name(key_id: &str) -> String {
        format!("{}.kvlt", hex::encode(blake2b256(key_id.as_bytes())))
    }

    fn derive_key(&self, salt: &[u8; SALT_LEN]) -> Result<[u8; 32], KeyVaultError> {
        let params = Params::new(
            ARGON2_M_COST,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(DERIVED_KEY_LEN),
        )
        .map_err(|e| KeyVaultError::SigningFailed(format!("invalid Argon2 params: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(self.password.expose_secret().as_bytes(), salt, &mut key)
            .map_err(|e| KeyVaultError::SigningFailed(format!("Argon2 failed: {e}")))?;
        Ok(key)
    }

    fn encrypt_plaintext(
        &self,
        key_type: KeyType,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyVaultError> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt)
            .map_err(|e| KeyVaultError::SigningFailed(format!("entropy unavailable: {e}")))?;
        let mut nonce_bytes = [0u8; format::NONCE_LEN];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|e| KeyVaultError::SigningFailed(format!("entropy unavailable: {e}")))?;

        let mut key = self.derive_key(&salt)?;
        let aad = format::header_aad(key_type, &salt);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &aad, &mut ciphertext)
            .map_err(|e| KeyVaultError::SigningFailed(format!("encryption failed: {e}")))?;
        key.zeroize();

        let mut tag_bytes = [0u8; format::TAG_LEN];
        tag_bytes.copy_from_slice(&tag);
        let bytes = format::encode(key_type, &salt, &nonce_bytes, &ciphertext, &tag_bytes);
        ciphertext.zeroize();
        Ok(bytes)
    }

    fn decrypt_plaintext(&self, decoded: &format::Decoded) -> Result<Vec<u8>, KeyVaultError> {
        let mut key = self.derive_key(&decoded.salt)?;
        let aad = format::header_aad(decoded.key_type, &decoded.salt);
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

    fn unlock(&self, key_id: &KeyId) -> Result<Keypair, KeyVaultError> {
        let index = index::load(&self.index_path())?;
        let entry = index
            .find(&key_id.0)
            .ok_or_else(|| KeyVaultError::KeyNotFound(key_id.0.clone()))?;
        if !index::is_valid_key_file_name(&entry.file) {
            return Err(KeyVaultError::InvalidKeyFormat(format!(
                "invalid file name in index: {}",
                entry.file
            )));
        }
        let raw = std::fs::read(self.keys_dir().join(&entry.file))?;
        let decoded = format::decode(&raw)?;
        let mut plaintext = self.decrypt_plaintext(&decoded)?;

        let keypair = match decoded.key_type {
            KeyType::Ed25519 => {
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
            KeyType::Sr25519 => {
                let secret_key = schnorrkel::SecretKey::from_bytes(&plaintext).map_err(|e| {
                    KeyVaultError::InvalidKeyFormat(format!("invalid sr25519 key: {e}"))
                })?;
                plaintext.zeroize();
                Keypair::Sr25519(secret_key)
            }
        };
        Ok(keypair)
    }

    fn key_path(&self, file_name: &str) -> PathBuf {
        self.keys_dir().join(file_name)
    }
}

#[async_trait]
impl KeyVault for FileKeystore {
    async fn generate(&self) -> Result<KeyId, KeyVaultError> {
        let index_path = self.index_path();
        let mut index = index::load(&index_path)?;

        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| KeyVaultError::SigningFailed(format!("entropy unavailable: {e}")))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = signing_key.verifying_key().to_bytes();
        let key_id = KeyId(encode_did_key(&public));
        if index.find(&key_id.0).is_some() {
            seed.zeroize();
            return Err(KeyVaultError::KeyAlreadyExists(key_id.0));
        }

        let file_bytes = self.encrypt_plaintext(KeyType::Ed25519, &seed)?;
        seed.zeroize();

        let file_name = Self::key_file_name(&key_id.0);
        let key_path = self.key_path(&file_name);
        atomic_write(&key_path, &file_bytes)?;
        index.upsert(KeyEntry {
            key_id: key_id.0.clone(),
            key_type: KeyType::Ed25519.as_u8(),
            file: file_name,
            created_at: now_unix(),
        });
        index::save(&index_path, &index)?;

        self.unlocked
            .write()
            .await
            .insert(key_id.clone(), Keypair::Ed25519(signing_key));
        Ok(key_id)
    }

    async fn load(&self, key_id: &KeyId) -> Result<(), KeyVaultError> {
        let mut guard = self.unlocked.write().await;
        if guard.contains_key(key_id) {
            return Ok(());
        }
        let keypair = self.unlock(key_id)?;
        guard.insert(key_id.clone(), keypair);
        Ok(())
    }

    async fn sign(&self, key_id: &KeyId, payload: &[u8]) -> Result<Signature, KeyVaultError> {
        let mut guard = self.unlocked.write().await;
        if !guard.contains_key(key_id) {
            let keypair = self.unlock(key_id)?;
            guard.insert(key_id.clone(), keypair);
        }
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
        let mut guard = self.unlocked.write().await;
        if !guard.contains_key(key_id) {
            let keypair = self.unlock(key_id)?;
            guard.insert(key_id.clone(), keypair);
        }
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
        let index = index::load(&self.index_path())?;
        let mut keys: Vec<KeyId> = index
            .keys
            .into_iter()
            .map(|entry| KeyId(entry.key_id))
            .collect();
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(keys)
    }

    async fn delete(&self, key_id: &KeyId) -> Result<(), KeyVaultError> {
        let index_path = self.index_path();
        let mut index = index::load(&index_path)?;
        if let Some(entry) = index.find(&key_id.0).cloned() {
            let path = self.key_path(&entry.file);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(KeyVaultError::IoError(err)),
            }
            index.remove(&key_id.0);
            index::save(&index_path, &index)?;
        }
        self.unlocked.write().await.remove(key_id);
        Ok(())
    }
}
