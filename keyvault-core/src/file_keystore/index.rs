//! `index.json` 的读写与校验（v2，含 namespace/algorithm）。

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fsutil::atomic_write;
use crate::{KeyAlgorithm, KeyNamespace, KeyVaultError};

/// 索引格式版本。
pub const INDEX_VERSION: u8 = 2;

/// 单条密钥索引。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyEntry {
    /// 带 namespace 前缀的 KeyId。
    pub key_id: String,
    /// namespace。
    pub namespace: KeyNamespace,
    /// algorithm。
    pub algorithm: KeyAlgorithm,
    /// 密钥文件名（位于 namespace 子目录下，以 `.enc` 结尾）。
    pub file: String,
    /// 创建时间（Unix 秒）。
    pub created_at: u64,
}

/// `index.json` 的完整内容。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyIndex {
    /// 索引格式版本。
    pub version: u8,
    /// 密钥条目。
    pub keys: Vec<KeyEntry>,
}

impl Default for KeyIndex {
    fn default() -> Self {
        Self {
            version: INDEX_VERSION,
            keys: Vec::new(),
        }
    }
}

impl KeyIndex {
    /// 查找 key_id 对应的条目。
    pub fn find(&self, key_id: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|entry| entry.key_id == key_id)
    }

    /// 插入或替换条目。
    pub fn upsert(&mut self, entry: KeyEntry) {
        if let Some(existing) = self
            .keys
            .iter_mut()
            .find(|item| item.key_id == entry.key_id)
        {
            *existing = entry;
        } else {
            self.keys.push(entry);
        }
    }

    /// 删除条目。
    pub fn remove(&mut self, key_id: &str) -> bool {
        let before = self.keys.len();
        self.keys.retain(|entry| entry.key_id != key_id);
        self.keys.len() != before
    }
}

/// 校验密钥文件名，防止目录穿越与非法字符。
pub fn is_valid_key_file_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".enc") else {
        return false;
    };
    !stem.is_empty()
        && !stem.starts_with('.')
        && !stem.contains("..")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// 从磁盘加载索引。文件不存在时返回空索引。
pub fn load(path: &Path) -> Result<KeyIndex, KeyVaultError> {
    if !path.exists() {
        return Ok(KeyIndex::default());
    }
    let raw = std::fs::read(path)?;
    let index: KeyIndex = serde_json::from_slice(&raw)
        .map_err(|error| KeyVaultError::InvalidKeyFormat(format!("invalid index.json: {error}")))?;
    if index.version != INDEX_VERSION {
        return Err(KeyVaultError::InvalidKeyFormat(format!(
            "unsupported index version: {}",
            index.version
        )));
    }
    for entry in &index.keys {
        if !is_valid_key_file_name(&entry.file) {
            return Err(KeyVaultError::InvalidKeyFormat(format!(
                "invalid key file name in index: {}",
                entry.file
            )));
        }
        let actual = entry
            .key_id
            .strip_prefix(entry.namespace.prefix())
            .ok_or_else(|| {
                KeyVaultError::InvalidKeyFormat(format!(
                    "key_id {} does not match namespace {:?}",
                    entry.key_id, entry.namespace
                ))
            })?;
        if actual.is_empty() {
            return Err(KeyVaultError::InvalidKeyFormat(
                "empty local id in key index".into(),
            ));
        }
    }
    Ok(index)
}

/// 原子保存索引。
pub fn save(path: &Path, index: &KeyIndex) -> Result<(), KeyVaultError> {
    let bytes = serde_json::to_vec_pretty(index)?;
    atomic_write(path, &bytes)?;
    Ok(())
}
