//! VC / VP 构造、哈希与加密文件存储。

use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use keyvault_core::crypto::blake2::blake2b256;
use keyvault_core::signing_input::{issued_vc_v1, vp_v1};
use zeroize::Zeroize;

use crate::storage::atomic_write;
use crate::{DidSdkError, Disclosure, Proof, VerifiableCredential, VerifiablePresentation};

const VC_STORE_MAGIC: &[u8; 4] = b"DVCS";
const VC_META_MAGIC: &[u8; 4] = b"DVCM";
const VC_STORE_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;
const VC_PASSWORD_ENV: &str = "DID_SDK_VC_STORAGE_PASSWORD";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct StoredVc {
    pub(crate) vc: VerifiableCredential,
    #[serde(default)]
    pub(crate) disclosures: Vec<Disclosure>,
}

/// 加密 VC 文件存储。
///
/// 每个 VC 文件格式：`DVCS | version | nonce(12) | ciphertext | tag(16)`。
/// 密钥由 `DID_SDK_VC_STORAGE_PASSWORD` 或 `.vc_password`（自动生成，0600）
/// 经 Argon2id + `.vc_meta` salt 派生；密钥只驻留内存。
pub(crate) struct VcStore {
    root: PathBuf,
    key: [u8; 32],
}

impl Drop for VcStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl VcStore {
    pub(crate) fn new(
        root: PathBuf,
        password: Option<secrecy::SecretString>,
    ) -> Result<Self, DidSdkError> {
        std::fs::create_dir_all(&root)
            .map_err(|error| DidSdkError::BackendUnavailable(format!("create VC dir: {error}")))?;
        let password = match password {
            Some(password) => secrecy::ExposeSecret::expose_secret(&password).to_string(),
            None => resolve_vc_password(&root)?,
        };
        let salt = load_or_create_salt(&root)?;
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|error| DidSdkError::ConfigError(format!("invalid Argon2 params: {error}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut key)
            .map_err(|error| DidSdkError::ConfigError(format!("derive VC key: {error}")))?;
        let mut password = password;
        password.zeroize();
        Ok(Self { root, key })
    }

    fn path_for(&self, anchor_id: &str) -> PathBuf {
        self.root.join(format!(
            "{}.json",
            hex::encode(blake2b256(anchor_id.as_bytes()))
        ))
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, DidSdkError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|error| DidSdkError::BackendUnavailable(format!("entropy: {error}")))?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), VC_STORE_MAGIC, &mut ciphertext)
            .map_err(|error| DidSdkError::BackendUnavailable(format!("VC encryption: {error}")))?;
        let mut out = Vec::with_capacity(4 + 1 + NONCE_LEN + ciphertext.len() + TAG_LEN);
        out.extend_from_slice(VC_STORE_MAGIC);
        out.push(VC_STORE_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn decrypt(&self, bytes: &[u8]) -> Result<Vec<u8>, DidSdkError> {
        if bytes.len() < 4 + 1 + NONCE_LEN + TAG_LEN {
            return Err(DidSdkError::InvalidArgument("VC file too short".into()));
        }
        if &bytes[..4] != VC_STORE_MAGIC {
            return Err(DidSdkError::InvalidArgument("bad VC file magic".into()));
        }
        if bytes[4] != VC_STORE_VERSION {
            return Err(DidSdkError::InvalidArgument(format!(
                "unsupported VC file version: {}",
                bytes[4]
            )));
        }
        let nonce_start = 5;
        let ciphertext_start = nonce_start + NONCE_LEN;
        let tag_start = bytes.len() - TAG_LEN;
        let mut ciphertext = bytes[ciphertext_start..tag_start].to_vec();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[tag_start..]);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&bytes[nonce_start..ciphertext_start]),
                VC_STORE_MAGIC,
                &mut ciphertext,
                Tag::from_slice(&tag),
            )
            .map_err(|_| DidSdkError::InvalidArgument("VC decryption failed".into()))?;
        Ok(ciphertext)
    }

    fn load_bundle(&self, path: &Path, anchor_id: &str) -> Result<StoredVc, DidSdkError> {
        let raw = std::fs::read(path).map_err(|error| {
            DidSdkError::BackendUnavailable(format!("read {}: {error}", path.display()))
        })?;
        // 兼容极早期明文文件；读取后立即重新加密。
        if raw.first() == Some(&b'{') {
            let bundle = parse_bundle(&raw, path)?;
            self.put_bundle(&bundle.vc, &bundle.disclosures)?;
            tracing::warn!(path = %path.display(), "migrated plaintext VC to encrypted form");
            return Ok(bundle);
        }
        let plaintext = self.decrypt(&raw)?;
        let bundle = parse_bundle(&plaintext, path)?;
        if bundle.vc.anchor_id.as_deref() != Some(anchor_id) {
            return Err(DidSdkError::InvalidArgument(format!(
                "VC anchor_id mismatch for {anchor_id}"
            )));
        }
        Ok(bundle)
    }

    pub(crate) fn put_bundle(
        &self,
        vc: &VerifiableCredential,
        disclosures: &[Disclosure],
    ) -> Result<(), DidSdkError> {
        let anchor_id = vc
            .anchor_id
            .as_deref()
            .ok_or_else(|| DidSdkError::InvalidArgument("VC is missing anchor_id".into()))?;
        let bundle = StoredVc {
            vc: vc.clone(),
            disclosures: disclosures.to_vec(),
        };
        let json = serde_json::to_vec(&bundle)
            .map_err(|error| DidSdkError::InvalidArgument(format!("serialize VC: {error}")))?;
        let encrypted = self.encrypt(&json)?;
        atomic_write(&self.path_for(anchor_id), &encrypted)
            .map_err(|error| DidSdkError::BackendUnavailable(format!("write VC: {error}")))
    }

    pub(crate) fn put(&self, vc: &VerifiableCredential) -> Result<(), DidSdkError> {
        self.put_bundle(vc, &[])
    }

    pub(crate) fn get(&self, anchor_id: &str) -> Result<Option<VerifiableCredential>, DidSdkError> {
        Ok(self.get_bundle(anchor_id)?.map(|bundle| bundle.vc))
    }

    pub(crate) fn get_bundle(&self, anchor_id: &str) -> Result<Option<StoredVc>, DidSdkError> {
        let path = self.path_for(anchor_id);
        if !path.exists() {
            return Ok(None);
        }
        self.load_bundle(&path, anchor_id).map(Some)
    }

    pub(crate) fn list(&self) -> Result<Vec<VerifiableCredential>, DidSdkError> {
        Ok(self
            .list_bundles()?
            .into_iter()
            .map(|bundle| bundle.vc)
            .collect())
    }

    pub(crate) fn list_bundles(&self) -> Result<Vec<StoredVc>, DidSdkError> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(error) => {
                return Err(DidSdkError::BackendUnavailable(format!(
                    "read VC dir: {error}"
                )));
            }
        };
        for entry in entries {
            let entry =
                entry.map_err(|error| DidSdkError::BackendUnavailable(error.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let anchor_id = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default()
                .to_string();
            match std::fs::read(&path) {
                Ok(raw) if raw.first() == Some(&b'{') => match parse_bundle(&raw, &path) {
                    Ok(bundle) => {
                        if let Err(error) = self.put_bundle(&bundle.vc, &bundle.disclosures) {
                            tracing::warn!(path = %path.display(), %error, "re-encrypt VC failed");
                        }
                        out.push(bundle);
                    }
                    Err(error) => {
                        tracing::warn!(path = %path.display(), %error, "skip invalid VC file");
                    }
                },
                Ok(raw) => match self
                    .decrypt(&raw)
                    .and_then(|plain| parse_bundle(&plain, &path))
                {
                    Ok(bundle) => out.push(bundle),
                    Err(error) => {
                        tracing::warn!(path = %path.display(), %error, "skip invalid VC file");
                    }
                },
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skip unreadable VC file");
                }
            }
            let _ = anchor_id;
        }
        out.sort_by(|a, b| a.vc.id.cmp(&b.vc.id));
        Ok(out)
    }

    pub(crate) fn remove(&self, anchor_id: &str) -> Result<(), DidSdkError> {
        let path = self.path_for(anchor_id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(DidSdkError::VcNotFound(anchor_id.to_string()))
            }
            Err(error) => Err(DidSdkError::BackendUnavailable(format!(
                "remove VC: {error}"
            ))),
        }
    }
}

fn parse_bundle(bytes: &[u8], path: &Path) -> Result<StoredVc, DidSdkError> {
    if let Ok(bundle) = serde_json::from_slice::<StoredVc>(bytes) {
        return Ok(bundle);
    }
    let vc: VerifiableCredential = serde_json::from_slice(bytes).map_err(|error| {
        DidSdkError::InvalidArgument(format!("parse VC {}: {error}", path.display()))
    })?;
    Ok(StoredVc {
        vc,
        disclosures: Vec::new(),
    })
}

fn resolve_vc_password(root: &Path) -> Result<String, DidSdkError> {
    if let Ok(value) = std::env::var(VC_PASSWORD_ENV) {
        if !value.is_empty() {
            return Ok(value);
        }
    }
    let path = root.join(".vc_password");
    if path.exists() {
        let value = std::fs::read_to_string(&path)
            .map_err(|error| DidSdkError::ConfigError(format!("read VC password file: {error}")))?;
        let value = value.trim_end_matches(['\r', '\n']).to_string();
        if value.is_empty() {
            return Err(DidSdkError::ConfigError("VC password file is empty".into()));
        }
        return Ok(value);
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)
        .map_err(|error| DidSdkError::ConfigError(format!("entropy: {error}")))?;
    let password = bs58::encode(random).into_string();
    random.zeroize();
    atomic_write(&path, password.as_bytes())
        .map_err(|error| DidSdkError::ConfigError(format!("write VC password: {error}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)
            .map_err(|error| DidSdkError::ConfigError(error.to_string()))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .map_err(|error| DidSdkError::ConfigError(error.to_string()))?;
    }
    Ok(password)
}

fn load_or_create_salt(root: &Path) -> Result<[u8; SALT_LEN], DidSdkError> {
    let path = root.join(".vc_meta");
    if path.exists() {
        let bytes = std::fs::read(&path)
            .map_err(|error| DidSdkError::ConfigError(format!("read VC meta: {error}")))?;
        if bytes.len() != 4 + 1 + SALT_LEN
            || &bytes[..4] != VC_META_MAGIC
            || bytes[4] != VC_STORE_VERSION
        {
            return Err(DidSdkError::ConfigError("invalid VC meta file".into()));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[5..]);
        return Ok(salt);
    }
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|error| DidSdkError::ConfigError(format!("entropy: {error}")))?;
    let mut bytes = Vec::with_capacity(4 + 1 + SALT_LEN);
    bytes.extend_from_slice(VC_META_MAGIC);
    bytes.push(VC_STORE_VERSION);
    bytes.extend_from_slice(&salt);
    atomic_write(&path, &bytes)
        .map_err(|error| DidSdkError::ConfigError(format!("write VC meta: {error}")))?;
    Ok(salt)
}

/// Unix 秒 → RFC3339 UTC。
pub(crate) fn rfc3339_utc(timestamp: u64) -> String {
    let days = (timestamp / 86_400) as i64;
    let seconds = timestamp % 86_400;
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

pub(crate) fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// 构造 VC（不含 proof）。
pub(crate) fn build_vc(
    issuer: &str,
    claims: serde_json::Value,
    proof: Option<Proof>,
) -> VerifiableCredential {
    let now = now_ts();
    let subject = claims
        .get("credentialSubject")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "id": issuer, "claims": claims }));
    let mut types = vec!["VerifiableCredential".to_string()];
    match claims.get("type") {
        Some(serde_json::Value::String(value)) => types.push(value.clone()),
        Some(serde_json::Value::Array(values)) => {
            for value in values {
                if let Some(value) = value.as_str() {
                    types.push(value.to_string());
                }
            }
        }
        _ => {}
    }
    if types.len() == 1 {
        types.push("SelfAssertedCredential".into());
    }
    let id_seed = format!(
        "{issuer}:{now}:{}",
        serde_json::to_string(&claims).unwrap_or_default()
    );
    let id = format!(
        "urn:did-sdk:vc:{}",
        hex::encode(blake2b256(id_seed.as_bytes()))
    );
    let anchor_id = hex::encode(blake2b256(id.as_bytes()));
    VerifiableCredential {
        context: vec!["https://www.w3.org/ns/credentials/v2".into()],
        id,
        types,
        issuer: issuer.to_string(),
        issuance_date: rfc3339_utc(now),
        expiration_date: None,
        credential_subject: subject,
        proof,
        anchor_id: Some(anchor_id),
    }
}

/// 组装 Server 模式的 VC（proof 外部注入）。
pub(crate) fn assemble_vc(
    issuer: &str,
    claims: serde_json::Value,
    subject: &str,
    proof: Proof,
) -> Result<VerifiableCredential, DidSdkError> {
    if subject.is_empty() {
        return Err(DidSdkError::InvalidArgument("empty VC subject".into()));
    }
    let mut vc = build_vc(issuer, claims, Some(proof));
    if let Some(object) = vc.credential_subject.as_object_mut() {
        object.insert("id".into(), serde_json::Value::String(subject.to_string()));
    } else {
        vc.credential_subject = serde_json::json!({ "id": subject });
    }
    Ok(vc)
}

/// VC 去掉 `proof`、保留 `anchor_id` 的 BLAKE2b-256（小写 hex，无前缀）。
///
/// 用途：`IssuedVc-v1` 签名输入、VC 签发哈希。与 `chain-sdk`
/// `sd::vc_signing_input` 的哈希部分逐字节一致。
pub fn vc_hash_without_proof(vc: &VerifiableCredential) -> Result<String, DidSdkError> {
    let mut copy = vc.clone();
    copy.proof = None;
    let bytes = serde_json::to_vec(&copy)
        .map_err(|error| DidSdkError::InvalidArgument(format!("serialize VC: {error}")))?;
    Ok(hex::encode(blake2b256(&bytes)))
}

/// 完整 VC（含 `proof` / `anchor_id`）的 BLAKE2b-256（小写 hex，无前缀）。
///
/// 用途：`VP-SD-v1` 的 `vc_hash`。与 `chain-sdk` `sd::vp_signing_input`
/// 的 VC 哈希逐字节一致。
pub fn vc_hash(vc: &VerifiableCredential) -> Result<String, DidSdkError> {
    let bytes = serde_json::to_vec(vc)
        .map_err(|error| DidSdkError::InvalidArgument(format!("serialize VC: {error}")))?;
    Ok(hex::encode(blake2b256(&bytes)))
}

/// 锚定载荷哈希：去掉 `proof` 与 `anchor_id`，紧凑 JSON，BLAKE2b-256，
/// 返回 `"blake2b:<小写 hex>"`。
///
/// 这是路径三（用户 A 委托链主代提交锚定）中 `vc_hash` 的唯一推荐来源。
/// 必须与 `chain-sdk` `sd::payload_hash` 逐字节一致：两者对同一个
/// [`VerifiableCredential`] 的 `proof = None, anchor_id = None` 副本调用
/// `serde_json::to_vec`，再做 BLAKE2b-256 并加 `blake2b:` 前缀。
pub fn anchor_payload_hash(vc: &VerifiableCredential) -> Result<String, DidSdkError> {
    let mut copy = vc.clone();
    copy.proof = None;
    copy.anchor_id = None;
    let bytes = serde_json::to_vec(&copy)
        .map_err(|error| DidSdkError::InvalidArgument(format!("serialize VC: {error}")))?;
    Ok(format!("blake2b:{}", hex::encode(blake2b256(&bytes))))
}

/// VC 的签发待签名字节。
pub(crate) fn vc_signing_input(vc: &VerifiableCredential) -> Result<Vec<u8>, DidSdkError> {
    let subject_did = vc
        .credential_subject
        .get("id")
        .and_then(|value| value.as_str())
        .unwrap_or(&vc.issuer);
    let vc_type = vc
        .types
        .last()
        .map(String::as_str)
        .unwrap_or("SelfAssertedCredential");
    let hash = vc_hash_without_proof(vc)?;
    Ok(issued_vc_v1(&vc.issuer, subject_did, vc_type, &hash))
}

/// 构造 Proof。
pub(crate) fn proof_for(did: &str, created: u64, signature: &[u8]) -> Proof {
    Proof {
        type_: "Ed25519Signature2020".into(),
        created,
        verification_method: format!("{did}#key-1"),
        jws: bs58::encode(signature).into_string(),
    }
}

/// VP 的待签名字节。
pub(crate) fn vp_signing_input(
    holder: &str,
    challenge: &str,
    domain: &str,
    vcs: &[VerifiableCredential],
) -> Result<Vec<u8>, DidSdkError> {
    let hashes = vcs.iter().map(vc_hash).collect::<Result<Vec<_>, _>>()?;
    Ok(vp_v1(holder, challenge, domain, &hashes))
}

/// 构造 VP（proof 可为空）。
pub(crate) fn build_vp_object(
    holder: &str,
    vcs: Vec<VerifiableCredential>,
    challenge: &str,
    domain: &str,
    disclosures: Option<Vec<Disclosure>>,
    proof: Option<Proof>,
) -> VerifiablePresentation {
    VerifiablePresentation {
        context: vec!["https://www.w3.org/ns/credentials/v2".into()],
        types: vec!["VerifiablePresentation".into()],
        holder: holder.to_string(),
        verifiable_credential: vcs,
        challenge: challenge.to_string(),
        domain: domain.to_string(),
        disclosures,
        proof,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::rfc3339_utc;

    #[test]
    fn formats_epoch_and_leap_day() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }
}
