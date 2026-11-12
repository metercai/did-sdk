//! VC / VP 构造、哈希与本地文件存储。

use std::path::{Path, PathBuf};

use keyvault_core::crypto::blake2::blake2b256;
use keyvault_core::signing_input::{issued_vc_v1, vp_v1};

use crate::storage::atomic_write;
use crate::{DidSdkError, Proof, VerifiableCredential, VerifiablePresentation};

/// 本地 VC 文件存储。文件名使用 anchor_id 的 BLAKE2b-256，避免路径注入。
#[derive(Debug, Clone)]
pub(crate) struct VcStore {
    root: PathBuf,
}

impl VcStore {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path_for(&self, anchor_id: &str) -> PathBuf {
        self.root.join(format!(
            "{}.json",
            hex::encode(blake2b256(anchor_id.as_bytes()))
        ))
    }

    pub(crate) fn put(&self, vc: &VerifiableCredential) -> Result<(), DidSdkError> {
        let anchor_id = vc
            .anchor_id
            .as_deref()
            .ok_or_else(|| DidSdkError::InvalidArgument("VC is missing anchor_id".into()))?;
        let bytes = serde_json::to_vec_pretty(vc)
            .map_err(|error| DidSdkError::InvalidArgument(format!("serialize VC: {error}")))?;
        atomic_write(&self.path_for(anchor_id), &bytes)
            .map_err(|error| DidSdkError::ChainUnavailable(format!("write VC: {error}")))
    }

    pub(crate) fn get(&self, anchor_id: &str) -> Result<Option<VerifiableCredential>, DidSdkError> {
        let path = self.path_for(anchor_id);
        if !path.exists() {
            return Ok(None);
        }
        let vc = read_vc(&path)?;
        if vc.anchor_id.as_deref() != Some(anchor_id) {
            return Err(DidSdkError::InvalidArgument(format!(
                "VC anchor_id mismatch for {anchor_id}"
            )));
        }
        Ok(Some(vc))
    }

    pub(crate) fn list(&self) -> Result<Vec<VerifiableCredential>, DidSdkError> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(error) => {
                return Err(DidSdkError::ChainUnavailable(format!(
                    "read VC dir: {error}"
                )));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|error| DidSdkError::ChainUnavailable(error.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            match read_vc(&path) {
                Ok(vc) => out.push(vc),
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skip invalid VC file")
                }
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    pub(crate) fn remove(&self, anchor_id: &str) -> Result<(), DidSdkError> {
        let path = self.path_for(anchor_id);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(DidSdkError::VcNotFound(anchor_id.to_string()))
            }
            Err(error) => Err(DidSdkError::ChainUnavailable(format!("remove VC: {error}"))),
        }
    }
}

fn read_vc(path: &Path) -> Result<VerifiableCredential, DidSdkError> {
    let raw = std::fs::read(path).map_err(|error| {
        DidSdkError::ChainUnavailable(format!("read {}: {error}", path.display()))
    })?;
    serde_json::from_slice(&raw)
        .map_err(|error| DidSdkError::InvalidArgument(format!("parse {}: {error}", path.display())))
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

/// VC 去掉 proof 后的 canonical JSON hash。
pub(crate) fn vc_hash_without_proof(vc: &VerifiableCredential) -> Result<String, DidSdkError> {
    let mut copy = vc.clone();
    copy.proof = None;
    let bytes = serde_json::to_vec(&copy)
        .map_err(|error| DidSdkError::InvalidArgument(format!("serialize VC: {error}")))?;
    Ok(hex::encode(blake2b256(&bytes)))
}

/// VC 完整 JSON hash（VP 绑定用）。
pub(crate) fn vc_hash(vc: &VerifiableCredential) -> Result<String, DidSdkError> {
    let bytes = serde_json::to_vec(vc)
        .map_err(|error| DidSdkError::InvalidArgument(format!("serialize VC: {error}")))?;
    Ok(hex::encode(blake2b256(&bytes)))
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
    proof: Option<Proof>,
) -> VerifiablePresentation {
    VerifiablePresentation {
        context: vec!["https://www.w3.org/ns/credentials/v2".into()],
        types: vec!["VerifiablePresentation".into()],
        holder: holder.to_string(),
        verifiable_credential: vcs,
        challenge: challenge.to_string(),
        domain: domain.to_string(),
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
