//! VC / VP 构造与本地文件存储。

use std::path::{Path, PathBuf};

use keyvault_core::crypto::blake2::blake2b256;
use keyvault_core::signing_input::{issued_vc_v1, vp_v1};

use crate::DidSdkError;
use crate::core::SdkCore;
use crate::server_request::{AuthorizationRequestContext, VpRequestContext};
use crate::storage::atomic_write;
use crate::types::{
    IssueAuthorizationSignature, VcProof, VerifiableCredential, VerifiablePresentation,
};

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
            .map_err(|e| DidSdkError::InvalidArgument(format!("serialize VC: {e}")))?;
        atomic_write(&self.path_for(anchor_id), &bytes)
            .map_err(|e| DidSdkError::ChainUnavailable(format!("write VC: {e}")))
    }

    pub(crate) fn get(&self, anchor_id: &str) -> Result<Option<VerifiableCredential>, DidSdkError> {
        let path = self.path_for(anchor_id);
        if !path.exists() {
            return Ok(None);
        }
        read_vc(&path).map(Some)
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
            let entry = entry.map_err(|e| DidSdkError::ChainUnavailable(e.to_string()))?;
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
    let raw = std::fs::read(path)
        .map_err(|e| DidSdkError::ChainUnavailable(format!("read {}: {e}", path.display())))?;
    serde_json::from_slice(&raw)
        .map_err(|e| DidSdkError::InvalidArgument(format!("parse {}: {e}", path.display())))
}

/// 将 Unix 秒格式化为 RFC3339 UTC 字符串（`YYYY-MM-DDTHH:MM:SSZ`）。
pub(crate) fn rfc3339_utc(timestamp: u64) -> String {
    let days = (timestamp / 86_400) as i64;
    let seconds = timestamp % 86_400;
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;

    // Howard Hinnant 的 civil_from_days 算法。
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

fn vc_hash(vc: &VerifiableCredential) -> Result<String, DidSdkError> {
    let bytes = serde_json::to_vec(vc)
        .map_err(|e| DidSdkError::InvalidArgument(format!("serialize VC: {e}")))?;
    Ok(hex::encode(blake2b256(&bytes)))
}

fn proof_for(core: &SdkCore, did: &str, purpose: &str, signature: &[u8]) -> VcProof {
    VcProof {
        proof_type: "Ed25519Signature2020".into(),
        created: rfc3339_utc(core.now()),
        verification_method: format!("{did}#key-1"),
        proof_purpose: purpose.into(),
        proof_value: bs58::encode(signature).into_string(),
    }
}

/// 签发 self-asserted VC。
pub(crate) async fn issue_self_asserted_vc(
    core: &SdkCore,
    claims: serde_json::Value,
) -> Result<VerifiableCredential, DidSdkError> {
    let did = core.active_did().await?;
    let now = core.now();

    let subject = claims
        .get("credentialSubject")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "id": did, "claims": claims }));
    let subject_did = subject
        .get("id")
        .and_then(|value| value.as_str())
        .unwrap_or(&did)
        .to_string();

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
    let vc_type = types
        .last()
        .cloned()
        .unwrap_or_else(|| "SelfAssertedCredential".into());

    let id_seed = format!(
        "{did}:{now}:{}",
        serde_json::to_string(&claims).unwrap_or_default()
    );
    let id = format!(
        "urn:did-sdk:vc:{}",
        hex::encode(blake2b256(id_seed.as_bytes()))
    );
    let anchor_id = hex::encode(blake2b256(id.as_bytes()));

    let mut vc = VerifiableCredential {
        context: vec!["https://www.w3.org/ns/credentials/v2".into()],
        id,
        types,
        issuer: did.clone(),
        issuance_date: rfc3339_utc(now),
        expiration_date: None,
        credential_subject: subject,
        proof: None,
        anchor_id: Some(anchor_id),
    };

    let hash = vc_hash(&vc)?;
    let signing_input = issued_vc_v1(&did, &subject_did, &vc_type, &hash);
    let signature = core.sign_with_active(&signing_input).await?;
    vc.proof = Some(proof_for(core, &did, "assertionMethod", &signature.0));
    Ok(vc)
}

/// 构造并签名 VP。
pub(crate) async fn build_vp(
    core: &SdkCore,
    vcs: Vec<VerifiableCredential>,
    challenge: &str,
    domain: &str,
) -> Result<VerifiablePresentation, DidSdkError> {
    let holder = core.active_did().await?;
    let vc_ids = vcs
        .iter()
        .filter_map(|vc| vc.anchor_id.clone())
        .collect::<Vec<_>>();
    core.confirm_vp(VpRequestContext {
        holder: holder.clone(),
        challenge: challenge.to_string(),
        domain: domain.to_string(),
        vc_ids,
    })
    .await?;

    let mut hashes = Vec::with_capacity(vcs.len());
    for vc in &vcs {
        hashes.push(vc_hash(vc)?);
    }
    let signing_input = vp_v1(&holder, challenge, domain, &hashes);
    let signature = core.sign_with_active(&signing_input).await?;

    Ok(VerifiablePresentation {
        context: vec!["https://www.w3.org/ns/credentials/v2".into()],
        types: vec!["VerifiablePresentation".into()],
        holder: holder.clone(),
        verifiable_credential: vcs,
        challenge: challenge.to_string(),
        domain: domain.to_string(),
        proof: Some(proof_for(core, &holder, "authentication", &signature.0)),
    })
}

/// 签发 VC 授权签名。
pub(crate) async fn sign_issue_authorization(
    core: &SdkCore,
    subject_did: &str,
    vc_type: &str,
    vc_hash: &str,
    timestamp: u64,
) -> Result<IssueAuthorizationSignature, DidSdkError> {
    let issuer_did = core.active_did().await?;
    core.confirm_authorization(AuthorizationRequestContext {
        subject_did: subject_did.to_string(),
        vc_type: vc_type.to_string(),
        vc_hash: vc_hash.to_string(),
        timestamp,
    })
    .await?;
    let signing_input = issued_vc_v1(&issuer_did, subject_did, vc_type, vc_hash);
    let signature = core.sign_with_active(&signing_input).await?;
    Ok(IssueAuthorizationSignature {
        issuer_did,
        subject_did: subject_did.to_string(),
        vc_type: vc_type.to_string(),
        vc_hash: vc_hash.to_string(),
        timestamp,
        signature: bs58::encode(&signature.0).into_string(),
    })
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
