//! SD-JWT 选择性披露辅助：`_sd` 构造、Disclosure 筛选与验证。

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{DidSdkError, Disclosure, VerifiableCredential};

/// 支持的 `_sd_alg`。
pub const SD_ALG: &str = "sha-256";

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// 把 claims 中指定的属性移入 `_sd`，返回改造后的 claims 与 Disclosures。
///
/// - `id` / 不存在的属性返回 `disclosure_missing`；
/// - 每个可披露属性生成独立 16 字节盐；
/// - `_sd` 使用 base64url(SHA-256(...))，`_sd_alg = "sha-256"`。
pub fn split_selective_claims(
    claims: Value,
    disclosable: &[String],
) -> Result<(Value, Vec<Disclosure>), DidSdkError> {
    let mut wrapper = claims
        .as_object()
        .cloned()
        .ok_or_else(|| DidSdkError::InvalidArgument("claims must be a JSON object".into()))?;
    let mut subject = match wrapper.get("credentialSubject") {
        Some(Value::Object(subject)) => subject.clone(),
        Some(_) => {
            return Err(DidSdkError::InvalidArgument(
                "credentialSubject must be an object".into(),
            ));
        }
        None => wrapper.clone(),
    };
    if subject.contains_key("_sd") || subject.contains_key("_sd_alg") {
        return Err(DidSdkError::InvalidArgument(
            "claims already contain _sd/_sd_alg".into(),
        ));
    }

    let mut disclosures = Vec::new();
    let mut hashes = Vec::new();
    for name in disclosable {
        if name == "id" {
            return Err(DidSdkError::DisclosureMissing(
                "id is mandatory and cannot be disclosed selectively".into(),
            ));
        }
        let value = subject
            .remove(name)
            .ok_or_else(|| DidSdkError::DisclosureMissing(format!("claim not found: {name}")))?;
        let disclosure = Disclosure::generate(name.clone(), value)?;
        hashes.push(disclosure.hash_string()?);
        disclosures.push(disclosure);
    }
    if !hashes.is_empty() {
        subject.insert(
            "_sd".into(),
            Value::Array(hashes.into_iter().map(Value::String).collect()),
        );
        subject.insert("_sd_alg".into(), Value::String(SD_ALG.into()));
    }

    if wrapper.contains_key("credentialSubject") {
        wrapper.insert("credentialSubject".into(), Value::Object(subject));
    } else {
        let mut out = Map::new();
        if let Some(value) = wrapper.get("type").cloned() {
            out.insert("type".into(), value);
        }
        if let Some(value) = wrapper.get("expirationDate").cloned() {
            out.insert("expirationDate".into(), value);
        }
        out.insert("credentialSubject".into(), Value::Object(subject));
        wrapper = out;
    }
    Ok((Value::Object(wrapper), disclosures))
}

/// 按属性名筛选 Disclosure；默认空集合表示全部隐藏。
pub fn select_disclosures(
    all: &[Disclosure],
    names: &[String],
) -> Result<Vec<Disclosure>, DidSdkError> {
    let mut selected = Vec::with_capacity(names.len());
    let mut seen = std::collections::HashSet::new();
    for name in names {
        if !seen.insert(name) {
            return Err(DidSdkError::DisclosureDuplicate(name.clone()));
        }
        let disclosure = all
            .iter()
            .find(|disclosure| &disclosure.name == name)
            .ok_or_else(|| DidSdkError::DisclosureMissing(name.clone()))?;
        selected.push(disclosure.clone());
    }
    Ok(selected)
}

/// Disclosures 数组 canonical JSON 的 SHA-256（hex）。
pub fn disclosures_hash(disclosures: &[Disclosure]) -> Result<String, DidSdkError> {
    let bytes = serde_json::to_vec(disclosures)
        .map_err(|error| DidSdkError::InvalidArgument(format!("serialize disclosures: {error}")))?;
    Ok(sha256_hex(&bytes))
}

/// 返回 VC `credentialSubject._sd` 中的哈希集合。
pub fn sd_hashes(
    vc: &VerifiableCredential,
) -> Result<std::collections::HashSet<String>, DidSdkError> {
    let Some(subject) = vc.credential_subject.as_object() else {
        return Err(DidSdkError::InvalidArgument(
            "credentialSubject must be an object".into(),
        ));
    };
    let Some(sd) = subject.get("_sd") else {
        return Ok(std::collections::HashSet::new());
    };
    let alg = subject
        .get("_sd_alg")
        .and_then(Value::as_str)
        .ok_or_else(|| DidSdkError::SdAlgUnsupported("_sd_alg missing".into()))?;
    if alg != SD_ALG {
        return Err(DidSdkError::SdAlgUnsupported(alg.into()));
    }
    let array = sd
        .as_array()
        .ok_or_else(|| DidSdkError::InvalidArgument("_sd must be an array".into()))?;
    let mut out = std::collections::HashSet::new();
    for value in array {
        let hash = value
            .as_str()
            .ok_or_else(|| DidSdkError::InvalidArgument("_sd entries must be strings".into()))?;
        out.insert(hash.to_string());
    }
    Ok(out)
}

/// 校验一组 Disclosure 是否都能匹配 `_sd`，并拒绝重复属性。
pub fn verify_disclosures(
    vc: &VerifiableCredential,
    disclosures: &[Disclosure],
) -> Result<usize, DidSdkError> {
    let hashes = sd_hashes(vc)?;
    if !disclosures.is_empty() && hashes.is_empty() {
        return Err(DidSdkError::DisclosureHashMismatch(
            "VC has no _sd array".into(),
        ));
    }
    let mut names = std::collections::HashSet::new();
    for disclosure in disclosures {
        if !names.insert(disclosure.name.as_str()) {
            return Err(DidSdkError::DisclosureDuplicate(disclosure.name.clone()));
        }
        let hash = disclosure.hash_string()?;
        if !hashes.contains(&hash) {
            return Err(DidSdkError::DisclosureHashMismatch(disclosure.name.clone()));
        }
    }
    Ok(disclosures.len())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn splits_claims_and_verifies() {
        let claims = serde_json::json!({
            "type": "IDCardVC",
            "name": "Alice",
            "gender": "F",
            "idCardNumber": "123"
        });
        let (claims, disclosures) =
            split_selective_claims(claims, &["name".into(), "gender".into()]).unwrap();
        assert_eq!(claims["credentialSubject"]["_sd_alg"], "sha-256");
        assert_eq!(
            claims["credentialSubject"]["_sd"].as_array().unwrap().len(),
            2
        );
        assert!(claims["credentialSubject"].get("name").is_none());
        let vc = crate::vc::build_vc("did:key:zIssuer", claims, None);
        assert_eq!(verify_disclosures(&vc, &disclosures).unwrap(), 2);
        assert!(matches!(
            verify_disclosures(
                &vc,
                &[Disclosure::generate("name", "Mallory".into()).unwrap()]
            ),
            Err(DidSdkError::DisclosureHashMismatch(_))
        ));
    }

    #[test]
    fn rejects_duplicate_selection() {
        let d = Disclosure::generate("name", "Alice".into()).unwrap();
        assert!(matches!(
            select_disclosures(&[d], &["name".into(), "name".into()]),
            Err(DidSdkError::DisclosureDuplicate(_))
        ));
    }
}
