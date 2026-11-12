//! DID 方法与 DID 文档辅助（did:key / did:peer / did:web）。

use std::collections::HashMap;

use keyvault_core::crypto::{blake2::blake2b256, decode_did_key_pubkey, encode_did_key};
use multibase::Base;

use crate::{DidDocument, DidSdkError, PeerNumalgo, VerificationMethod};

/// 构造 did:key 文档。
pub fn did_key_document(pubkey: &[u8; 32]) -> DidDocument {
    let did = encode_did_key(pubkey);
    let multibase = did.strip_prefix("did:key:").unwrap_or_default().to_string();
    DidDocument {
        id: did.clone(),
        also_known_as: Vec::new(),
        verification_method: vec![VerificationMethod {
            id: format!("{did}#key-1"),
            type_: "Ed25519VerificationKey2020".into(),
            controller: did.clone(),
            public_key_multibase: Some(multibase),
            public_key_jwk: None,
        }],
        authentication: vec![format!("{did}#key-1")],
        assertion_method: vec![format!("{did}#key-1")],
        service: Vec::new(),
    }
}

/// 构造 did:peer 及其文档。
///
/// POC 简化：
/// - numalgo 0：`did:peer:0z<multibase(0xED01||key)>`
/// - numalgo 1：`did:peer:1z<base58btc(blake2b256(document JSON))>`，文档由本地保存
/// - numalgo 2：`did:peer:2z<multibase(0xED01||key)>`（POC 简化编码）
pub fn encode_peer_did(pubkey: &[u8; 32], numalgo: PeerNumalgo) -> (String, DidDocument) {
    let multibase = encode_did_key(pubkey)
        .strip_prefix("did:key:")
        .unwrap_or_default()
        .to_string();
    let mut data = Vec::with_capacity(34);
    data.extend_from_slice(&[0xED, 0x01]);
    data.extend_from_slice(pubkey);
    let encoded = multibase::encode(Base::Base58Btc, &data);
    match numalgo {
        PeerNumalgo::Zero => {
            let did = format!("did:peer:0{encoded}");
            (did.clone(), document_for_peer(&did, &multibase))
        }
        PeerNumalgo::Two => {
            let did = format!("did:peer:2{encoded}");
            (did.clone(), document_for_peer(&did, &multibase))
        }
        PeerNumalgo::One => {
            let seed_doc = document_for_peer("did:peer:1", &multibase);
            let json = serde_json::to_vec(&seed_doc).unwrap_or_default();
            let hash = blake2b256(&json);
            let did = format!("did:peer:1{}", multibase::encode(Base::Base58Btc, hash));
            let mut doc = document_for_peer(&did, &multibase);
            doc.id = did.clone();
            doc.verification_method[0].id = format!("{did}#key-1");
            doc.verification_method[0].controller = did.clone();
            doc.authentication = vec![format!("{did}#key-1")];
            doc.assertion_method = vec![format!("{did}#key-1")];
            (did, doc)
        }
    }
}

fn document_for_peer(did: &str, multibase: &str) -> DidDocument {
    DidDocument {
        id: did.to_string(),
        also_known_as: Vec::new(),
        verification_method: vec![VerificationMethod {
            id: format!("{did}#key-1"),
            type_: "Ed25519VerificationKey2020".into(),
            controller: did.to_string(),
            public_key_multibase: Some(multibase.to_string()),
            public_key_jwk: None,
        }],
        authentication: vec![format!("{did}#key-1")],
        assertion_method: vec![format!("{did}#key-1")],
        service: Vec::new(),
    }
}

/// 解析 did:peer。numalgo 1 需要调用方提供本地文档缓存。
pub fn resolve_peer(
    did: &str,
    docs: &HashMap<String, DidDocument>,
) -> Result<DidDocument, DidSdkError> {
    if let Some(document) = docs.get(did) {
        return Ok(document.clone());
    }
    let rest = did
        .strip_prefix("did:peer:")
        .ok_or_else(|| DidSdkError::DidResolutionFailed(format!("not a did:peer: {did}")))?;
    if rest.len() < 2 {
        return Err(DidSdkError::DidResolutionFailed(
            "empty did:peer identifier".into(),
        ));
    }
    let (numalgo, encoded) = rest.split_at(1);
    let _public_key = decode_multibase_key(encoded)?;
    match numalgo {
        "0" | "2" => Ok(document_for_peer(did, encoded)),
        "1" => Err(DidSdkError::DidResolutionFailed(
            "did:peer:1 requires the accompanying DID document".into(),
        )),
        other => Err(DidSdkError::UnsupportedDidMethod(format!(
            "did:peer numalgo {other}"
        ))),
    }
}

/// 从多 base58/multibase 字符串解析 Ed25519 公钥。
pub fn decode_multibase_key(encoded: &str) -> Result<[u8; 32], DidSdkError> {
    let (base, data) = multibase::decode(encoded)
        .map_err(|error| DidSdkError::DidResolutionFailed(format!("invalid multibase: {error}")))?;
    if base != Base::Base58Btc {
        return Err(DidSdkError::DidResolutionFailed(format!(
            "unsupported multibase: {base:?}"
        )));
    }
    let key_bytes = match data.as_slice() {
        [0xED, 0x01, rest @ ..] if rest.len() == 32 => rest,
        bytes if bytes.len() == 32 => bytes,
        _ => {
            return Err(DidSdkError::DidResolutionFailed(
                "unsupported DID key multicodec".into(),
            ));
        }
    };
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);
    Ok(key)
}

/// 从 DID 文档中取第一个 Ed25519 公钥。
pub fn document_public_key(document: &DidDocument) -> Result<[u8; 32], DidSdkError> {
    for method in &document.verification_method {
        if let Some(encoded) = &method.public_key_multibase {
            return decode_multibase_key(encoded);
        }
        if let Some(jwk) = &method.public_key_jwk {
            if let (Some("OKP"), Some("Ed25519"), Some(x)) = (
                jwk.get("kty").and_then(|value| value.as_str()),
                jwk.get("crv").and_then(|value| value.as_str()),
                jwk.get("x").and_then(|value| value.as_str()),
            ) {
                let bytes = base64url_decode(x)?;
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    return Ok(key);
                }
            }
        }
    }
    Err(DidSdkError::DidResolutionFailed(
        "DID document has no Ed25519 public key".into(),
    ))
}

/// 解析 did:key 文档。
pub fn did_key_document_from_did(did: &str) -> Result<DidDocument, DidSdkError> {
    let pubkey = decode_did_key_pubkey(did)
        .map_err(|error| DidSdkError::DidResolutionFailed(error.to_string()))?;
    Ok(did_key_document(&pubkey))
}

/// 计算 did:web 的 HTTPS 文档 URL。
pub fn did_web_url(did: &str) -> Result<String, DidSdkError> {
    let rest = did
        .strip_prefix("did:web:")
        .ok_or_else(|| DidSdkError::DidResolutionFailed(format!("not a did:web: {did}")))?;
    let mut parts = rest.split(':');
    let host = parts
        .next()
        .ok_or_else(|| DidSdkError::DidResolutionFailed("empty did:web host".into()))?;
    let host = percent_decode(host);
    let path: Vec<String> = parts.map(percent_decode).collect();
    if path.is_empty() {
        Ok(format!("https://{host}/.well-known/did.json"))
    } else {
        Ok(format!("https://{host}/{}/did.json", path.join("/")))
    }
}

fn percent_decode(value: &str) -> String {
    value.replace("%3A", ":").replace("%3a", ":")
}

fn base64url_decode(value: &str) -> Result<Vec<u8>, DidSdkError> {
    multibase::decode(format!("u{value}"))
        .map(|(_, data)| data)
        .map_err(|error| DidSdkError::DidResolutionFailed(format!("invalid base64url: {error}")))
}

/// 从 did:key / did:peer:0 / did:peer:2 直接解析公钥。
pub fn public_key_from_did(did: &str) -> Result<[u8; 32], DidSdkError> {
    if did.starts_with("did:key:") {
        return decode_did_key_pubkey(did)
            .map_err(|error| DidSdkError::DidResolutionFailed(error.to_string()));
    }
    if let Some(rest) = did.strip_prefix("did:peer:") {
        let (numalgo, encoded) = rest.split_at(1);
        if matches!(numalgo, "0" | "2") {
            return decode_multibase_key(encoded);
        }
    }
    Err(DidSdkError::UnsupportedDidMethod(did.to_string()))
}

/// 从 DID 解析公钥；did:peer:1 需要本地文档缓存。
pub fn public_key_from_did_with_docs(
    did: &str,
    docs: &HashMap<String, DidDocument>,
) -> Result<[u8; 32], DidSdkError> {
    if did.starts_with("did:peer:1") {
        let document = docs.get(did).ok_or_else(|| {
            DidSdkError::DidResolutionFailed(
                "did:peer:1 requires the accompanying DID document".into(),
            )
        })?;
        return document_public_key(document);
    }
    public_key_from_did(did)
}
