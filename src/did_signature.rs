//! DID-Signature header 的构造与校验。
//!
//! 线格式：`DID-Signature-v1.<multibase(base64url, JSON)>`。
//! 签名输入仍然由 `keyvault_core::signing_input::did_signature_v1` 生成。

use serde::{Deserialize, Serialize};

use crate::DidSdkError;
use crate::core::SdkCore;
use crate::server_request::ChallengeContext;
use crate::types::{IntegrityStatus, VerifyResult};

const HEADER_PREFIX: &str = "DID-Signature-v1.";

#[derive(Debug, Serialize, Deserialize)]
struct HeaderBody {
    v: u8,
    did: String,
    from: String,
    timestamp: u64,
    anchor_ref: String,
    body_hash: String,
    rcpt_hash: String,
    sig: String,
}

fn invalid(reason: impl Into<String>) -> VerifyResult {
    VerifyResult {
        valid: false,
        integrity: IntegrityStatus::Invalid,
        did: None,
        timestamp: None,
        reason: Some(reason.into()),
    }
}

/// 构造 DID-Signature header。
pub(crate) async fn build_header(
    core: &SdkCore,
    from: &str,
    anchor_id: &str,
    body_hash: &str,
    rcpt_hash: &str,
) -> Result<String, DidSdkError> {
    let did = core.active_did().await?;
    let timestamp = core.now();
    core.confirm_challenge(ChallengeContext {
        did: did.clone(),
        from: from.to_string(),
        anchor_id: anchor_id.to_string(),
        body_hash: body_hash.to_string(),
        rcpt_hash: rcpt_hash.to_string(),
    })
    .await?;

    let signing_input = keyvault_core::signing_input::did_signature_v1(
        &did, from, timestamp, anchor_id, body_hash, rcpt_hash,
    );
    let signature = core.sign_with_active(&signing_input).await?;
    let body = HeaderBody {
        v: 1,
        did,
        from: from.to_string(),
        timestamp,
        anchor_ref: anchor_id.to_string(),
        body_hash: body_hash.to_string(),
        rcpt_hash: rcpt_hash.to_string(),
        sig: bs58::encode(&signature.0).into_string(),
    };
    let json = serde_json::to_vec(&body)
        .map_err(|e| DidSdkError::InvalidArgument(format!("serialize header: {e}")))?;
    let encoded = multibase::encode(multibase::Base::Base64Url, json);
    Ok(format!("{HEADER_PREFIX}{encoded}"))
}

/// 校验 DID-Signature header（本地 did:key，无网络）。
pub(crate) fn verify_header(
    _core: &SdkCore,
    header: &str,
    from: &str,
    body_hash: &str,
    rcpt_hash: &str,
) -> Result<VerifyResult, DidSdkError> {
    let Some(encoded) = header.strip_prefix(HEADER_PREFIX) else {
        return Ok(invalid("missing DID-Signature-v1 prefix"));
    };
    let (base, json) = match multibase::decode(encoded) {
        Ok(decoded) => decoded,
        Err(error) => return Ok(invalid(format!("invalid multibase: {error}"))),
    };
    if base != multibase::Base::Base64Url {
        return Ok(invalid(format!("unsupported multibase: {base:?}")));
    }
    let body: HeaderBody = match serde_json::from_slice(&json) {
        Ok(body) => body,
        Err(error) => return Ok(invalid(format!("invalid header JSON: {error}"))),
    };
    if body.v != 1 {
        return Ok(invalid(format!("unsupported header version: {}", body.v)));
    }
    if body.from != from {
        return Ok(invalid("header `from` does not match"));
    }
    if body.body_hash != body_hash {
        return Ok(invalid("header `body_hash` does not match"));
    }
    if body.rcpt_hash != rcpt_hash {
        return Ok(invalid("header `rcpt_hash` does not match"));
    }

    let public_key = match keyvault_core::crypto::decode_did_key_pubkey(&body.did) {
        Ok(public_key) => public_key,
        Err(error) => return Ok(invalid(format!("invalid DID: {error}"))),
    };
    let signature = match keyvault_core::crypto::base58::decode(&body.sig) {
        Ok(signature) => signature,
        Err(error) => return Ok(invalid(format!("invalid signature encoding: {error}"))),
    };
    let signing_input = keyvault_core::signing_input::did_signature_v1(
        &body.did,
        &body.from,
        body.timestamp,
        &body.anchor_ref,
        &body.body_hash,
        &body.rcpt_hash,
    );
    if !keyvault_core::crypto::ed25519::verify(&public_key, &signing_input, &signature) {
        return Ok(VerifyResult {
            valid: false,
            integrity: IntegrityStatus::Invalid,
            did: Some(body.did),
            timestamp: Some(body.timestamp),
            reason: Some("signature verification failed".into()),
        });
    }

    Ok(VerifyResult {
        valid: true,
        integrity: IntegrityStatus::Valid,
        did: Some(body.did),
        timestamp: Some(body.timestamp),
        reason: None,
    })
}
