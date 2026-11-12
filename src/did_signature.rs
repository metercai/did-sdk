//! DID-Signature header 编解码与本地验签。

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use crate::{AddressStatus, DidDocument, DidSdkError, IntegrityStatus, VerifyResult};

const HEADER_PREFIX: &str = "DID-Signature-v1.";

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HeaderBody {
    pub(crate) v: u8,
    pub(crate) did: String,
    pub(crate) from: String,
    pub(crate) timestamp: u64,
    pub(crate) anchor_ref: String,
    pub(crate) body_hash: String,
    pub(crate) rcpt_hash: String,
    pub(crate) sig: String,
}

pub(crate) fn encode_header(body: &HeaderBody) -> Result<String, DidSdkError> {
    let json = serde_json::to_vec(body)
        .map_err(|error| DidSdkError::InvalidArgument(format!("serialize header: {error}")))?;
    let encoded = multibase::encode(multibase::Base::Base64Url, json);
    Ok(format!("{HEADER_PREFIX}{encoded}"))
}

pub(crate) fn invalid(reason: impl Into<String>) -> VerifyResult {
    VerifyResult {
        verified: false,
        integrity: IntegrityStatus::Invalid,
        address: AddressStatus::Active,
        reason: Some(reason.into()),
    }
}

pub(crate) fn verify_header_with_docs(
    header: &str,
    from: &str,
    body_hash: &str,
    rcpt_hash: &str,
    docs: &HashMap<String, DidDocument>,
) -> VerifyResult {
    let Some(encoded) = header.strip_prefix(HEADER_PREFIX) else {
        return invalid("missing DID-Signature-v1 prefix");
    };
    let (base, json) = match multibase::decode(encoded) {
        Ok(decoded) => decoded,
        Err(error) => return invalid(format!("invalid multibase: {error}")),
    };
    if base != multibase::Base::Base64Url {
        return invalid(format!("unsupported multibase: {base:?}"));
    }
    let body: HeaderBody = match serde_json::from_slice(&json) {
        Ok(body) => body,
        Err(error) => return invalid(format!("invalid header JSON: {error}")),
    };
    if body.v != 1 {
        return invalid(format!("unsupported header version: {}", body.v));
    }
    if body.from != from {
        return invalid("header `from` does not match");
    }
    if body.body_hash != body_hash {
        return invalid("header `body_hash` does not match");
    }
    if body.rcpt_hash != rcpt_hash {
        return invalid("header `rcpt_hash` does not match");
    }
    let public_key = match crate::did::public_key_from_did_with_docs(&body.did, docs) {
        Ok(public_key) => public_key,
        Err(error) => return invalid(format!("invalid DID: {error}")),
    };
    let signature = match keyvault_core::crypto::base58::decode(&body.sig) {
        Ok(signature) => signature,
        Err(error) => return invalid(format!("invalid signature encoding: {error}")),
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
        return VerifyResult {
            verified: false,
            integrity: IntegrityStatus::Invalid,
            address: AddressStatus::Active,
            reason: Some("signature verification failed".into()),
        };
    }
    VerifyResult {
        verified: true,
        integrity: IntegrityStatus::Valid,
        address: AddressStatus::Active,
        reason: None,
    }
}
