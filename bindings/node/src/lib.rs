//! did-sdk Node 绑定（napi-rs）。

#![allow(missing_docs)]

use std::sync::Arc;

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use did_sdk::config::{ConfigOverrides, resolve_config};
use did_sdk::{
    DidSdk as DidSdkTrait, DidSdkConfig, DidSdkError as CoreError, SigningContext,
    VerifiableCredential, build_did_sdk,
};

/// JS 侧构造参数（camelCase 由 napi 自动映射）。
#[napi(object)]
pub struct JsConfigOverrides {
    pub mode: Option<String>,
    pub vc_storage_path: Option<String>,
    pub key_vault_path: Option<String>,
    pub key_vault_scheme: Option<String>,
    pub key_vault_password: Option<String>,
    pub key_vault_password_file: Option<String>,
    pub centralized_endpoint: Option<String>,
    pub chain_endpoint: Option<String>,
    pub cache_ttl_secs: Option<u32>,
}

/// JS 侧签名上下文。
#[napi(object)]
pub struct JsSigningContext {
    pub purpose: String,
    pub payload_summary: Option<String>,
    pub requestor: Option<String>,
}

fn to_overrides(overrides: Option<JsConfigOverrides>) -> ConfigOverrides {
    let Some(overrides) = overrides else {
        return ConfigOverrides::default();
    };
    ConfigOverrides {
        mode: overrides.mode,
        vc_storage_path: overrides.vc_storage_path.map(Into::into),
        key_vault_path: overrides.key_vault_path.map(Into::into),
        key_vault_scheme: overrides.key_vault_scheme,
        key_vault_password: overrides.key_vault_password,
        key_vault_password_file: overrides.key_vault_password_file.map(Into::into),
        centralized_endpoint: overrides.centralized_endpoint,
        chain_endpoint: overrides.chain_endpoint,
        cache_ttl_secs: overrides.cache_ttl_secs.map(u64::from),
    }
}

fn to_napi_err(error: CoreError) -> napi::Error {
    let code = match &error {
        CoreError::UserRejected => "UserRejected",
        CoreError::VcNotFound(_) | CoreError::AnchorNotFound(_) => "NotFound",
        CoreError::InvalidArgument(_) => "InvalidArgument",
        _ => "DidSdkError",
    };
    napi::Error::new(napi::Status::GenericFailure, format!("{code}: {error}"))
}

fn to_json<T: serde::Serialize>(value: &T) -> napi::Result<serde_json::Value> {
    serde_json::to_value(value)
        .map_err(|error| napi::Error::from_reason(format!("SerializeError: {error}")))
}

/// did-sdk 的统一 Node 客户端。
#[napi]
pub struct DidSdk {
    inner: Arc<dyn DidSdkTrait>,
    config: DidSdkConfig,
}

#[napi]
impl DidSdk {
    #[napi(constructor)]
    pub fn new(overrides: Option<JsConfigOverrides>) -> napi::Result<Self> {
        let config = resolve_config(to_overrides(overrides)).map_err(to_napi_err)?;
        let sdk = build_did_sdk(&config).map_err(to_napi_err)?;
        Ok(Self { inner: sdk, config })
    }

    #[napi]
    pub async fn generate_did_key(&self) -> napi::Result<String> {
        self.inner.generate_did_key().await.map_err(to_napi_err)
    }

    #[napi]
    pub async fn sign_with_did_key(
        &self,
        message: Buffer,
        context: Option<JsSigningContext>,
    ) -> napi::Result<Buffer> {
        let context = context.map(|context| SigningContext {
            purpose: context.purpose,
            payload_summary: context.payload_summary.unwrap_or_default(),
            requestor: context.requestor,
        });
        let signature = self
            .inner
            .sign_with_did_key(
                message.as_ref(),
                context.unwrap_or_else(|| SigningContext {
                    purpose: "sign".into(),
                    payload_summary: String::new(),
                    requestor: None,
                }),
            )
            .await
            .map_err(to_napi_err)?;
        Ok(Buffer::from(signature.0))
    }

    #[napi]
    pub fn resolve_did_key(&self, did: String) -> napi::Result<Buffer> {
        let key = self.inner.resolve_did_key(&did).map_err(to_napi_err)?;
        Ok(Buffer::from(key.0.to_vec()))
    }

    #[napi]
    pub async fn create_did(&self) -> napi::Result<serde_json::Value> {
        let record = self.inner.create_did().await.map_err(to_napi_err)?;
        to_json(&record)
    }

    #[napi]
    pub async fn resolve_did(&self, did: String) -> napi::Result<Option<serde_json::Value>> {
        let record = self.inner.resolve_did(&did).await.map_err(to_napi_err)?;
        record.map(|record| to_json(&record)).transpose()
    }

    #[napi]
    pub async fn issue_self_asserted_vc(
        &self,
        claims: serde_json::Value,
    ) -> napi::Result<serde_json::Value> {
        let vc = self
            .inner
            .issue_self_asserted_vc(claims)
            .await
            .map_err(to_napi_err)?;
        to_json(&vc)
    }

    #[napi]
    pub async fn store_vc(&self, vc: serde_json::Value) -> napi::Result<()> {
        let vc: VerifiableCredential = serde_json::from_value(vc)
            .map_err(|error| napi::Error::from_reason(format!("InvalidArgument: {error}")))?;
        self.inner.store_vc(vc).await.map_err(to_napi_err)
    }

    #[napi]
    pub async fn get_vc(&self, anchor_id: String) -> napi::Result<Option<serde_json::Value>> {
        let vc = self.inner.get_vc(&anchor_id).await.map_err(to_napi_err)?;
        vc.map(|vc| to_json(&vc)).transpose()
    }

    #[napi]
    pub async fn list_vcs(&self) -> napi::Result<Vec<serde_json::Value>> {
        let vcs = self.inner.list_vcs().await.map_err(to_napi_err)?;
        vcs.iter().map(to_json).collect()
    }

    #[napi]
    pub async fn remove_vc(&self, anchor_id: String) -> napi::Result<()> {
        self.inner.remove_vc(&anchor_id).await.map_err(to_napi_err)
    }

    #[napi]
    pub async fn build_vp(
        &self,
        vcs: Vec<serde_json::Value>,
        challenge: String,
        domain: String,
    ) -> napi::Result<serde_json::Value> {
        let vcs = vcs
            .into_iter()
            .map(|value| {
                serde_json::from_value::<VerifiableCredential>(value)
                    .map_err(|error| napi::Error::from_reason(format!("InvalidArgument: {error}")))
            })
            .collect::<napi::Result<Vec<_>>>()?;
        let vp = self
            .inner
            .build_vp(vcs, &challenge, &domain)
            .await
            .map_err(to_napi_err)?;
        to_json(&vp)
    }

    #[napi]
    pub async fn build_did_signature_header(
        &self,
        from: String,
        anchor_id: String,
        body_hash: String,
        rcpt_hash: String,
    ) -> napi::Result<String> {
        self.inner
            .build_did_signature_header(&from, &anchor_id, &body_hash, &rcpt_hash)
            .await
            .map_err(to_napi_err)
    }

    #[napi]
    pub fn verify_did_signature_header(
        &self,
        header: String,
        from: String,
        body_hash: String,
        rcpt_hash: String,
    ) -> napi::Result<serde_json::Value> {
        let result = self
            .inner
            .verify_did_signature_header(&header, &from, &body_hash, &rcpt_hash)
            .map_err(to_napi_err)?;
        to_json(&result)
    }

    #[napi]
    pub async fn sign_issue_authorization(
        &self,
        subject_did: String,
        vc_type: String,
        vc_hash: String,
        timestamp: u32,
    ) -> napi::Result<serde_json::Value> {
        let signature = self
            .inner
            .sign_issue_authorization(&subject_did, &vc_type, &vc_hash, u64::from(timestamp))
            .await
            .map_err(to_napi_err)?;
        to_json(&signature)
    }

    #[napi]
    pub async fn get_anchor(&self, anchor_id: String) -> napi::Result<serde_json::Value> {
        let anchor = self
            .inner
            .get_anchor(&anchor_id)
            .await
            .map_err(to_napi_err)?;
        to_json(&anchor)
    }

    #[napi]
    pub fn resolved_config(&self) -> napi::Result<serde_json::Value> {
        to_json(&self.config)
    }

    #[napi(js_name = "didSignatureV1Bytes")]
    pub fn did_signature_v1_bytes(
        did: String,
        from: String,
        timestamp: u32,
        anchor_ref: String,
        body_hash: String,
        rcpt_hash: String,
    ) -> Buffer {
        Buffer::from(keyvault_core::signing_input::did_signature_v1(
            &did,
            &from,
            u64::from(timestamp),
            &anchor_ref,
            &body_hash,
            &rcpt_hash,
        ))
    }

    #[napi(js_name = "issuedVcV1Bytes")]
    pub fn issued_vc_v1_bytes(
        issuer_did: String,
        subject_did: String,
        vc_type: String,
        vc_hash: String,
    ) -> Buffer {
        Buffer::from(keyvault_core::signing_input::issued_vc_v1(
            &issuer_did,
            &subject_did,
            &vc_type,
            &vc_hash,
        ))
    }

    #[napi(js_name = "vpV1Bytes")]
    pub fn vp_v1_bytes(
        holder: String,
        challenge: String,
        domain: String,
        vc_hashes: Vec<String>,
    ) -> Buffer {
        Buffer::from(keyvault_core::signing_input::vp_v1(
            &holder, &challenge, &domain, &vc_hashes,
        ))
    }

    #[napi(js_name = "ed25519SignWithSeed")]
    pub fn ed25519_sign_with_seed(seed_hex: String, payload: Buffer) -> napi::Result<Buffer> {
        let seed = hex::decode(seed_hex)
            .map_err(|error| napi::Error::from_reason(format!("InvalidArgument: {error}")))?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| napi::Error::from_reason("InvalidArgument: seed must be 32 bytes"))?;
        Ok(Buffer::from(
            keyvault_core::crypto::ed25519::sign_with_seed(&seed, payload.as_ref()),
        ))
    }
}
