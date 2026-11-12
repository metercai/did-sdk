//! did-sdk Node 绑定（Client 模式）。

#![allow(missing_docs)]

use std::sync::Arc;

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use secrecy::SecretString;

use did_sdk::config::{ConfigOverrides, resolve_config};
use did_sdk::{
    ClientConfig, DidSdkError as CoreError, DidSdkMode, PeerNumalgo, Proof, ServerConfig,
    VerifiableCredential, build_client_sdk, build_server_sdk,
};

type Sdk = did_sdk::DidSdk<did_sdk::Client>;

/// JS 构造参数。
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

/// JS 签名上下文。
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
        CoreError::InvalidArgument(_)
        | CoreError::UnsupportedDidMethod(_)
        | CoreError::DidResolutionFailed(_) => "InvalidArgument",
        _ => "DidSdkError",
    };
    napi::Error::new(napi::Status::GenericFailure, format!("{code}: {error}"))
}

fn to_json<T: serde::Serialize>(value: &T) -> napi::Result<serde_json::Value> {
    serde_json::to_value(value)
        .map_err(|error| napi::Error::from_reason(format!("SerializeError: {error}")))
}

fn parse_numalgo(value: &str) -> napi::Result<PeerNumalgo> {
    match value.to_ascii_lowercase().as_str() {
        "0" | "zero" => Ok(PeerNumalgo::Zero),
        "1" | "one" => Ok(PeerNumalgo::One),
        "2" | "two" => Ok(PeerNumalgo::Two),
        other => Err(napi::Error::from_reason(format!(
            "InvalidArgument: invalid PeerNumalgo {other}"
        ))),
    }
}

fn parse_mode(value: &str) -> napi::Result<DidSdkMode> {
    match value.to_ascii_lowercase().as_str() {
        "mock" => Ok(DidSdkMode::Mock),
        "centralized" => Ok(DidSdkMode::Centralized),
        "chain" => Ok(DidSdkMode::Chain),
        other => Err(napi::Error::from_reason(format!(
            "InvalidArgument: invalid mode {other}"
        ))),
    }
}

fn server_config(
    participant_did: String,
    overrides: Option<JsConfigOverrides>,
) -> napi::Result<ServerConfig> {
    let overrides = overrides.unwrap_or(JsConfigOverrides {
        mode: None,
        vc_storage_path: None,
        key_vault_path: None,
        key_vault_scheme: None,
        key_vault_password: None,
        key_vault_password_file: None,
        centralized_endpoint: None,
        chain_endpoint: None,
        cache_ttl_secs: None,
    });
    let mut config = ServerConfig::default();
    config.participant_did = participant_did;
    if let Some(mode) = overrides.mode {
        config.mode = parse_mode(&mode)?;
    }
    if let Some(path) = overrides.vc_storage_path {
        config.vc_storage_path = path.into();
    }
    if let Some(endpoint) = overrides.centralized_endpoint {
        config.centralized_endpoint = endpoint;
    }
    if let Some(endpoint) = overrides.chain_endpoint {
        config.chain_endpoint = endpoint;
    }
    if let Some(ttl) = overrides.cache_ttl_secs {
        config.cache_ttl_secs = u64::from(ttl);
    }
    if let Some(scheme) = overrides.key_vault_scheme {
        if scheme == "none" {
            config.key_vault = None;
        } else {
            let mut key_vault = config.key_vault.unwrap_or_default();
            key_vault.scheme = scheme;
            if let Some(path) = overrides.key_vault_path {
                key_vault.path = path.into();
            }
            if let Some(file) = overrides.key_vault_password_file {
                key_vault.password_file = file.into();
            }
            config.key_vault = Some(key_vault);
        }
    }
    if let Some(password) = overrides.key_vault_password {
        config.resolved_password = Some(SecretString::from(password));
    }
    Ok(config)
}

/// did-sdk Server Node 客户端。
#[napi]
pub struct ServerDidSdk {
    inner: Arc<did_sdk::DidSdk<did_sdk::Server>>,
    config: ServerConfig,
}

#[napi]
impl ServerDidSdk {
    #[napi(constructor)]
    pub fn new(
        participant_did: String,
        overrides: Option<JsConfigOverrides>,
    ) -> napi::Result<Self> {
        let config = server_config(participant_did, overrides)?;
        let sdk = build_server_sdk(&config).map_err(to_napi_err)?;
        Ok(Self { inner: sdk, config })
    }

    #[napi(getter)]
    pub fn participant_did(&self) -> String {
        self.config.participant_did.clone()
    }

    #[napi(getter)]
    pub fn has_signer(&self) -> bool {
        self.inner.has_signer()
    }

    #[napi]
    pub async fn resolve_did_web(&self, did: String) -> napi::Result<serde_json::Value> {
        let document = self
            .inner
            .resolve_did_web(&did)
            .await
            .map_err(to_napi_err)?;
        to_json(&document)
    }

    #[napi]
    pub fn assemble_vc_with_proof(
        &self,
        claims: serde_json::Value,
        subject_did: String,
        proof: serde_json::Value,
    ) -> napi::Result<serde_json::Value> {
        let proof: Proof = serde_json::from_value(proof)
            .map_err(|error| napi::Error::from_reason(format!("InvalidArgument: {error}")))?;
        let vc = self
            .inner
            .assemble_vc_with_proof(claims, &subject_did, proof)
            .map_err(to_napi_err)?;
        to_json(&vc)
    }

    #[napi]
    pub async fn verify_vc(&self, vc: serde_json::Value) -> napi::Result<serde_json::Value> {
        let vc: VerifiableCredential = serde_json::from_value(vc)
            .map_err(|error| napi::Error::from_reason(format!("InvalidArgument: {error}")))?;
        let result = self.inner.verify_vc(&vc).await.map_err(to_napi_err)?;
        to_json(&result)
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
    pub fn resolve_did(&self, did: String) -> napi::Result<Option<serde_json::Value>> {
        let record = self.inner.resolve_did(&did).map_err(to_napi_err)?;
        record.map(|record| to_json(&record)).transpose()
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
    pub async fn sign_with_participant_key(
        &self,
        message: Buffer,
        context: Option<JsSigningContext>,
    ) -> napi::Result<Buffer> {
        let context = context.unwrap_or(JsSigningContext {
            purpose: "sign".into(),
            payload_summary: None,
            requestor: None,
        });
        let signature = self
            .inner
            .sign_with_participant_key(
                message.as_ref(),
                did_sdk::SigningContext {
                    purpose: context.purpose,
                    payload_summary: context.payload_summary.unwrap_or_default(),
                    requestor: context.requestor,
                },
            )
            .await
            .map_err(to_napi_err)?;
        Ok(Buffer::from(signature.0))
    }

    #[napi]
    pub async fn issue_self_asserted_vc(
        &self,
        claims: serde_json::Value,
    ) -> napi::Result<serde_json::Value> {
        let vc = self
            .inner
            .issue_self_asserted_vc(claims)
            .map_err(to_napi_err)?;
        to_json(&vc)
    }

    #[napi]
    pub fn resolved_config(&self) -> napi::Result<serde_json::Value> {
        to_json(&self.config)
    }
}

/// did-sdk Client Node 客户端。
#[napi]
pub struct DidSdk {
    inner: Arc<Sdk>,
    config: ClientConfig,
}

#[napi]
impl DidSdk {
    #[napi(constructor)]
    pub fn new(overrides: Option<JsConfigOverrides>) -> napi::Result<Self> {
        let config = resolve_config(to_overrides(overrides)).map_err(to_napi_err)?;
        let sdk = build_client_sdk(&config).map_err(to_napi_err)?;
        Ok(Self { inner: sdk, config })
    }

    #[napi]
    pub async fn generate_did_key(&self) -> napi::Result<String> {
        self.inner.generate_did_key().map_err(to_napi_err)
    }

    #[napi]
    pub async fn generate_did_peer(&self, numalgo: String) -> napi::Result<String> {
        let numalgo = parse_numalgo(&numalgo)?;
        self.inner.generate_did_peer(numalgo).map_err(to_napi_err)
    }

    #[napi]
    pub async fn sign_with_did_key(
        &self,
        message: Buffer,
        context: Option<JsSigningContext>,
    ) -> napi::Result<Buffer> {
        let context = context.map(|context| did_sdk::SigningContext {
            purpose: context.purpose,
            payload_summary: context.payload_summary.unwrap_or_default(),
            requestor: context.requestor,
        });
        let signature = self
            .inner
            .sign_with_did_key(
                message.as_ref(),
                context.unwrap_or_else(|| did_sdk::SigningContext {
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
    pub fn resolve_did_peer(&self, did: String) -> napi::Result<serde_json::Value> {
        let document = self.inner.resolve_did_peer(&did).map_err(to_napi_err)?;
        to_json(&document)
    }

    #[napi]
    pub async fn create_did(&self) -> napi::Result<serde_json::Value> {
        let record = self.inner.create_did().map_err(to_napi_err)?;
        to_json(&record)
    }

    #[napi]
    pub fn resolve_did(&self, did: String) -> napi::Result<Option<serde_json::Value>> {
        let record = self.inner.resolve_did(&did).map_err(to_napi_err)?;
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
    ) -> napi::Result<Buffer> {
        let signature = self
            .inner
            .sign_issue_authorization(&subject_did, &vc_type, &vc_hash, u64::from(timestamp))
            .await
            .map_err(to_napi_err)?;
        Ok(Buffer::from(signature.0))
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

    #[napi(js_name = "gatewayAccessV1Bytes")]
    pub fn gateway_access_v1_bytes(did: String, agent_email: String, challenge: String) -> Buffer {
        Buffer::from(keyvault_core::signing_input::gateway_access_v1(
            &did,
            &agent_email,
            &challenge,
        ))
    }

    #[napi(js_name = "participantRegistrationV1Bytes")]
    pub fn participant_registration_v1_bytes(
        participant_id: u32,
        controller_did: String,
        operator: String,
        chain_role: String,
        business_types: Vec<String>,
        authorized_domains: Vec<String>,
    ) -> Buffer {
        Buffer::from(keyvault_core::signing_input::participant_registration_v1(
            participant_id,
            &controller_did,
            &operator,
            &chain_role,
            &business_types,
            &authorized_domains,
        ))
    }

    #[napi(js_name = "operatorRotationV1Bytes")]
    pub fn operator_rotation_v1_bytes(
        participant_id: u32,
        new_operator: String,
        timestamp: u32,
    ) -> Buffer {
        Buffer::from(keyvault_core::signing_input::operator_rotation_v1(
            participant_id,
            &new_operator,
            u64::from(timestamp),
        ))
    }

    #[napi(js_name = "controllerDidRotationV1Bytes")]
    pub fn controller_did_rotation_v1_bytes(
        participant_id: u32,
        new_controller_did: String,
        timestamp: u32,
    ) -> Buffer {
        Buffer::from(keyvault_core::signing_input::controller_did_rotation_v1(
            participant_id,
            &new_controller_did,
            u64::from(timestamp),
        ))
    }

    #[napi(js_name = "delegationAuthorizationV1Bytes")]
    pub fn delegation_authorization_v1_bytes(
        vc_hash: String,
        delegate_did: String,
        delegate_operator: String,
        timestamp: u32,
    ) -> Buffer {
        Buffer::from(keyvault_core::signing_input::delegation_authorization_v1(
            &vc_hash,
            &delegate_did,
            &delegate_operator,
            u64::from(timestamp),
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
