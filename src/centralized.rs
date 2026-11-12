//! Centralized 模式：只读 HTTP（仅 GET），带 TTL 缓存。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_lock::RwLock;
use async_trait::async_trait;
use keyvault_core::KeyVault;

use crate::core::{SdkCore, map_vault_err};
use crate::did_signature;
use crate::server_request::ServerRequestHandler;
use crate::types::{
    AnchorRecord, DidRecord, Ed25519PublicKey, IssueAuthorizationSignature, Signature,
    SigningContext, VerifiableCredential, VerifiablePresentation, VerifyResult,
};
use crate::vc;
use crate::{DidSdk, DidSdkConfig, DidSdkError};

#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    inserted: Instant,
}

/// Centralized 只读实现。
pub struct CentralizedDidSdk {
    pub(crate) core: SdkCore,
    http: reqwest::Client,
    anchors: RwLock<HashMap<String, CacheEntry<AnchorRecord>>>,
    dids: RwLock<HashMap<String, CacheEntry<DidRecord>>>,
}

impl CentralizedDidSdk {
    /// 构造 Centralized SDK。
    pub fn new(vault: Arc<dyn KeyVault>, config: DidSdkConfig) -> Result<Self, DidSdkError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("did-sdk/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| DidSdkError::ConfigError(format!("build HTTP client: {e}")))?;
        Ok(Self {
            core: SdkCore::new(vault, config)?,
            http,
            anchors: RwLock::new(HashMap::new()),
            dids: RwLock::new(HashMap::new()),
        })
    }

    fn cache_is_fresh<T>(entry: &CacheEntry<T>, ttl_secs: u64) -> bool {
        entry.inserted.elapsed() < Duration::from_secs(ttl_secs)
    }

    fn url(&self, resource: &str, id: &str) -> Result<reqwest::Url, DidSdkError> {
        let mut url = reqwest::Url::parse(&self.core.config.centralized_endpoint)
            .map_err(|e| DidSdkError::ConfigError(format!("invalid endpoint: {e}")))?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|()| DidSdkError::ConfigError("endpoint cannot be a base URL".into()))?;
            segments.pop_if_empty();
            segments.push(resource);
            segments.push(id);
        }
        Ok(url)
    }

    async fn fetch_anchor(&self, anchor_id: &str) -> Result<AnchorRecord, DidSdkError> {
        let url = self.url("anchors", anchor_id)?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| DidSdkError::ChainUnavailable(e.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DidSdkError::AnchorNotFound(anchor_id.to_string()));
        }
        if !response.status().is_success() {
            return Err(DidSdkError::ChainUnavailable(format!(
                "GET anchor returned HTTP {}",
                response.status()
            )));
        }
        response
            .json::<AnchorRecord>()
            .await
            .map_err(|e| DidSdkError::ChainUnavailable(format!("invalid anchor JSON: {e}")))
    }

    async fn fetch_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError> {
        let url = self.url("dids", did)?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| DidSdkError::ChainUnavailable(e.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(DidSdkError::ChainUnavailable(format!(
                "GET DID returned HTTP {}",
                response.status()
            )));
        }
        response
            .json::<DidRecord>()
            .await
            .map(Some)
            .map_err(|e| DidSdkError::ChainUnavailable(format!("invalid DID JSON: {e}")))
    }
}

#[async_trait]
impl DidSdk for CentralizedDidSdk {
    async fn generate_did_key(&self) -> Result<String, DidSdkError> {
        self.core.generate_did_key().await
    }

    async fn sign_with_did_key(
        &self,
        message: &[u8],
        _ctx: SigningContext,
    ) -> Result<Signature, DidSdkError> {
        self.core.sign_with_active(message).await
    }

    fn resolve_did_key(&self, did: &str) -> Result<Ed25519PublicKey, DidSdkError> {
        keyvault_core::crypto::decode_did_key_pubkey(did)
            .map(Ed25519PublicKey)
            .map_err(map_vault_err)
    }

    async fn create_did(&self) -> Result<DidRecord, DidSdkError> {
        let record = self.core.create_did_record().await?;
        self.dids.write().await.insert(
            record.did.clone(),
            CacheEntry {
                value: record.clone(),
                inserted: Instant::now(),
            },
        );
        Ok(record)
    }

    async fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError> {
        {
            let cache = self.dids.read().await;
            if let Some(entry) = cache.get(did) {
                if Self::cache_is_fresh(entry, self.core.config.cache_ttl_secs) {
                    return Ok(Some(entry.value.clone()));
                }
            }
        }
        let Some(record) = self.fetch_did(did).await? else {
            return Ok(None);
        };
        self.dids.write().await.insert(
            did.to_string(),
            CacheEntry {
                value: record.clone(),
                inserted: Instant::now(),
            },
        );
        Ok(Some(record))
    }

    async fn issue_self_asserted_vc(
        &self,
        claims: serde_json::Value,
    ) -> Result<VerifiableCredential, DidSdkError> {
        vc::issue_self_asserted_vc(&self.core, claims).await
    }

    async fn store_vc(&self, vc: VerifiableCredential) -> Result<(), DidSdkError> {
        self.core.vcs.put(&vc)
    }

    async fn get_vc(&self, anchor_id: &str) -> Result<Option<VerifiableCredential>, DidSdkError> {
        self.core.vcs.get(anchor_id)
    }

    async fn list_vcs(&self) -> Result<Vec<VerifiableCredential>, DidSdkError> {
        self.core.vcs.list()
    }

    async fn remove_vc(&self, anchor_id: &str) -> Result<(), DidSdkError> {
        self.core.vcs.remove(anchor_id)
    }

    async fn build_vp(
        &self,
        vcs: Vec<VerifiableCredential>,
        challenge: &str,
        domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError> {
        vc::build_vp(&self.core, vcs, challenge, domain).await
    }

    async fn build_did_signature_header(
        &self,
        from: &str,
        anchor_id: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> Result<String, DidSdkError> {
        did_signature::build_header(&self.core, from, anchor_id, body_hash, rcpt_hash).await
    }

    fn verify_did_signature_header(
        &self,
        header: &str,
        from: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> Result<VerifyResult, DidSdkError> {
        did_signature::verify_header(&self.core, header, from, body_hash, rcpt_hash)
    }

    async fn sign_issue_authorization(
        &self,
        subject_did: &str,
        vc_type: &str,
        vc_hash: &str,
        timestamp: u64,
    ) -> Result<IssueAuthorizationSignature, DidSdkError> {
        vc::sign_issue_authorization(&self.core, subject_did, vc_type, vc_hash, timestamp).await
    }

    async fn get_anchor(&self, anchor_id: &str) -> Result<AnchorRecord, DidSdkError> {
        {
            let cache = self.anchors.read().await;
            if let Some(entry) = cache.get(anchor_id) {
                if Self::cache_is_fresh(entry, self.core.config.cache_ttl_secs) {
                    return Ok(entry.value.clone());
                }
            }
        }
        let record = self.fetch_anchor(anchor_id).await?;
        self.anchors.write().await.insert(
            anchor_id.to_string(),
            CacheEntry {
                value: record.clone(),
                inserted: Instant::now(),
            },
        );
        Ok(record)
    }

    fn set_request_handler(&self, handler: Arc<dyn ServerRequestHandler>) {
        self.core.set_handler(handler);
    }
}
