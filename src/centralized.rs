//! Centralized 后端：只读 HTTP（仅 GET），带 TTL 缓存。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_lock::RwLock;
use async_trait::async_trait;

use crate::backend::Backend;
use crate::{AnchorRecord, DidRecord, DidSdkError};

#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    inserted: Instant,
}

/// 中心化模拟链后端。
pub struct CentralizedBackend {
    http: reqwest::Client,
    endpoint: String,
    ttl_secs: u64,
    anchors: RwLock<HashMap<String, CacheEntry<AnchorRecord>>>,
    dids: RwLock<HashMap<String, CacheEntry<DidRecord>>>,
}

impl CentralizedBackend {
    /// 构造后端。
    pub fn new(endpoint: String, ttl_secs: u64) -> Result<Self, DidSdkError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("did-sdk/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| DidSdkError::ConfigError(format!("build HTTP client: {error}")))?;
        Ok(Self {
            http,
            endpoint,
            ttl_secs,
            anchors: RwLock::new(HashMap::new()),
            dids: RwLock::new(HashMap::new()),
        })
    }

    fn fresh<T>(entry: &CacheEntry<T>, ttl_secs: u64) -> bool {
        entry.inserted.elapsed() < Duration::from_secs(ttl_secs)
    }

    fn url(&self, resource: &str, id: &str) -> Result<reqwest::Url, DidSdkError> {
        let mut url = reqwest::Url::parse(&self.endpoint)
            .map_err(|error| DidSdkError::ConfigError(format!("invalid endpoint: {error}")))?;
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
            .map_err(|error| DidSdkError::ChainUnavailable(error.to_string()))?;
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
            .map_err(|error| DidSdkError::ChainUnavailable(format!("invalid anchor JSON: {error}")))
    }

    async fn fetch_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError> {
        let url = self.url("dids", did)?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|error| DidSdkError::ChainUnavailable(error.to_string()))?;
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
            .map_err(|error| DidSdkError::ChainUnavailable(format!("invalid DID JSON: {error}")))
    }
}

#[async_trait]
impl Backend for CentralizedBackend {
    async fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError> {
        {
            let cache = self.dids.read().await;
            if let Some(entry) = cache.get(did) {
                if Self::fresh(entry, self.ttl_secs) {
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

    async fn get_anchor(&self, anchor_id: &str) -> Result<AnchorRecord, DidSdkError> {
        {
            let cache = self.anchors.read().await;
            if let Some(entry) = cache.get(anchor_id) {
                if Self::fresh(entry, self.ttl_secs) {
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
}
