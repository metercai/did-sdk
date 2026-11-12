//! Chain 后端：Substrate 只读 storage，不注入链账户签名者。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_lock::{Mutex, RwLock};
use async_trait::async_trait;
use scale_value::ValueDef;
use subxt::dynamic::{At, Value};
use subxt::{OnlineClient, PolkadotConfig};

use crate::backend::Backend;
use crate::{AddressStatus, AnchorRecord, DidMethod, DidRecord, DidSdkError};

#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    inserted: Instant,
}

/// Chain 后端。
pub struct ChainBackend {
    endpoint: String,
    client: Mutex<Option<OnlineClient<PolkadotConfig>>>,
    ttl_secs: u64,
    anchors: RwLock<HashMap<String, CacheEntry<AnchorRecord>>>,
    dids: RwLock<HashMap<String, CacheEntry<DidRecord>>>,
}

impl ChainBackend {
    /// 构造后端；不会立即连接节点。
    pub fn new(endpoint: String, ttl_secs: u64) -> Self {
        Self {
            endpoint,
            client: Mutex::new(None),
            ttl_secs,
            anchors: RwLock::new(HashMap::new()),
            dids: RwLock::new(HashMap::new()),
        }
    }

    async fn online_client(&self) -> Result<OnlineClient<PolkadotConfig>, DidSdkError> {
        let mut guard = self.client.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }
        let client = OnlineClient::<PolkadotConfig>::from_url(&self.endpoint)
            .await
            .map_err(|error| {
                DidSdkError::ChainUnavailable(format!("connect {}: {error}", self.endpoint))
            })?;
        *guard = Some(client.clone());
        Ok(client)
    }

    fn fresh<T>(entry: &CacheEntry<T>, ttl_secs: u64) -> bool {
        entry.inserted.elapsed() < Duration::from_secs(ttl_secs)
    }

    fn pallet() -> String {
        std::env::var("DID_SDK_CHAIN_PALLET").unwrap_or_else(|_| "Identity".into())
    }

    fn anchor_storage() -> String {
        std::env::var("DID_SDK_CHAIN_ANCHOR_STORAGE").unwrap_or_else(|_| "Anchors".into())
    }

    fn did_storage() -> String {
        std::env::var("DID_SDK_CHAIN_DID_STORAGE").unwrap_or_else(|_| "Dids".into())
    }

    async fn fetch_anchor(&self, anchor_id: &str) -> Result<AnchorRecord, DidSdkError> {
        let client = self.online_client().await?;
        let at = client
            .at_current_block()
            .await
            .map_err(|error| DidSdkError::ChainUnavailable(error.to_string()))?;
        let pallet = Self::pallet();
        let entry = Self::anchor_storage();
        let value = if let Some(key) = decode_hex32(anchor_id) {
            let address = subxt::dynamic::storage::<([u8; 32],), Value>(&pallet, &entry);
            at.storage()
                .try_fetch(address, (key,))
                .await
                .map_err(|error| DidSdkError::ChainUnavailable(error.to_string()))?
        } else {
            let address = subxt::dynamic::storage::<(String,), Value>(&pallet, &entry);
            at.storage()
                .try_fetch(address, (anchor_id.to_string(),))
                .await
                .map_err(|error| DidSdkError::ChainUnavailable(error.to_string()))?
        };
        let value = value.ok_or_else(|| DidSdkError::AnchorNotFound(anchor_id.to_string()))?;
        let value = value
            .decode()
            .map_err(|error| DidSdkError::ChainUnavailable(format!("decode anchor: {error}")))?;
        Ok(value_to_anchor(&value, anchor_id))
    }

    async fn fetch_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError> {
        let client = self.online_client().await?;
        let at = client
            .at_current_block()
            .await
            .map_err(|error| DidSdkError::ChainUnavailable(error.to_string()))?;
        let pallet = Self::pallet();
        let entry = Self::did_storage();
        let address = subxt::dynamic::storage::<(String,), Value>(&pallet, &entry);
        let Some(value) = at
            .storage()
            .try_fetch(address, (did.to_string(),))
            .await
            .map_err(|error| DidSdkError::ChainUnavailable(error.to_string()))?
        else {
            return Ok(None);
        };
        let value = value
            .decode()
            .map_err(|error| DidSdkError::ChainUnavailable(format!("decode DID: {error}")))?;
        Ok(Some(value_to_did(&value, did)))
    }
}

#[async_trait]
impl Backend for ChainBackend {
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

fn decode_hex32(value: &str) -> Option<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return None;
    }
    let bytes = hex::decode(value).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn status_from_value(value: &Value) -> AddressStatus {
    match value.at("status") {
        Some(Value {
            value: ValueDef::Variant(variant),
            ..
        }) => match variant.name.as_str() {
            "Revoked" => AddressStatus::Revoked,
            "Expired" => AddressStatus::Expired,
            "Pending" => AddressStatus::Pending,
            _ => AddressStatus::Active,
        },
        _ => AddressStatus::Active,
    }
}

fn timestamp_at(value: &Value, field: &str) -> Option<u64> {
    value
        .at(field)
        .and_then(|item| item.as_u128())
        .map(|number| number as u64)
}

fn string_at(value: &Value, field: &str) -> Option<String> {
    value
        .at(field)
        .and_then(|item| item.as_str())
        .map(str::to_string)
}

fn method_from_value(value: &Value) -> DidMethod {
    match string_at(value, "method").as_deref() {
        Some("peer") => DidMethod::Peer,
        Some("web") => DidMethod::Web,
        _ => DidMethod::Key,
    }
}

fn value_to_anchor(value: &Value, fallback_id: &str) -> AnchorRecord {
    AnchorRecord {
        anchor_id: string_at(value, "anchor_id").unwrap_or_else(|| fallback_id.to_string()),
        did: string_at(value, "did").unwrap_or_default(),
        status: status_from_value(value),
        created_at: timestamp_at(value, "created_at").unwrap_or(0),
        updated_at: timestamp_at(value, "updated_at").unwrap_or(0),
        expires_at: timestamp_at(value, "expires_at"),
        payload: serde_json::Value::Null,
    }
}

fn value_to_did(value: &Value, fallback_did: &str) -> DidRecord {
    DidRecord {
        did: string_at(value, "did").unwrap_or_else(|| fallback_did.to_string()),
        method: method_from_value(value),
        doc_hash: string_at(value, "doc_hash"),
        owner: string_at(value, "owner"),
        block_number: timestamp_at(value, "block_number"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn decodes_32_byte_hex() {
        let value = "11".repeat(32);
        assert_eq!(decode_hex32(&value), Some([0x11; 32]));
        assert_eq!(decode_hex32("0x1234"), None);
    }

    #[test]
    fn maps_anchor_fields() {
        let value = Value::named_composite([
            ("did", Value::string("did:key:z")),
            ("created_at", Value::u128(7)),
        ]);
        let anchor = value_to_anchor(&value, "a1");
        assert_eq!(anchor.anchor_id, "a1");
        assert_eq!(anchor.did, "did:key:z");
        assert_eq!(anchor.created_at, 7);
    }
}
