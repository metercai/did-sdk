//! Chain 模式：Substrate 只读 storage，不注入链账户签名者。
//!
//! POC 不提交某个具体链的 `.scale` 元数据；连接节点后使用运行时元数据做动态
//! storage 查询。pallet / 存储项名称可通过环境变量覆盖：
//! `DID_SDK_CHAIN_PALLET`、`DID_SDK_CHAIN_ANCHOR_STORAGE`、`DID_SDK_CHAIN_DID_STORAGE`。
//!
//! 真实链集成测试标记为 `#[ignore]`，需要 `DID_SDK_CHAIN_ENDPOINT` 与匹配的链。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_lock::{Mutex, RwLock};
use async_trait::async_trait;
use keyvault_core::KeyVault;
use scale_value::{Composite, ValueDef};
use subxt::dynamic::{At, Value};
use subxt::{OnlineClient, PolkadotConfig};

use crate::core::{SdkCore, map_vault_err};
use crate::did_signature;
use crate::server_request::ServerRequestHandler;
use crate::types::{
    AddressStatus, AnchorRecord, DidRecord, Ed25519PublicKey, IssueAuthorizationSignature,
    Signature, SigningContext, VerifiableCredential, VerifiablePresentation, VerifyResult,
};
use crate::vc;
use crate::{DidSdk, DidSdkConfig, DidSdkError};

#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    inserted: Instant,
}

/// Chain 只读实现。
pub struct ChainModeDidSdk {
    pub(crate) core: SdkCore,
    endpoint: String,
    client: Mutex<Option<OnlineClient<PolkadotConfig>>>,
    anchors: RwLock<HashMap<String, CacheEntry<AnchorRecord>>>,
    dids: RwLock<HashMap<String, CacheEntry<DidRecord>>>,
}

impl ChainModeDidSdk {
    /// 构造 Chain SDK。不会立即连接节点，首次查询时懒连接。
    pub fn new(vault: Arc<dyn KeyVault>, config: DidSdkConfig) -> Result<Self, DidSdkError> {
        let endpoint = config.chain_endpoint.clone();
        Ok(Self {
            core: SdkCore::new(vault, config)?,
            endpoint,
            client: Mutex::new(None),
            anchors: RwLock::new(HashMap::new()),
            dids: RwLock::new(HashMap::new()),
        })
    }

    async fn online_client(&self) -> Result<OnlineClient<PolkadotConfig>, DidSdkError> {
        let mut guard = self.client.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }
        let client = OnlineClient::<PolkadotConfig>::from_url(&self.endpoint)
            .await
            .map_err(|e| {
                DidSdkError::ChainUnavailable(format!("connect {}: {e}", self.endpoint))
            })?;
        *guard = Some(client.clone());
        Ok(client)
    }

    fn cache_is_fresh<T>(entry: &CacheEntry<T>, ttl_secs: u64) -> bool {
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
            .map_err(|e| DidSdkError::ChainUnavailable(e.to_string()))?;
        let pallet = Self::pallet();
        let entry = Self::anchor_storage();

        let value = if let Some(key) = decode_hex32(anchor_id) {
            let address = subxt::dynamic::storage::<([u8; 32],), Value>(&pallet, &entry);
            at.storage()
                .try_fetch(address, (key,))
                .await
                .map_err(|e| DidSdkError::ChainUnavailable(e.to_string()))?
        } else {
            let address = subxt::dynamic::storage::<(String,), Value>(&pallet, &entry);
            at.storage()
                .try_fetch(address, (anchor_id.to_string(),))
                .await
                .map_err(|e| DidSdkError::ChainUnavailable(e.to_string()))?
        };
        let value = value.ok_or_else(|| DidSdkError::AnchorNotFound(anchor_id.to_string()))?;
        let value = value
            .decode()
            .map_err(|e| DidSdkError::ChainUnavailable(format!("decode anchor: {e}")))?;
        Ok(value_to_anchor(&value, anchor_id))
    }

    async fn fetch_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError> {
        let client = self.online_client().await?;
        let at = client
            .at_current_block()
            .await
            .map_err(|e| DidSdkError::ChainUnavailable(e.to_string()))?;
        let pallet = Self::pallet();
        let entry = Self::did_storage();
        let address = subxt::dynamic::storage::<(String,), Value>(&pallet, &entry);
        let Some(value) = at
            .storage()
            .try_fetch(address, (did.to_string(),))
            .await
            .map_err(|e| DidSdkError::ChainUnavailable(e.to_string()))?
        else {
            return Ok(None);
        };
        let value = value
            .decode()
            .map_err(|e| DidSdkError::ChainUnavailable(format!("decode DID: {e}")))?;
        Ok(Some(value_to_did(&value, did)?))
    }
}

#[async_trait]
impl DidSdk for ChainModeDidSdk {
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

fn bytes32_at(value: &Value, field: &str) -> Option<[u8; 32]> {
    let item = value.at(field)?;
    let ValueDef::Composite(Composite::Unnamed(values)) = &item.value else {
        return None;
    };
    if values.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, value) in values.iter().enumerate() {
        let byte = u8::try_from(value.as_u128()?).ok()?;
        out[index] = byte;
    }
    Some(out)
}

fn value_to_did(value: &Value, fallback_did: &str) -> Result<DidRecord, DidSdkError> {
    let did = string_at(value, "did").unwrap_or_else(|| fallback_did.to_string());
    let public_key = bytes32_at(value, "public_key").ok_or_else(|| {
        DidSdkError::InvalidArgument(
            "chain DID record has no decodable public_key (need [u8; 32])".into(),
        )
    })?;
    let created_at = timestamp_at(value, "created_at").unwrap_or(0);
    Ok(DidRecord {
        did,
        public_key: Ed25519PublicKey(public_key),
        created_at,
        updated_at: timestamp_at(value, "updated_at").unwrap_or(created_at),
        anchor_id: string_at(value, "anchor_id"),
        status: status_from_value(value),
    })
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
