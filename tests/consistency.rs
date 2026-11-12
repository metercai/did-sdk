//! 三模式语义一致性测试。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

mod common;

use std::path::Path;
use std::sync::Arc;

use did_sdk::{
    AddressStatus, AnchorRecord, CentralizedDidSdk, ChainModeDidSdk, DidSdk, DidSdkConfig,
    DidSdkMode, MockDidSdk,
};
use keyvault_core::MemoryKeystore;

fn config(dir: &Path, mode: DidSdkMode, endpoint: &str) -> DidSdkConfig {
    let mut config = DidSdkConfig::default();
    config.mode = mode;
    config.centralized_endpoint = endpoint.to_string();
    config.chain_endpoint = endpoint.to_string();
    config.cache_ttl_secs = 600;
    config.vc_storage_path = dir.join("vc");
    config.key_vault.scheme = "memory-keystore".into();
    config
}

#[tokio::test]
async fn mock_consistency() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = MockDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), DidSdkMode::Mock, "http://127.0.0.1:9"),
    )
    .unwrap();
    common::assert_roundtrip(&sdk).await;
}

#[tokio::test]
async fn centralized_consistency_without_remote_calls() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = CentralizedDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), DidSdkMode::Centralized, "http://127.0.0.1:9"),
    )
    .unwrap();
    common::assert_roundtrip(&sdk).await;
}

#[tokio::test]
async fn chain_local_consistency_without_node() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = ChainModeDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), DidSdkMode::Chain, "ws://127.0.0.1:9"),
    )
    .unwrap();
    common::assert_roundtrip(&sdk).await;
}

#[tokio::test]
async fn mock_preloaded_anchor() {
    let dir = tempfile::tempdir().unwrap();
    let anchor = AnchorRecord {
        anchor_id: "a1".into(),
        did: "did:key:z6MkTest".into(),
        status: AddressStatus::Active,
        created_at: 1,
        updated_at: 2,
        expires_at: None,
        payload: serde_json::json!({"kind": "test"}),
    };
    let sdk = MockDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), DidSdkMode::Mock, "http://127.0.0.1:9"),
    )
    .unwrap()
    .with_preloaded_anchors(vec![anchor.clone()]);
    assert_eq!(sdk.get_anchor("a1").await.unwrap(), anchor);
    assert!(sdk.get_anchor("missing").await.is_err());
}

#[tokio::test]
#[ignore = "requires a live identity-chain node and DID_SDK_CHAIN_ENDPOINT"]
async fn chain_anchor_integration() {
    let endpoint = std::env::var("DID_SDK_CHAIN_ENDPOINT")
        .expect("DID_SDK_CHAIN_ENDPOINT must be set for this ignored test");
    let anchor_id =
        std::env::var("DID_SDK_CHAIN_ANCHOR_ID").expect("DID_SDK_CHAIN_ANCHOR_ID must be set");
    let dir = tempfile::tempdir().unwrap();
    let sdk = ChainModeDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), DidSdkMode::Chain, &endpoint),
    )
    .unwrap();
    let anchor = sdk.get_anchor(&anchor_id).await.expect("anchor");
    assert_eq!(anchor.anchor_id, anchor_id);
}
