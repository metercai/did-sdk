//! 三后端语义一致性测试。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use did_sdk::{
    AddressStatus, AnchorRecord, ClientConfig, DidSdkMode, MockBackend, build_client_sdk,
    build_client_sdk_with_backend,
};
use keyvault_core::MemoryKeystore;
use secrecy::SecretString;

fn config(dir: &Path, mode: DidSdkMode, endpoint: &str) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.mode = mode;
    config.centralized_endpoint = endpoint.to_string();
    config.chain_endpoint = endpoint.to_string();
    config.cache_ttl_secs = 600;
    config.vc_storage_path = dir.join("vc");
    config.key_vault.scheme = "memory-keystore".into();
    config.resolved_password = Some(SecretString::from("test".to_string()));
    config
}

#[tokio::test]
async fn mock_consistency() {
    let dir = tempfile::tempdir().unwrap();
    let sdk =
        build_client_sdk(&config(dir.path(), DidSdkMode::Mock, "http://127.0.0.1:9")).unwrap();
    common::assert_roundtrip(&sdk).await;
}

#[tokio::test]
async fn centralized_consistency_without_remote_calls() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk(&config(
        dir.path(),
        DidSdkMode::Centralized,
        "http://127.0.0.1:9",
    ))
    .unwrap();
    common::assert_roundtrip(&sdk).await;
}

#[tokio::test]
async fn chain_local_consistency_without_node() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk(&config(dir.path(), DidSdkMode::Chain, "ws://127.0.0.1:9")).unwrap();
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
    let backend = MockBackend::new()
        .with_preloaded_anchors(HashMap::from([("a1".to_string(), anchor.clone())]));
    let sdk = build_client_sdk_with_backend(
        &config(dir.path(), DidSdkMode::Mock, "http://127.0.0.1:9"),
        Arc::new(backend),
        Arc::new(MemoryKeystore::new()),
    )
    .unwrap();
    assert_eq!(sdk.get_anchor("a1").await.unwrap(), anchor);
    assert!(sdk.get_anchor("missing").await.is_err());
}

#[tokio::test]
async fn vc_anchor_mismatch_is_rejected() {
    use did_sdk::DidSdkError;
    use keyvault_core::crypto::blake2::blake2b256;

    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), DidSdkMode::Mock, "http://127.0.0.1:9");
    let vc_dir = config.vc_storage_path.clone();
    std::fs::create_dir_all(&vc_dir).unwrap();
    let anchor_id = "a1";
    let file = vc_dir.join(format!(
        "{}.json",
        hex::encode(blake2b256(anchor_id.as_bytes()))
    ));
    let vc = serde_json::json!({
        "id": "urn:test",
        "issuer": "did:key:z6MkTest",
        "anchor_id": "other",
        "context": [],
        "type": ["VerifiableCredential"],
        "issuanceDate": "1970-01-01T00:00:00Z",
        "credentialSubject": {}
    });
    std::fs::write(&file, serde_json::to_vec(&vc).unwrap()).unwrap();

    let sdk = build_client_sdk(&config).unwrap();
    assert!(matches!(
        sdk.get_vc(anchor_id).await.unwrap_err(),
        DidSdkError::InvalidArgument(_)
    ));
}

#[tokio::test]
#[ignore = "requires a live identity-chain node and DID_SDK_CHAIN_ENDPOINT"]
async fn chain_anchor_integration() {
    let endpoint = std::env::var("DID_SDK_CHAIN_ENDPOINT")
        .expect("DID_SDK_CHAIN_ENDPOINT must be set for this ignored test");
    let anchor_id =
        std::env::var("DID_SDK_CHAIN_ANCHOR_ID").expect("DID_SDK_CHAIN_ANCHOR_ID must be set");
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk(&config(dir.path(), DidSdkMode::Chain, &endpoint)).unwrap();
    let anchor = sdk.get_anchor(&anchor_id).await.expect("anchor");
    assert_eq!(anchor.anchor_id, anchor_id);
}
