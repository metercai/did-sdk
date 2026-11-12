//! Centralized 只读 HTTP 契约测试：只允许 GET /anchors/{id} 与 GET /dids/{did}。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

use std::path::Path;
use std::sync::Arc;

use did_sdk::{AddressStatus, CentralizedDidSdk, DidSdk, DidSdkConfig, DidSdkError};
use keyvault_core::MemoryKeystore;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(dir: &Path, endpoint: String) -> DidSdkConfig {
    let mut config = DidSdkConfig::default();
    config.mode = did_sdk::DidSdkMode::Centralized;
    config.centralized_endpoint = endpoint;
    config.cache_ttl_secs = 600;
    config.vc_storage_path = dir.join("vc");
    config.key_vault.scheme = "memory-keystore".into();
    config
}

#[tokio::test]
async fn anchor_get_and_cache_hit() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let anchor = json!({
        "anchor_id": "a1",
        "did": "did:key:z6MkTest",
        "status": "active",
        "created_at": 1,
        "updated_at": 2,
        "expires_at": null,
        "payload": {"source": "wiremock"}
    });
    Mock::given(method("GET"))
        .and(path("/anchors/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(anchor))
        .mount(&server)
        .await;

    let sdk = CentralizedDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), server.uri()),
    )
    .unwrap();

    let first = sdk.get_anchor("a1").await.unwrap();
    assert_eq!(first.anchor_id, "a1");
    assert_eq!(first.did, "did:key:z6MkTest");
    assert_eq!(first.status, AddressStatus::Active);
    assert_eq!(first.payload["source"], "wiremock");

    // 第二次必须命中缓存，不再发请求。
    let second = sdk.get_anchor("a1").await.unwrap();
    assert_eq!(second, first);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
}

#[tokio::test]
async fn anchor_404_maps_to_anchor_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let sdk = CentralizedDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), server.uri()),
    )
    .unwrap();
    let error = sdk.get_anchor("missing").await.unwrap_err();
    assert!(matches!(error, DidSdkError::AnchorNotFound(id) if id == "missing"));
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
}

#[tokio::test]
async fn did_get_and_cache_hit() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let did = "did:key:z6MkTest";
    let record = did_sdk::DidRecord {
        did: did.to_string(),
        public_key: did_sdk::Ed25519PublicKey([7u8; 32]),
        created_at: 1,
        updated_at: 2,
        anchor_id: None,
        status: AddressStatus::Active,
    };
    let record = serde_json::to_value(&record).unwrap();
    Mock::given(method("GET"))
        .and(path(format!("/dids/{did}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(record))
        .mount(&server)
        .await;

    let sdk = CentralizedDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), server.uri()),
    )
    .unwrap();
    let first = sdk.resolve_did(did).await.unwrap().unwrap();
    assert_eq!(first.did, did);
    assert_eq!(first.public_key.0, [7u8; 32]);
    let second = sdk.resolve_did(did).await.unwrap().unwrap();
    assert_eq!(second, first);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
}

#[tokio::test]
async fn did_404_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let sdk = CentralizedDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), server.uri()),
    )
    .unwrap();
    assert!(sdk.resolve_did("did:key:zMissing").await.unwrap().is_none());
}

#[tokio::test]
async fn local_writes_never_use_remote() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let sdk = CentralizedDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), server.uri()),
    )
    .unwrap();

    let record = sdk.create_did().await.unwrap();
    assert!(record.did.starts_with("did:key:z"));
    let vc = sdk
        .issue_self_asserted_vc(json!({"name": "alice"}))
        .await
        .unwrap();
    sdk.store_vc(vc.clone()).await.unwrap();
    sdk.remove_vc(vc.anchor_id.as_deref().unwrap())
        .await
        .unwrap();
    sdk.sign_issue_authorization(&record.did, "SelfAssertedCredential", "hash", 1)
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert!(requests.is_empty(), "local operations must not hit HTTP");
}

#[tokio::test]
async fn server_error_maps_to_chain_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/anchors/err"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let sdk = CentralizedDidSdk::new(
        Arc::new(MemoryKeystore::new()),
        config(dir.path(), server.uri()),
    )
    .unwrap();
    assert!(matches!(
        sdk.get_anchor("err").await.unwrap_err(),
        DidSdkError::ChainUnavailable(_)
    ));
}

#[tokio::test]
async fn zero_ttl_disables_cache() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let anchor = json!({
        "anchor_id": "a1",
        "did": "did:key:z6MkTest",
        "status": "active",
        "created_at": 1,
        "updated_at": 2,
        "expires_at": null,
        "payload": null
    });
    Mock::given(method("GET"))
        .and(path("/anchors/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(anchor))
        .mount(&server)
        .await;

    let mut cfg = config(dir.path(), server.uri());
    cfg.cache_ttl_secs = 0;
    let sdk = CentralizedDidSdk::new(Arc::new(MemoryKeystore::new()), cfg).unwrap();
    sdk.get_anchor("a1").await.unwrap();
    sdk.get_anchor("a1").await.unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}
