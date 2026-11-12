//! Centralized 只读 HTTP 契约测试（仅 DID 解析）。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

use std::path::Path;

use did_sdk::{ClientConfig, DidSdkError, DidSdkMode, build_client_sdk};
use secrecy::SecretString;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn config(dir: &Path, endpoint: String) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.mode = DidSdkMode::Centralized;
    config.centralized_endpoint = endpoint;
    config.cache_ttl_secs = 600;
    config.vc_storage_path = dir.join("vc");
    config.key_vault.scheme = "memory-keystore".into();
    config.resolved_password = Some(SecretString::from("test".to_string()));
    config
}

#[tokio::test]
async fn did_get_and_cache_hit() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let did = "did:web:example.com";
    let record = json!({
        "did": did,
        "method": "web",
        "doc_hash": null,
        "owner": null,
        "block_number": null
    });
    Mock::given(method("GET"))
        .and(path(format!("/dids/{did}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(record))
        .mount(&server)
        .await;

    let sdk = build_client_sdk(&config(dir.path(), server.uri())).unwrap();
    let first = sdk.resolve_did(did).unwrap().unwrap();
    assert_eq!(first.did, did);
    let second = sdk.resolve_did(did).unwrap().unwrap();
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
    let sdk = build_client_sdk(&config(dir.path(), server.uri())).unwrap();
    assert!(
        sdk.resolve_did("did:web:missing.example.com")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn server_error_maps_to_backend_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/dids/did:web:err.example.com"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let sdk = build_client_sdk(&config(dir.path(), server.uri())).unwrap();
    assert!(matches!(
        sdk.resolve_did("did:web:err.example.com").unwrap_err(),
        DidSdkError::BackendUnavailable(_)
    ));
}

#[tokio::test]
async fn zero_ttl_disables_cache() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let did = "did:web:example.com";
    let record = json!({
        "did": did,
        "method": "web",
        "doc_hash": null,
        "owner": null,
        "block_number": null
    });
    Mock::given(method("GET"))
        .and(path(format!("/dids/{did}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(record))
        .mount(&server)
        .await;

    let mut cfg = config(dir.path(), server.uri());
    cfg.cache_ttl_secs = 0;
    let sdk = build_client_sdk(&cfg).unwrap();
    sdk.resolve_did(did).unwrap();
    sdk.resolve_did(did).unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn local_writes_never_use_remote() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let sdk = build_client_sdk(&config(dir.path(), server.uri())).unwrap();

    let record = sdk.create_did().unwrap();
    assert!(record.did.starts_with("did:key:z"));
    let vc = sdk
        .issue_self_asserted_vc(json!({"name": "alice"}))
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
