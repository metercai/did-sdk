//! Centralized 只读 HTTP 契约测试。

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

    let sdk = build_client_sdk(&config(dir.path(), server.uri())).unwrap();
    let first = sdk.get_anchor("a1").await.unwrap();
    assert_eq!(first.anchor_id, "a1");
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
    let sdk = build_client_sdk(&config(dir.path(), server.uri())).unwrap();
    assert!(matches!(
        sdk.get_anchor("missing").await.unwrap_err(),
        DidSdkError::AnchorNotFound(_)
    ));
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
async fn server_error_maps_to_chain_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/anchors/err"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let sdk = build_client_sdk(&config(dir.path(), server.uri())).unwrap();
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
    let sdk = build_client_sdk(&cfg).unwrap();
    sdk.get_anchor("a1").await.unwrap();
    sdk.get_anchor("a1").await.unwrap();
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
