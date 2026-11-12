//! 两种后端语义一致性测试。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

mod common;

use std::path::Path;

use did_sdk::{ClientConfig, DidSdkMode, build_client_sdk};
use secrecy::SecretString;

fn config(dir: &Path, mode: DidSdkMode, endpoint: &str) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.mode = mode;
    config.centralized_endpoint = endpoint.to_string();
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
