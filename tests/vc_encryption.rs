//! VC 静态加密测试（Client + Server）。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

use std::path::Path;

use did_sdk::{ClientConfig, DidSdkMode, ServerConfig, build_client_sdk, build_server_sdk};
use keyvault_core::crypto::blake2::blake2b256;
use secrecy::SecretString;

fn client_config(dir: &Path) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.mode = DidSdkMode::Mock;
    config.vc_storage_path = dir.join("client-vc");
    config.key_vault.scheme = "memory-keystore".into();
    config.resolved_password = Some(SecretString::from("test".to_string()));
    config
}

fn server_config(dir: &Path) -> ServerConfig {
    let mut config = ServerConfig::default();
    config.mode = DidSdkMode::Mock;
    config.participant_did = "did:web:issuer.example.com".into();
    config.vc_storage_path = dir.join("server-vc");
    config.key_vault = None;
    config
}

fn vc_file(dir: &Path, anchor_id: &str) -> std::path::PathBuf {
    dir.join("client-vc").join(format!(
        "{}.json",
        hex::encode(blake2b256(anchor_id.as_bytes()))
    ))
}

#[tokio::test]
async fn client_vc_is_stored_as_ciphertext_and_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let config = client_config(dir.path());
    let sdk = build_client_sdk(&config).unwrap();
    sdk.generate_did_key().unwrap();
    let vc = sdk
        .issue_self_asserted_vc(serde_json::json!({"name": "Alice", "email": "alice@example.com"}))
        .unwrap();
    let anchor_id = vc.anchor_id.clone().unwrap();
    sdk.store_vc(vc.clone()).await.unwrap();

    let bytes = std::fs::read(vc_file(dir.path(), &anchor_id)).unwrap();
    assert!(bytes.starts_with(b"DVCS"), "VC file must be encrypted");
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("Alice"));
    assert!(!text.contains("alice@example.com"));
    assert!(!text.contains(&vc.id));
    assert!(!text.contains("issuer"));

    // 重新打开（自动密码文件 + meta salt）仍可解密。
    let reopened = build_client_sdk(&config).unwrap();
    let loaded = reopened.get_vc(&anchor_id).await.unwrap().unwrap();
    assert_eq!(loaded.id, vc.id);
    assert_eq!(loaded.credential_subject["claims"]["name"], "Alice");
}

#[tokio::test]
async fn server_vc_is_stored_as_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let server = build_server_sdk(&server_config(dir.path())).unwrap();
    let vc = server
        .assemble_vc_with_proof(
            serde_json::json!({"credentialSubject": {"id": "did:key:zSubject"}}),
            "did:key:zSubject",
            did_sdk::Proof {
                type_: "Ed25519Signature2020".into(),
                created: 1,
                verification_method: "did:web:issuer.example.com#key-1".into(),
                jws: "zTest".into(),
            },
        )
        .unwrap();
    let anchor_id = vc.anchor_id.clone().unwrap();
    server.store_vc(vc).await.unwrap();

    let file = dir.path().join("server-vc").join(format!(
        "{}.json",
        hex::encode(blake2b256(anchor_id.as_bytes()))
    ));
    let bytes = std::fs::read(file).unwrap();
    assert!(bytes.starts_with(b"DVCS"));
    assert!(!String::from_utf8_lossy(&bytes).contains("issuer"));
}

#[tokio::test]
async fn client_vc_key_follows_keyvault_password() {
    let dir = tempfile::tempdir().unwrap();
    let config = client_config(dir.path());
    let sdk = build_client_sdk(&config).unwrap();
    sdk.generate_did_key().unwrap();
    let vc = sdk
        .issue_self_asserted_vc(serde_json::json!({"name": "Alice"}))
        .unwrap();
    let anchor_id = vc.anchor_id.clone().unwrap();
    sdk.store_vc(vc).await.unwrap();

    let mut wrong = config.clone();
    wrong.resolved_password = Some(SecretString::from("wrong-password".to_string()));
    let reopened = build_client_sdk(&wrong).unwrap();
    assert!(reopened.get_vc(&anchor_id).await.is_err());
}

#[test]
fn server_default_has_file_keyvault() {
    let config = ServerConfig::default();
    assert_eq!(
        config.key_vault.as_ref().map(|vault| vault.scheme.as_str()),
        Some("file-keystore")
    );
}
