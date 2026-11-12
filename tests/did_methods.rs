//! 三种 DID 方法与 Server proof/verify 测试。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

use std::path::Path;

use did_sdk::{
    ClientConfig, DidMethod, DidSdkMode, PeerNumalgo, Proof, ServerConfig, build_client_sdk,
    build_server_sdk,
};
use secrecy::SecretString;

fn client_config(dir: &Path) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.mode = DidSdkMode::Mock;
    config.vc_storage_path = dir.join("vc");
    config.key_vault.scheme = "memory-keystore".into();
    config.resolved_password = Some(SecretString::from("test".to_string()));
    config
}

fn server_config(dir: &Path, participant_did: &str) -> ServerConfig {
    let mut config = ServerConfig::default();
    config.mode = DidSdkMode::Mock;
    config.participant_did = participant_did.to_string();
    config.vc_storage_path = dir.join("server-vc");
    config.key_vault = None;
    config
}

#[test]
fn did_key_generation_and_record() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk(&client_config(dir.path())).unwrap();
    let did = sdk.generate_did_key().unwrap();
    assert!(did.starts_with("did:key:z"));
    assert_eq!(
        sdk.resolve_did(&did).unwrap().unwrap().method,
        DidMethod::Key
    );
    let record = sdk.create_did().unwrap();
    assert_eq!(record.method, DidMethod::Key);
}

#[test]
fn did_peer_numalgos_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk(&client_config(dir.path())).unwrap();
    for numalgo in [PeerNumalgo::Zero, PeerNumalgo::One, PeerNumalgo::Two] {
        let did = sdk.generate_did_peer(numalgo).unwrap();
        assert!(did.starts_with("did:peer:"), "{did}");
        let document = sdk.resolve_did_peer(&did).unwrap();
        assert_eq!(document.id, did);
        assert_eq!(document.verification_method.len(), 1);
        assert!(
            document.verification_method[0]
                .public_key_multibase
                .as_deref()
                .unwrap()
                .starts_with('z')
        );
    }
}

#[test]
fn did_peer_one_document_is_cached_for_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk(&client_config(dir.path())).unwrap();
    let did = sdk.generate_did_peer(PeerNumalgo::One).unwrap();
    assert!(sdk.resolve_did_peer(&did).is_ok());
}

#[test]
fn server_assemble_vc_with_external_proof() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_server_sdk(&server_config(dir.path(), "did:web:issuer.example.com")).unwrap();
    let proof = Proof {
        type_: "Ed25519Signature2020".into(),
        created: 1,
        verification_method: "did:web:issuer.example.com#key-1".into(),
        jws: "zTest".into(),
    };
    let vc = sdk
        .assemble_vc_with_proof(
            serde_json::json!({"credentialSubject": {"id": "did:key:zSubject"}}),
            "did:key:zSubject",
            proof.clone(),
        )
        .unwrap();
    assert_eq!(vc.issuer, "did:web:issuer.example.com");
    assert_eq!(vc.proof, Some(proof));
    assert_eq!(
        vc.credential_subject["id"].as_str(),
        Some("did:key:zSubject")
    );
}

#[tokio::test]
async fn server_verifies_client_issued_vc() {
    let dir = tempfile::tempdir().unwrap();
    let client = build_client_sdk(&client_config(dir.path())).unwrap();
    client.generate_did_key().unwrap();
    let vc = client
        .issue_self_asserted_vc(serde_json::json!({"name": "Alice"}))
        .unwrap();
    let server =
        build_server_sdk(&server_config(dir.path(), "did:web:issuer.example.com")).unwrap();
    let result = server.verify_vc(&vc).await.unwrap();
    assert!(result.verified, "reason: {:?}", result.reason);
    assert!(result.issuer_resolved);
}

#[tokio::test]
async fn server_rejects_tampered_vc() {
    let dir = tempfile::tempdir().unwrap();
    let client = build_client_sdk(&client_config(dir.path())).unwrap();
    client.generate_did_key().unwrap();
    let mut vc = client
        .issue_self_asserted_vc(serde_json::json!({"name": "Alice"}))
        .unwrap();
    vc.credential_subject["name"] = serde_json::json!("Mallory");
    let server =
        build_server_sdk(&server_config(dir.path(), "did:web:issuer.example.com")).unwrap();
    let result = server.verify_vc(&vc).await.unwrap();
    assert!(!result.verified);
}

#[tokio::test]
async fn did_web_url_and_peer_key_helpers() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk(&client_config(dir.path())).unwrap();
    let did = sdk.generate_did_peer(PeerNumalgo::Zero).unwrap();
    let key = did_sdk::did::public_key_from_did(&did).unwrap();
    assert_eq!(key.len(), 32);
    assert_eq!(
        did_sdk::did::did_web_url("did:web:example.com:user:alice").unwrap(),
        "https://example.com/user/alice/did.json"
    );
    assert_eq!(
        did_sdk::did::did_web_url("did:web:example.com%3A8080").unwrap(),
        "https://example.com:8080/.well-known/did.json"
    );
}

#[tokio::test]
async fn did_peer_one_signature_header_verifies_offline() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk(&client_config(dir.path())).unwrap();
    sdk.generate_did_peer(PeerNumalgo::One).unwrap();
    let header = sdk
        .build_did_signature_header("alice@example.com", "anchor:abc", "body", "rcpt")
        .await
        .unwrap();
    let result = sdk
        .verify_did_signature_header(&header, "alice@example.com", "body", "rcpt")
        .unwrap();
    assert!(result.verified, "reason: {:?}", result.reason);
}

#[tokio::test]
async fn server_dev_file_signer_can_sign() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = server_config(dir.path(), "did:web:issuer.example.com");
    config.key_vault = Some(did_sdk::KeyVaultConfig {
        scheme: "memory-keystore".into(),
        path: dir.path().join("server-keys"),
        password_env: "DID_SDK_KEYVAULT_PASSWORD".into(),
        password_file: dir.path().join("server.password"),
        allow_auto_generate_password: true,
        password_prompt: false,
    });
    config.resolved_password = Some(SecretString::from("test".to_string()));
    let server = build_server_sdk(&config).unwrap();
    assert!(server.has_signer());

    let signature = server
        .sign_with_participant_key(
            b"server payload",
            did_sdk::SigningContext {
                purpose: "dev".into(),
                payload_summary: "test".into(),
                requestor: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(signature.0.len(), 64);

    let vc = server
        .issue_self_asserted_vc(serde_json::json!({"name": "Alice"}))
        .unwrap();
    assert_eq!(vc.issuer, "did:web:issuer.example.com");
    assert!(vc.proof.is_some());
}
