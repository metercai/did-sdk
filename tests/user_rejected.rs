//! `UserRejected` 三来源透传测试。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use did_sdk::server_request::{
    AuthorizationResponse, ServerRequestHandler, SignatureResponse, VpResponse,
};
use did_sdk::{
    ClientConfig, DidSdkError, MockBackend, SigningContext, build_client_sdk,
    build_client_sdk_with_backend,
};
use keyvault_core::{
    KeyAlgorithm, KeyId, KeyNamespace, KeyVault, KeyVaultError, MemoryKeystore, PublicKey,
    Signature,
};
use secrecy::SecretString;

fn config(dir: &Path) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.mode = did_sdk::DidSdkMode::Mock;
    config.vc_storage_path = dir.join("vc");
    config.key_vault.scheme = "memory-keystore".into();
    config.resolved_password = Some(SecretString::from("test".to_string()));
    config
}

struct RejectingVault {
    inner: MemoryKeystore,
}

impl RejectingVault {
    fn new() -> Self {
        Self {
            inner: MemoryKeystore::new(),
        }
    }
}

#[async_trait]
impl KeyVault for RejectingVault {
    async fn generate(
        &self,
        namespace: KeyNamespace,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyId, KeyVaultError> {
        self.inner.generate(namespace, algorithm).await
    }

    async fn load(&self, key_id: &KeyId) -> Result<(), KeyVaultError> {
        self.inner.load(key_id).await
    }

    async fn sign(&self, _key_id: &KeyId, _payload: &[u8]) -> Result<Signature, KeyVaultError> {
        Err(KeyVaultError::UserRejected)
    }

    async fn public_key(&self, key_id: &KeyId) -> Result<PublicKey, KeyVaultError> {
        self.inner.public_key(key_id).await
    }

    async fn list_keys(
        &self,
        namespace: Option<KeyNamespace>,
    ) -> Result<Vec<KeyId>, KeyVaultError> {
        self.inner.list_keys(namespace).await
    }

    async fn delete(&self, key_id: &KeyId) -> Result<(), KeyVaultError> {
        self.inner.delete(key_id).await
    }

    async fn sign_checked(
        &self,
        _key_id: &KeyId,
        _payload: &[u8],
        _expected_namespace: KeyNamespace,
        _expected_algorithm: KeyAlgorithm,
    ) -> Result<Signature, KeyVaultError> {
        Err(KeyVaultError::UserRejected)
    }
}

struct RejectingHandler;

#[async_trait]
impl ServerRequestHandler for RejectingHandler {
    async fn on_challenge(
        &self,
        _challenge: &str,
        _requestor: &str,
    ) -> Result<SignatureResponse, DidSdkError> {
        Ok(SignatureResponse {
            approved: false,
            reason: Some("rejected".into()),
        })
    }

    async fn on_vp_request(
        &self,
        _credential_types: &[String],
        _challenge: &str,
    ) -> Result<VpResponse, DidSdkError> {
        Ok(VpResponse {
            approved: false,
            reason: Some("rejected".into()),
        })
    }

    async fn on_authorization_request(
        &self,
        _fields: &[String],
        _purpose: &str,
        _requestor: &str,
    ) -> Result<AuthorizationResponse, DidSdkError> {
        Ok(AuthorizationResponse {
            approved: false,
            reason: Some("rejected".into()),
        })
    }
}

fn mock_with_policy(dir: &Path, backend: MockBackend) -> Arc<did_sdk::DidSdk<did_sdk::Client>> {
    build_client_sdk_with_backend(
        &config(dir),
        Arc::new(backend),
        Arc::new(MemoryKeystore::new()),
    )
    .unwrap()
}

#[tokio::test]
async fn mock_auto_reject_returns_user_rejected_before_signing() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = mock_with_policy(dir.path(), MockBackend::new().with_auto_reject());
    sdk.generate_did_key().unwrap();
    let error = sdk
        .sign_with_did_key(
            b"payload",
            SigningContext {
                purpose: "test".into(),
                payload_summary: "reject".into(),
                requestor: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, DidSdkError::UserRejected));
}

#[tokio::test]
async fn vault_user_rejected_maps_to_did_sdk_error() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk_with_backend(
        &config(dir.path()),
        Arc::new(MockBackend::new()),
        Arc::new(RejectingVault::new()),
    )
    .unwrap();
    sdk.generate_did_key().unwrap();
    let error = sdk
        .sign_with_did_key(
            b"payload",
            SigningContext {
                purpose: "test".into(),
                payload_summary: "vault reject".into(),
                requestor: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, DidSdkError::UserRejected));
}

#[tokio::test]
async fn handler_rejection_propagates() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk(&config(dir.path())).unwrap();
    sdk.set_request_handler(Arc::new(RejectingHandler));
    sdk.generate_did_key().unwrap();
    let error = sdk
        .build_did_signature_header("alice@example.com", "anchor:abc", "body", "rcpt")
        .await
        .unwrap_err();
    assert!(matches!(error, DidSdkError::UserRejected));
}

#[tokio::test]
async fn handler_rejection_propagates_for_vp_and_authorization() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = build_client_sdk(&config(dir.path())).unwrap();
    sdk.set_request_handler(Arc::new(RejectingHandler));
    let did = sdk.generate_did_key().unwrap();
    let error = sdk
        .sign_issue_authorization(&did, "TestCredential", "hash", 1)
        .await
        .unwrap_err();
    assert!(matches!(error, DidSdkError::UserRejected));

    let vc = did_sdk::VerifiableCredential {
        context: vec![],
        id: "urn:test".into(),
        types: vec!["VerifiableCredential".into()],
        issuer: did,
        issuance_date: String::new(),
        expiration_date: None,
        credential_subject: serde_json::json!({}),
        proof: None,
        anchor_id: Some("a".into()),
    };
    let error = sdk
        .build_vp(vec![vc], "challenge", "example.com")
        .await
        .unwrap_err();
    assert!(matches!(error, DidSdkError::UserRejected));
}

#[tokio::test]
async fn mock_auto_reject_blocks_all_signing_paths() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = mock_with_policy(dir.path(), MockBackend::new().with_auto_reject());
    let did = sdk.generate_did_key().unwrap();

    assert!(matches!(
        sdk.issue_self_asserted_vc(serde_json::json!({"name": "Alice"}))
            .unwrap_err(),
        DidSdkError::UserRejected
    ));
    assert!(matches!(
        sdk.build_did_signature_header("alice@example.com", "a", "b", "c")
            .await
            .unwrap_err(),
        DidSdkError::UserRejected
    ));
    assert!(matches!(
        sdk.sign_issue_authorization(&did, "T", "h", 1)
            .await
            .unwrap_err(),
        DidSdkError::UserRejected
    ));

    let vc = did_sdk::VerifiableCredential {
        context: vec![],
        id: "urn:test".into(),
        types: vec!["VerifiableCredential".into()],
        issuer: did,
        issuance_date: String::new(),
        expiration_date: None,
        credential_subject: serde_json::json!({}),
        proof: None,
        anchor_id: Some("a".into()),
    };
    assert!(matches!(
        sdk.build_vp(vec![vc], "c", "d").await.unwrap_err(),
        DidSdkError::UserRejected
    ));
}

#[tokio::test]
async fn signing_delay_still_confirms() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = mock_with_policy(dir.path(), MockBackend::new().with_signing_delay(1));
    sdk.generate_did_key().unwrap();
    let signature = sdk
        .sign_with_did_key(
            b"payload",
            SigningContext {
                purpose: "test".into(),
                payload_summary: "delay".into(),
                requestor: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(signature.0.len(), 64);
}
