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
    AuthorizationRequestContext, ChallengeContext, ServerRequestHandler, VpRequestContext,
};
use did_sdk::{DidSdk, DidSdkConfig, DidSdkError, MockDidSdk, SigningContext};
use keyvault_core::{KeyId, KeyVault, KeyVaultError, MemoryKeystore, PublicKey, Signature};

fn config(dir: &Path) -> DidSdkConfig {
    let mut config = DidSdkConfig::default();
    config.vc_storage_path = dir.join("vc");
    config.key_vault.scheme = "memory-keystore".into();
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
    async fn generate(&self) -> Result<KeyId, KeyVaultError> {
        self.inner.generate().await
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

    async fn list_keys(&self) -> Result<Vec<KeyId>, KeyVaultError> {
        self.inner.list_keys().await
    }

    async fn delete(&self, key_id: &KeyId) -> Result<(), KeyVaultError> {
        self.inner.delete(key_id).await
    }
}

struct RejectingHandler;

#[async_trait]
impl ServerRequestHandler for RejectingHandler {
    async fn on_challenge(&self, _ctx: &ChallengeContext) -> Result<(), DidSdkError> {
        Err(DidSdkError::UserRejected)
    }

    async fn on_vp_request(&self, _ctx: &VpRequestContext) -> Result<(), DidSdkError> {
        Err(DidSdkError::UserRejected)
    }

    async fn on_authorization_request(
        &self,
        _ctx: &AuthorizationRequestContext,
    ) -> Result<(), DidSdkError> {
        Err(DidSdkError::UserRejected)
    }
}

#[tokio::test]
async fn mock_auto_reject_returns_user_rejected_before_signing() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = MockDidSdk::new(Arc::new(MemoryKeystore::new()), config(dir.path()))
        .unwrap()
        .with_auto_reject();
    sdk.generate_did_key().await.unwrap();
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
    let sdk = MockDidSdk::new(Arc::new(RejectingVault::new()), config(dir.path())).unwrap();
    sdk.generate_did_key().await.unwrap();
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
    let sdk = MockDidSdk::new(Arc::new(MemoryKeystore::new()), config(dir.path())).unwrap();
    sdk.set_request_handler(Arc::new(RejectingHandler));
    let error = sdk
        .build_did_signature_header("alice@example.com", "anchor:abc", "body", "rcpt")
        .await
        .unwrap_err();
    assert!(matches!(error, DidSdkError::UserRejected));
}

#[tokio::test]
async fn signing_delay_still_confirms() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = MockDidSdk::new(Arc::new(MemoryKeystore::new()), config(dir.path()))
        .unwrap()
        .with_signing_delay(1);
    sdk.generate_did_key().await.unwrap();
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
