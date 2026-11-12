//! Mock 模式：进程内 anchor / DID 状态，可配置确认策略。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_lock::RwLock;
use async_trait::async_trait;
use keyvault_core::KeyVault;

use crate::core::{SdkCore, map_vault_err};
use crate::did_signature;
use crate::server_request::ServerRequestHandler;
use crate::types::{
    AnchorRecord, DidRecord, Ed25519PublicKey, IssueAuthorizationSignature, Signature,
    SigningContext, VerifiableCredential, VerifiablePresentation, VerifyResult,
};
use crate::vc;
use crate::{DidSdk, DidSdkConfig, DidSdkError};

/// 签名确认策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmPolicy {
    /// 自动确认（默认）。
    AutoConfirm,
    /// 自动拒绝，返回 `DidSdkError::UserRejected`。
    AutoReject,
    /// 延迟指定毫秒后确认。
    Delay(u64),
}

/// 进程内 Mock 实现。
pub struct MockDidSdk {
    pub(crate) core: SdkCore,
    anchors: RwLock<HashMap<String, AnchorRecord>>,
    dids: RwLock<HashMap<String, DidRecord>>,
    confirm: ConfirmPolicy,
}

impl MockDidSdk {
    /// 构造 Mock SDK。
    pub fn new(vault: Arc<dyn KeyVault>, config: DidSdkConfig) -> Result<Self, DidSdkError> {
        Ok(Self {
            core: SdkCore::new(vault, config)?,
            anchors: RwLock::new(HashMap::new()),
            dids: RwLock::new(HashMap::new()),
            confirm: ConfirmPolicy::AutoConfirm,
        })
    }

    /// 预置 anchor。
    #[must_use]
    pub fn with_preloaded_anchors(mut self, anchors: Vec<AnchorRecord>) -> Self {
        let map = anchors
            .into_iter()
            .map(|anchor| (anchor.anchor_id.clone(), anchor))
            .collect();
        self.anchors = RwLock::new(map);
        self
    }

    /// 自动确认（默认）。
    #[must_use]
    pub fn with_auto_confirm(mut self) -> Self {
        self.confirm = ConfirmPolicy::AutoConfirm;
        self
    }

    /// 自动拒绝。
    #[must_use]
    pub fn with_auto_reject(mut self) -> Self {
        self.confirm = ConfirmPolicy::AutoReject;
        self
    }

    /// 延迟指定毫秒后确认。
    #[must_use]
    pub fn with_signing_delay(mut self, milliseconds: u64) -> Self {
        self.confirm = ConfirmPolicy::Delay(milliseconds);
        self
    }
}

impl MockDidSdk {
    async fn check_confirm_policy(&self) -> Result<(), DidSdkError> {
        match self.confirm {
            ConfirmPolicy::AutoReject => Err(DidSdkError::UserRejected),
            ConfirmPolicy::Delay(milliseconds) => {
                tokio::time::sleep(Duration::from_millis(milliseconds)).await;
                Ok(())
            }
            ConfirmPolicy::AutoConfirm => Ok(()),
        }
    }
}

#[async_trait]
impl DidSdk for MockDidSdk {
    async fn generate_did_key(&self) -> Result<String, DidSdkError> {
        self.core.generate_did_key().await
    }

    async fn sign_with_did_key(
        &self,
        message: &[u8],
        ctx: SigningContext,
    ) -> Result<Signature, DidSdkError> {
        tracing::debug!(purpose = %ctx.purpose, "mock signing request");
        self.check_confirm_policy().await?;
        self.core.sign_with_active(message).await
    }

    fn resolve_did_key(&self, did: &str) -> Result<Ed25519PublicKey, DidSdkError> {
        keyvault_core::crypto::decode_did_key_pubkey(did)
            .map(Ed25519PublicKey)
            .map_err(map_vault_err)
    }

    async fn create_did(&self) -> Result<DidRecord, DidSdkError> {
        let record = self.core.create_did_record().await?;
        self.dids
            .write()
            .await
            .insert(record.did.clone(), record.clone());
        Ok(record)
    }

    async fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError> {
        Ok(self.dids.read().await.get(did).cloned())
    }

    async fn issue_self_asserted_vc(
        &self,
        claims: serde_json::Value,
    ) -> Result<VerifiableCredential, DidSdkError> {
        self.check_confirm_policy().await?;
        vc::issue_self_asserted_vc(&self.core, claims).await
    }

    async fn store_vc(&self, vc: VerifiableCredential) -> Result<(), DidSdkError> {
        self.core.vcs.put(&vc)
    }

    async fn get_vc(&self, anchor_id: &str) -> Result<Option<VerifiableCredential>, DidSdkError> {
        self.core.vcs.get(anchor_id)
    }

    async fn list_vcs(&self) -> Result<Vec<VerifiableCredential>, DidSdkError> {
        self.core.vcs.list()
    }

    async fn remove_vc(&self, anchor_id: &str) -> Result<(), DidSdkError> {
        self.core.vcs.remove(anchor_id)
    }

    async fn build_vp(
        &self,
        vcs: Vec<VerifiableCredential>,
        challenge: &str,
        domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError> {
        self.check_confirm_policy().await?;
        vc::build_vp(&self.core, vcs, challenge, domain).await
    }

    async fn build_did_signature_header(
        &self,
        from: &str,
        anchor_id: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> Result<String, DidSdkError> {
        self.check_confirm_policy().await?;
        did_signature::build_header(&self.core, from, anchor_id, body_hash, rcpt_hash).await
    }

    fn verify_did_signature_header(
        &self,
        header: &str,
        from: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> Result<VerifyResult, DidSdkError> {
        did_signature::verify_header(&self.core, header, from, body_hash, rcpt_hash)
    }

    async fn sign_issue_authorization(
        &self,
        subject_did: &str,
        vc_type: &str,
        vc_hash: &str,
        timestamp: u64,
    ) -> Result<IssueAuthorizationSignature, DidSdkError> {
        self.check_confirm_policy().await?;
        vc::sign_issue_authorization(&self.core, subject_did, vc_type, vc_hash, timestamp).await
    }

    async fn get_anchor(&self, anchor_id: &str) -> Result<AnchorRecord, DidSdkError> {
        self.anchors
            .read()
            .await
            .get(anchor_id)
            .cloned()
            .ok_or_else(|| DidSdkError::AnchorNotFound(anchor_id.to_string()))
    }

    fn set_request_handler(&self, handler: Arc<dyn ServerRequestHandler>) {
        self.core.set_handler(handler);
    }
}
