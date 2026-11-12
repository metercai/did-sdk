//! Mock 后端：进程内 DID 状态与确认策略。

use std::collections::HashMap;
use std::time::Duration;

use async_lock::RwLock;
use async_trait::async_trait;

use crate::backend::Backend;
use crate::{DidRecord, DidSdkError};

/// 签名确认策略（仅 Client + Mock）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmPolicy {
    /// 自动确认。
    AutoConfirm,
    /// 自动拒绝。
    AutoReject,
    /// 延迟后确认。
    Delay(u64),
}

impl Default for ConfirmPolicy {
    fn default() -> Self {
        Self::AutoConfirm
    }
}

/// 进程内 Mock 后端。
#[derive(Default)]
pub struct MockBackend {
    dids: RwLock<HashMap<String, DidRecord>>,
    confirm: ConfirmPolicy,
}

impl MockBackend {
    /// 创建空 Mock 后端。
    pub fn new() -> Self {
        Self::default()
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

    /// 延迟确认。
    #[must_use]
    pub fn with_signing_delay(mut self, milliseconds: u64) -> Self {
        self.confirm = ConfirmPolicy::Delay(milliseconds);
        self
    }

    /// 预置 DID 记录（测试用）。
    pub async fn insert_did(&self, record: DidRecord) {
        self.dids.write().await.insert(record.did.clone(), record);
    }

    async fn check(&self) -> Result<(), DidSdkError> {
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
impl Backend for MockBackend {
    async fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError> {
        Ok(self.dids.read().await.get(did).cloned())
    }

    async fn confirm_signing(&self) -> Result<(), DidSdkError> {
        self.check().await
    }

    async fn confirm_vp(&self) -> Result<(), DidSdkError> {
        self.check().await
    }

    async fn confirm_authorization(&self) -> Result<(), DidSdkError> {
        self.check().await
    }
}
