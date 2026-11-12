//! 三种后端（Mock / Centralized / Chain）的统一只读接口。

use async_trait::async_trait;

use crate::{AnchorRecord, DidRecord, DidSdkError};

/// 后端只读能力。三种后端只实现该 trait，不感知 Client/Server 模式。
#[async_trait]
pub trait Backend: Send + Sync {
    /// 解析 DID。
    async fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError>;

    /// 查询 anchor。
    async fn get_anchor(&self, anchor_id: &str) -> Result<AnchorRecord, DidSdkError>;

    /// Mock 专用：签名前确认策略。默认无策略（直接允许）。
    async fn confirm_signing(&self) -> Result<(), DidSdkError> {
        Ok(())
    }

    /// Mock 专用：VP 出示前确认策略。
    async fn confirm_vp(&self) -> Result<(), DidSdkError> {
        Ok(())
    }

    /// Mock 专用：授权签名前确认策略。
    async fn confirm_authorization(&self) -> Result<(), DidSdkError> {
        Ok(())
    }
}
