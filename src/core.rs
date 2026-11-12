//! 三种模式共用的核心状态与操作。

use std::sync::{Arc, RwLock as StdRwLock};

use async_lock::RwLock;
use keyvault_core::{KeyId, KeyVault, KeyVaultError};

use crate::server_request::{
    AuthorizationRequestContext, ChallengeContext, ServerRequestHandler, VpRequestContext,
};
use crate::types::{DidRecord, Ed25519PublicKey, Signature};
use crate::vc::VcStore;
use crate::{DidSdkConfig, DidSdkError};

/// 三模式共用的构造参数与状态。
pub(crate) struct SdkCore {
    pub(crate) vault: Arc<dyn KeyVault>,
    pub(crate) config: DidSdkConfig,
    pub(crate) active_key: RwLock<Option<KeyId>>,
    pub(crate) handler: StdRwLock<Option<Arc<dyn ServerRequestHandler>>>,
    pub(crate) vcs: VcStore,
}

impl SdkCore {
    pub(crate) fn new(vault: Arc<dyn KeyVault>, config: DidSdkConfig) -> Result<Self, DidSdkError> {
        Ok(Self {
            vault,
            vcs: VcStore::new(config.vc_storage_path.clone()),
            config,
            active_key: RwLock::new(None),
            handler: StdRwLock::new(None),
        })
    }

    /// 当前 Unix 时间戳（秒）。
    pub(crate) fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    /// 生成一把新 key，并设为 active key。
    pub(crate) async fn generate_did_key(&self) -> Result<String, DidSdkError> {
        let key_id = self.vault.generate().await.map_err(map_vault_err)?;
        let did = key_id.0.clone();
        *self.active_key.write().await = Some(key_id);
        Ok(did)
    }

    /// 获取 active key；没有时使用已有第一把 key，仍为空则生成一把。
    pub(crate) async fn ensure_active_key(&self) -> Result<KeyId, DidSdkError> {
        {
            let guard = self.active_key.read().await;
            if let Some(key_id) = guard.as_ref() {
                return Ok(key_id.clone());
            }
        }
        let mut keys = self.vault.list_keys().await.map_err(map_vault_err)?;
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        let key_id = match keys.into_iter().next() {
            Some(key_id) => key_id,
            None => self.vault.generate().await.map_err(map_vault_err)?,
        };
        *self.active_key.write().await = Some(key_id.clone());
        Ok(key_id)
    }

    /// active DID。
    pub(crate) async fn active_did(&self) -> Result<String, DidSdkError> {
        Ok(self.ensure_active_key().await?.0)
    }

    /// 用 active key 对原始字节签名。
    pub(crate) async fn sign_with_active(&self, payload: &[u8]) -> Result<Signature, DidSdkError> {
        let key_id = self.ensure_active_key().await?;
        let signature = self
            .vault
            .sign(&key_id, payload)
            .await
            .map_err(map_vault_err)?;
        Ok(Signature(signature.0))
    }

    /// 生成一个新的 DID 记录（会新生成一把 key 并设为 active）。
    pub(crate) async fn create_did_record(&self) -> Result<DidRecord, DidSdkError> {
        let key_id = self.vault.generate().await.map_err(map_vault_err)?;
        *self.active_key.write().await = Some(key_id.clone());
        let public_key = self
            .vault
            .public_key(&key_id)
            .await
            .map_err(map_vault_err)?;
        let public_key = match public_key {
            keyvault_core::PublicKey::Ed25519(bytes) => Ed25519PublicKey(bytes),
            keyvault_core::PublicKey::Sr25519(_) => {
                return Err(DidSdkError::Unsupported(
                    "create_did only supports Ed25519 keys in POC".into(),
                ));
            }
        };
        Ok(DidRecord::new_active(key_id.0, public_key, self.now()))
    }

    /// 安装请求确认 handler。
    pub(crate) fn set_handler(&self, handler: Arc<dyn ServerRequestHandler>) {
        let mut guard = self
            .handler
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(handler);
    }

    fn current_handler(&self) -> Option<Arc<dyn ServerRequestHandler>> {
        self.handler
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) async fn confirm_challenge(&self, ctx: ChallengeContext) -> Result<(), DidSdkError> {
        let handler = self.current_handler();
        match handler {
            Some(handler) => handler.on_challenge(&ctx).await,
            None => Ok(()),
        }
    }

    pub(crate) async fn confirm_vp(&self, ctx: VpRequestContext) -> Result<(), DidSdkError> {
        let handler = self.current_handler();
        match handler {
            Some(handler) => handler.on_vp_request(&ctx).await,
            None => Ok(()),
        }
    }

    pub(crate) async fn confirm_authorization(
        &self,
        ctx: AuthorizationRequestContext,
    ) -> Result<(), DidSdkError> {
        let handler = self.current_handler();
        match handler {
            Some(handler) => handler.on_authorization_request(&ctx).await,
            None => Ok(()),
        }
    }
}

/// 把 `KeyVaultError` 映射到 `DidSdkError`。
///
/// 所有内部实现都必须使用此函数，保证 `UserRejected` 等变体透传路径一致。
pub(crate) fn map_vault_err(error: KeyVaultError) -> DidSdkError {
    use keyvault_core::KeyVaultError as KE;
    match error {
        KE::KeyNotFound(message) => DidSdkError::KeyNotFound(message),
        KE::KeyAlreadyExists(message) => {
            DidSdkError::InvalidArgument(format!("key exists: {message}"))
        }
        KE::UserRejected => DidSdkError::UserRejected,
        KE::InvalidPassword => DidSdkError::SigningFailed("invalid password".into()),
        KE::Locked => DidSdkError::SigningFailed("keystore locked".into()),
        KE::SigningFailed(message) => DidSdkError::SigningFailed(message),
        KE::IoError(error) => DidSdkError::ChainUnavailable(error.to_string()),
        KE::InvalidKeyFormat(message) => DidSdkError::InvalidArgument(message),
        KE::DecryptionFailed => DidSdkError::SigningFailed("decryption failed".into()),
        KE::SerializationError(error) => DidSdkError::InvalidArgument(error.to_string()),
        KE::Unsupported => DidSdkError::Unsupported("keystore operation".into()),
    }
}
