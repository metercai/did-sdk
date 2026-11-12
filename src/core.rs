//! 三种后端、两种运行模式共享的 VC 钱包、确认回调与同步桥接。

use std::future::Future;
use std::sync::{Arc, RwLock as StdRwLock};

use async_lock::RwLock;
use keyvault_core::{KeyId, KeyVaultError};

use crate::DidSdkError;
use crate::server_request::{
    ServerRequestHandler, approve_authorization, approve_signature, approve_vp,
};
use crate::vc::VcStore;

pub(crate) struct SdkCore {
    pub(crate) vcs: VcStore,
    pub(crate) handler: StdRwLock<Option<Arc<dyn ServerRequestHandler>>>,
    pub(crate) active_key: RwLock<Option<KeyId>>,
}

impl SdkCore {
    pub(crate) fn new(vc_storage_path: std::path::PathBuf) -> Self {
        Self {
            vcs: VcStore::new(vc_storage_path),
            handler: StdRwLock::new(None),
            active_key: RwLock::new(None),
        }
    }

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

    pub(crate) async fn confirm_challenge(
        &self,
        challenge: &str,
        requestor: &str,
    ) -> Result<(), DidSdkError> {
        match self.current_handler() {
            Some(handler) => approve_signature(handler.on_challenge(challenge, requestor).await?),
            None => Ok(()),
        }
    }

    pub(crate) async fn confirm_vp(
        &self,
        credential_types: &[String],
        challenge: &str,
    ) -> Result<(), DidSdkError> {
        match self.current_handler() {
            Some(handler) => approve_vp(handler.on_vp_request(credential_types, challenge).await?),
            None => Ok(()),
        }
    }

    pub(crate) async fn confirm_authorization(
        &self,
        fields: &[String],
        purpose: &str,
        requestor: &str,
    ) -> Result<(), DidSdkError> {
        match self.current_handler() {
            Some(handler) => approve_authorization(
                handler
                    .on_authorization_request(fields, purpose, requestor)
                    .await?,
            ),
            None => Ok(()),
        }
    }
}

/// 同步桥接：用于规格中声明为同步、但底层 KeyVault/Backend 为异步的 API。
///
/// `futures::executor::block_on` 不启动 Tokio runtime；FileKeystore 只用
/// async-lock + 同步文件 IO，因此可用。
pub(crate) fn block_on_future<F: Future>(future: F) -> F::Output {
    futures::executor::block_on(future)
}

/// 同步桥接：用于 Centralized/Chain 后端。在 Tokio runtime 内调用时，切到
/// 独立线程 + 独立 runtime，避免嵌套 runtime panic。
pub(crate) fn block_on_backend<F, Fut, T>(make_future: F) -> Result<T, DidSdkError>
where
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = Result<T, DidSdkError>> + Send,
    T: Send,
{
    let run = || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| DidSdkError::ChainUnavailable(format!("build runtime: {error}")))?;
        runtime.block_on(make_future())
    };

    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::scope(|scope| {
            scope
                .spawn(run)
                .join()
                .map_err(|_| DidSdkError::ChainUnavailable("blocking bridge panicked".into()))?
        })
    } else {
        run()
    }
}

/// 把 `KeyVaultError` 映射为 `DidSdkError`。
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
        KE::IoError(message) => DidSdkError::ChainUnavailable(message),
        KE::InvalidKeyFormat(message) => DidSdkError::InvalidArgument(message),
        KE::DecryptionFailed => DidSdkError::SigningFailed("decryption failed".into()),
        KE::SerializationError(message) => DidSdkError::InvalidArgument(message),
        KE::Unsupported => DidSdkError::Unsupported("keystore operation".into()),
        KE::NamespaceViolation {
            key,
            actual,
            expected,
        } => DidSdkError::InvalidArgument(format!(
            "namespace violation for {key}: {actual:?} != {expected:?}"
        )),
        KE::AlgorithmMismatch {
            key,
            actual,
            expected,
        } => DidSdkError::InvalidArgument(format!(
            "algorithm mismatch for {key}: {actual:?} != {expected:?}"
        )),
    }
}
