//! did-sdk: DID 方法 + VC 钱包统一能力层。
//!
//! - `DidSdk<Client>`：客户端本地密钥、用户确认式签名；
//! - `DidSdk<Server>`：服务端固定 did:web、外部注入 Proof、校验他人 VC；
//! - 三种后端：Mock / Centralized / Chain。

pub mod config;
pub mod error;
pub mod server_request;
pub mod types;

pub mod backend;
mod centralized;
mod chain;
mod core;
pub mod did;
mod did_signature;
mod mock;
mod storage;
mod vc;

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock as StdRwLock};

use keyvault_core::{KeyAlgorithm, KeyId, KeyNamespace, KeyVault};

use crate::backend::Backend;
use crate::core::{SdkCore, block_on_backend, block_on_future, map_vault_err};
use crate::server_request::ServerRequestHandler;

pub use backend::Backend as BackendTrait;
pub use centralized::CentralizedBackend;
pub use chain::ChainBackend;
pub use config::{
    ClientConfig, ConfigOverrides, DidSdkConfig, DidSdkMode, KeyVaultConfig, ServerConfig,
    build_client_sdk, build_client_sdk_with_backend, build_server_sdk,
    build_server_sdk_with_backend, resolve_config,
};
pub use error::DidSdkError;
pub use mock::{ConfirmPolicy, MockBackend};
pub use types::*;

/// 运行模式标记 trait（Client / Server）。
pub trait SdkMode: Send + Sync + 'static {
    /// 是否为 Client 模式。
    const IS_CLIENT: bool;
}

/// Client 运行模式。
#[derive(Debug, Clone, Copy)]
pub struct Client;

/// Server 运行模式。
#[derive(Debug, Clone, Copy)]
pub struct Server;

impl SdkMode for Client {
    const IS_CLIENT: bool = true;
}

impl SdkMode for Server {
    const IS_CLIENT: bool = false;
}

/// DID SDK。
pub struct DidSdk<M: SdkMode> {
    pub(crate) core: SdkCore,
    pub(crate) backend: Arc<dyn Backend>,
    pub(crate) vault: Option<Arc<dyn KeyVault>>,
    pub(crate) participant_did: Option<String>,
    pub(crate) http: reqwest::Client,
    pub(crate) docs: StdRwLock<HashMap<String, DidDocument>>,
    pub(crate) local_dids: StdRwLock<HashMap<String, DidRecord>>,
    pub(crate) active_did: StdRwLock<Option<String>>,
    _mode: PhantomData<M>,
}

impl<M: SdkMode> DidSdk<M> {
    pub(crate) fn new(
        backend: Arc<dyn Backend>,
        vault: Option<Arc<dyn KeyVault>>,
        participant_did: Option<String>,
        vc_storage_path: std::path::PathBuf,
    ) -> Self {
        Self {
            core: SdkCore::new(vc_storage_path),
            backend,
            vault,
            participant_did,
            http: reqwest::Client::new(),
            docs: StdRwLock::new(HashMap::new()),
            local_dids: StdRwLock::new(HashMap::new()),
            active_did: StdRwLock::new(None),
            _mode: PhantomData,
        }
    }

    /// 解析 DID；本地 did:key / did:peer 直接构造记录，其他走 backend。
    pub fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError> {
        if let Some(record) = self
            .local_dids
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(did)
            .cloned()
        {
            return Ok(Some(record));
        }
        if did.starts_with("did:key:") {
            return Ok(Some(DidRecord::new(did.to_string(), DidMethod::Key)));
        }
        if did.starts_with("did:peer:") {
            return Ok(Some(DidRecord::new(did.to_string(), DidMethod::Peer)));
        }
        let backend = self.backend.clone();
        let did = did.to_string();
        block_on_backend(move || async move { backend.resolve_did(&did).await })
    }

    /// 查询 anchor。
    pub async fn get_anchor(&self, anchor_id: &str) -> Result<AnchorRecord, DidSdkError> {
        self.backend.get_anchor(anchor_id).await
    }

    /// 存储 VC。
    pub async fn store_vc(&self, vc: VerifiableCredential) -> Result<(), DidSdkError> {
        self.core.vcs.put(&vc)
    }

    /// 按 anchor id 获取 VC。
    pub async fn get_vc(
        &self,
        anchor_id: &str,
    ) -> Result<Option<VerifiableCredential>, DidSdkError> {
        self.core.vcs.get(anchor_id)
    }

    /// 列出本地 VC。
    pub async fn list_vcs(&self) -> Result<Vec<VerifiableCredential>, DidSdkError> {
        self.core.vcs.list()
    }

    /// 删除 VC。
    pub async fn remove_vc(&self, anchor_id: &str) -> Result<(), DidSdkError> {
        self.core.vcs.remove(anchor_id)
    }

    /// 构造 VP。Client 用 active key 签名；Server 无签名私钥，返回无 proof 的 VP。
    pub async fn build_vp(
        &self,
        vcs: Vec<VerifiableCredential>,
        challenge: &str,
        domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError> {
        let holder = self.holder_did()?;
        let mut types: Vec<String> = vcs.iter().flat_map(|vc| vc.types.iter().cloned()).collect();
        types.sort();
        types.dedup();
        self.core.confirm_vp(&types, challenge).await?;
        self.backend.confirm_vp().await?;
        let signing_input = vc::vp_signing_input(&holder, challenge, domain, &vcs)?;
        let proof = if let Some(vault) = &self.vault {
            let key_id = self.active_key().await?;
            let signature = vault
                .sign_checked(
                    &key_id,
                    &signing_input,
                    KeyNamespace::ClientDid,
                    KeyAlgorithm::Ed25519,
                )
                .await
                .map_err(map_vault_err)?;
            Some(vc::proof_for(&holder, vc::now_ts(), &signature.0))
        } else {
            None
        };
        Ok(vc::build_vp_object(&holder, vcs, challenge, domain, proof))
    }

    /// 安装用户确认 handler（仅 Client 有意义）。
    pub fn set_request_handler(&self, handler: Arc<dyn ServerRequestHandler>) {
        self.core.set_handler(handler);
    }

    fn holder_did(&self) -> Result<String, DidSdkError> {
        if let Some(did) = self
            .active_did
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            return Ok(did);
        }
        if let Some(participant) = &self.participant_did {
            return Ok(participant.clone());
        }
        Err(DidSdkError::InvalidArgument(
            "no active DID / participant DID".into(),
        ))
    }

    async fn active_key(&self) -> Result<KeyId, DidSdkError> {
        if let Some(key_id) = self.core.active_key.read().await.clone() {
            return Ok(key_id);
        }
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| DidSdkError::Unsupported("no KeyVault".into()))?;
        let mut keys = vault
            .list_keys(Some(KeyNamespace::ClientDid))
            .await
            .map_err(map_vault_err)?;
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        let key_id = match keys.into_iter().next() {
            Some(key_id) => key_id,
            None => vault
                .generate(KeyNamespace::ClientDid, KeyAlgorithm::Ed25519)
                .await
                .map_err(map_vault_err)?,
        };
        *self.core.active_key.write().await = Some(key_id.clone());
        Ok(key_id)
    }

    fn set_active(&self, key_id: &KeyId, did: &str) {
        *self
            .active_did
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(did.to_string());
        let mut guard = block_on_future(self.core.active_key.write());
        *guard = Some(key_id.clone());
    }
}

impl DidSdk<Client> {
    /// 生成 did:key。
    pub fn generate_did_key(&self) -> Result<String, DidSdkError> {
        let key_id = self.new_client_key()?;
        let did = did_from_key_id(&key_id)?;
        self.set_active(&key_id, &did);
        Ok(did)
    }

    /// 生成 did:peer。
    pub fn generate_did_peer(&self, numalgo: PeerNumalgo) -> Result<String, DidSdkError> {
        let key_id = self.new_client_key()?;
        let public_key = block_on_future(
            self.vault
                .as_ref()
                .ok_or_else(|| DidSdkError::Unsupported("no KeyVault".into()))?
                .public_key(&key_id),
        )
        .map_err(map_vault_err)?;
        let public_key = match public_key {
            keyvault_core::PublicKey::Ed25519(bytes) => bytes,
            keyvault_core::PublicKey::Sr25519(_) => {
                return Err(DidSdkError::UnsupportedDidMethod(
                    "sr25519 cannot be used for did:peer".into(),
                ));
            }
        };
        let (did, document) = did::encode_peer_did(&public_key, numalgo);
        self.docs
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(did.clone(), document);
        self.set_active(&key_id, &did);
        Ok(did)
    }

    fn new_client_key(&self) -> Result<KeyId, DidSdkError> {
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| DidSdkError::Unsupported("no KeyVault".into()))?;
        block_on_future(vault.generate(KeyNamespace::ClientDid, KeyAlgorithm::Ed25519))
            .map_err(map_vault_err)
    }

    /// 用 active key 签名。
    pub async fn sign_with_did_key(
        &self,
        message: &[u8],
        ctx: SigningContext,
    ) -> Result<Signature, DidSdkError> {
        self.backend.confirm_signing().await?;
        self.core
            .confirm_challenge(&ctx.purpose, &ctx.requestor.unwrap_or_default())
            .await?;
        let key_id = self.active_key().await?;
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| DidSdkError::Unsupported("no KeyVault".into()))?;
        let signature = vault
            .sign_checked(
                &key_id,
                message,
                KeyNamespace::ClientDid,
                KeyAlgorithm::Ed25519,
            )
            .await
            .map_err(map_vault_err)?;
        Ok(Signature(signature.0))
    }

    /// 解析 did:key。
    pub fn resolve_did_key(&self, did: &str) -> Result<Ed25519PublicKey, DidSdkError> {
        keyvault_core::crypto::decode_did_key_pubkey(did)
            .map(Ed25519PublicKey)
            .map_err(|error| DidSdkError::DidResolutionFailed(error.to_string()))
    }

    /// 解析 did:peer（本地文档缓存）。
    pub fn resolve_did_peer(&self, did: &str) -> Result<DidDocument, DidSdkError> {
        let docs = self
            .docs
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        did::resolve_peer(did, &docs)
    }

    /// 创建 did:key 记录。
    pub fn create_did(&self) -> Result<DidRecord, DidSdkError> {
        let did = self.generate_did_key()?;
        let record = DidRecord::new(did.clone(), DidMethod::Key);
        self.local_dids
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(did, record.clone());
        Ok(record)
    }

    /// 签发 self-asserted VC（本地签名）。
    pub fn issue_self_asserted_vc(
        &self,
        claims: serde_json::Value,
    ) -> Result<VerifiableCredential, DidSdkError> {
        let backend = self.backend.clone();
        block_on_backend(move || async move { backend.confirm_signing().await })?;
        let holder = self.holder_did()?;
        let key_id = block_on_future(self.active_key())?;
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| DidSdkError::Unsupported("no KeyVault".into()))?;
        let mut vc = vc::build_vc(&holder, claims, None);
        let signing_input = vc::vc_signing_input(&vc)?;
        let signature = block_on_future(vault.sign_checked(
            &key_id,
            &signing_input,
            KeyNamespace::ClientDid,
            KeyAlgorithm::Ed25519,
        ))
        .map_err(map_vault_err)?;
        vc.proof = Some(vc::proof_for(&holder, vc::now_ts(), &signature.0));
        Ok(vc)
    }

    /// 构造 DID-Signature header。
    pub async fn build_did_signature_header(
        &self,
        from: &str,
        anchor_id: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> Result<String, DidSdkError> {
        self.backend.confirm_signing().await?;
        self.core.confirm_challenge(anchor_id, from).await?;
        let did = self.holder_did()?;
        let key_id = self.active_key().await?;
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| DidSdkError::Unsupported("no KeyVault".into()))?;
        let timestamp = vc::now_ts();
        let signing_input = keyvault_core::signing_input::did_signature_v1(
            &did, from, timestamp, anchor_id, body_hash, rcpt_hash,
        );
        let signature = vault
            .sign_checked(
                &key_id,
                &signing_input,
                KeyNamespace::ClientDid,
                KeyAlgorithm::Ed25519,
            )
            .await
            .map_err(map_vault_err)?;
        did_signature::encode_header(&did_signature::HeaderBody {
            v: 1,
            did,
            from: from.to_string(),
            timestamp,
            anchor_ref: anchor_id.to_string(),
            body_hash: body_hash.to_string(),
            rcpt_hash: rcpt_hash.to_string(),
            sig: bs58::encode(&signature.0).into_string(),
        })
    }

    /// 校验 DID-Signature header。
    pub fn verify_did_signature_header(
        &self,
        header: &str,
        from: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> Result<VerifyResult, DidSdkError> {
        let docs = self
            .docs
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(did_signature::verify_header_with_docs(
            header, from, body_hash, rcpt_hash, &docs,
        ))
    }

    /// 签发授权签名。
    pub async fn sign_issue_authorization(
        &self,
        subject_did: &str,
        vc_type: &str,
        vc_hash: &str,
        _timestamp: u64,
    ) -> Result<IssueAuthorizationSignature, DidSdkError> {
        self.backend.confirm_authorization().await?;
        self.core
            .confirm_authorization(&[vc_type.to_string()], "issue-vc", subject_did)
            .await?;
        let issuer_did = self.holder_did()?;
        let key_id = self.active_key().await?;
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| DidSdkError::Unsupported("no KeyVault".into()))?;
        let signing_input =
            keyvault_core::signing_input::issued_vc_v1(&issuer_did, subject_did, vc_type, vc_hash);
        let signature = vault
            .sign_checked(
                &key_id,
                &signing_input,
                KeyNamespace::ClientDid,
                KeyAlgorithm::Ed25519,
            )
            .await
            .map_err(map_vault_err)?;
        Ok(IssueAuthorizationSignature(signature.0))
    }
}

impl DidSdk<Server> {
    /// 服务端参与方 did:web。
    pub fn participant_did(&self) -> &str {
        self.participant_did.as_deref().unwrap_or_default()
    }

    /// 解析 did:web（HTTPS 文档）。
    pub async fn resolve_did_web(&self, did: &str) -> Result<DidDocument, DidSdkError> {
        let url = did::did_web_url(did)?;
        let response =
            self.http.get(&url).send().await.map_err(|error| {
                DidSdkError::DidResolutionFailed(format!("fetch {url}: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(DidSdkError::DidResolutionFailed(format!(
                "fetch {url}: HTTP {}",
                response.status()
            )));
        }
        let document: DidDocument = response
            .json()
            .await
            .map_err(|error| DidSdkError::DidResolutionFailed(format!("parse {url}: {error}")))?;
        self.docs
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(did.to_string(), document.clone());
        Ok(document)
    }

    /// 组装 VC（proof 由外部 Signer 注入）。
    pub fn assemble_vc_with_proof(
        &self,
        claims: serde_json::Value,
        subject: &str,
        proof: Proof,
    ) -> Result<VerifiableCredential, DidSdkError> {
        vc::assemble_vc(self.participant_did(), claims, subject, proof)
    }

    /// 校验他人 VC。
    pub async fn verify_vc(
        &self,
        vc: &VerifiableCredential,
    ) -> Result<VcVerificationResult, DidSdkError> {
        let mut issuer_resolved = false;
        let issuer_key = if vc.issuer.starts_with("did:web:") {
            match self.resolve_did_web(&vc.issuer).await {
                Ok(document) => {
                    issuer_resolved = true;
                    did::document_public_key(&document)
                }
                Err(error) => Err(error),
            }
        } else {
            let document = if vc.issuer.starts_with("did:key:") {
                did::did_key_document_from_did(&vc.issuer)
            } else {
                self.resolve_did_peer_document(&vc.issuer)
            };
            match document {
                Ok(document) => {
                    issuer_resolved = true;
                    did::document_public_key(&document)
                }
                Err(error) => Err(error),
            }
        };

        let mut reason = None;
        let signature_ok = match (issuer_key, &vc.proof) {
            (Ok(key), Some(proof)) => match keyvault_core::crypto::base58::decode(&proof.jws) {
                Ok(signature) => match vc::vc_signing_input(vc) {
                    Ok(input) => keyvault_core::crypto::ed25519::verify(&key, &input, &signature),
                    Err(error) => {
                        reason = Some(error.to_string());
                        false
                    }
                },
                Err(error) => {
                    reason = Some(format!("invalid proof encoding: {error}"));
                    false
                }
            },
            (Err(error), _) => {
                reason = Some(error.to_string());
                false
            }
            (_, None) => {
                reason = Some("VC has no proof".into());
                false
            }
        };

        let expired = vc
            .expiration_date
            .as_deref()
            .is_some_and(|expiration| expiration <= vc::rfc3339_utc(vc::now_ts()).as_str());
        if expired {
            reason = Some("VC expired".into());
        }

        let mut anchor_valid = vc.anchor_id.is_none();
        if let Some(anchor_id) = &vc.anchor_id {
            match self.get_anchor(anchor_id).await {
                Ok(anchor) => {
                    anchor_valid = anchor.status == AddressStatus::Active;
                    if !anchor_valid {
                        reason = Some(format!("anchor status: {:?}", anchor.status));
                    }
                }
                Err(error) => {
                    anchor_valid = false;
                    reason = Some(error.to_string());
                }
            }
        }

        let issuer_registered = issuer_resolved;
        Ok(VcVerificationResult {
            verified: signature_ok && !expired && anchor_valid,
            issuer_resolved,
            issuer_registered,
            anchor_valid,
            reason,
        })
    }

    fn resolve_did_peer_document(&self, did: &str) -> Result<DidDocument, DidSdkError> {
        let docs = self
            .docs
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        did::resolve_peer(did, &docs)
    }
}

fn did_from_key_id(key_id: &KeyId) -> Result<String, DidSdkError> {
    let local = key_id.local_id().ok_or_else(|| {
        DidSdkError::InvalidArgument(format!("missing namespace prefix: {}", key_id.0))
    })?;
    let encoded = local.strip_prefix("did_key_").unwrap_or(local);
    Ok(format!("did:key:{encoded}"))
}
