//! did-sdk: DID 方法 + VC 钱包统一能力层。
//!
//! - `DidSdk<Client>`：客户端本地密钥、用户确认式签名；
//! - `DidSdk<Server>`：服务端固定 did:web、外部注入 Proof、校验他人 VC；
//! - 两种后端：Mock / Centralized（不承担链上查询）。

pub mod config;
pub mod error;
pub mod sd;
pub mod server_request;
pub mod types;

pub mod backend;
mod centralized;
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
pub use config::{
    ClientConfig, ConfigOverrides, DidSdkConfig, DidSdkMode, KeyVaultConfig, ServerConfig,
    build_client_sdk, build_client_sdk_with_backend, build_server_sdk,
    build_server_sdk_with_backend, resolve_config,
};
pub use error::DidSdkError;
pub use mock::{ConfirmPolicy, MockBackend};
pub use types::*;
pub use vc::{anchor_payload_hash, vc_hash, vc_hash_without_proof};

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
        vc_password: Option<secrecy::SecretString>,
    ) -> Result<Self, DidSdkError> {
        Ok(Self {
            core: SdkCore::new(vc_storage_path, vc_password)?,
            backend,
            vault,
            participant_did,
            http: reqwest::Client::new(),
            docs: StdRwLock::new(HashMap::new()),
            local_dids: StdRwLock::new(HashMap::new()),
            active_did: StdRwLock::new(None),
            _mode: PhantomData,
        })
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

    /// 存储 VC。
    pub async fn store_vc(&self, vc: VerifiableCredential) -> Result<(), DidSdkError> {
        self.core.vcs.put(&vc)
    }

    /// 列出某 VC 可选择性披露的属性名（来自已存储的 Disclosures）。
    pub async fn list_disclosable_attributes(
        &self,
        anchor_id: &str,
    ) -> Result<Vec<String>, DidSdkError> {
        let bundle = self
            .core
            .vcs
            .get_bundle(anchor_id)?
            .ok_or_else(|| DidSdkError::VcNotFound(anchor_id.to_string()))?;
        let mut names: Vec<String> = bundle
            .disclosures
            .into_iter()
            .map(|disclosure| disclosure.name)
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    /// 存储 VC 及其 Disclosures（同一加密信封绑定）。
    pub async fn store_vc_with_disclosures(
        &self,
        vc: VerifiableCredential,
        disclosures: Vec<Disclosure>,
    ) -> Result<(), DidSdkError> {
        sd::verify_disclosures(&vc, &disclosures)?;
        self.core.vcs.put_bundle(&vc, &disclosures)
    }

    /// 按 anchor id 获取 VC 及其 Disclosures。
    pub async fn get_vc_with_disclosures(
        &self,
        anchor_id: &str,
    ) -> Result<Option<(VerifiableCredential, Vec<Disclosure>)>, DidSdkError> {
        Ok(self
            .core
            .vcs
            .get_bundle(anchor_id)?
            .map(|bundle| (bundle.vc, bundle.disclosures)))
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
            let namespace = if M::IS_CLIENT {
                KeyNamespace::ClientDid
            } else {
                KeyNamespace::ParticipantDid
            };
            let signature = vault
                .sign_checked(&key_id, &signing_input, namespace, KeyAlgorithm::Ed25519)
                .await
                .map_err(map_vault_err)?;
            Some(vc::proof_for(&holder, vc::now_ts(), &signature.0))
        } else {
            None
        };
        Ok(vc::build_vp_object(
            &holder, vcs, challenge, domain, None, proof,
        ))
    }

    /// 构造选择性披露 VP。
    ///
    /// `requests` 中每个 VC 的 `disclose` 为空表示该 VC 全部属性隐藏；
    /// Disclosures 必须已通过 `store_vc_with_disclosures` 与 VC 绑定存储。
    pub async fn build_vp_selective(
        &self,
        requests: Vec<SelectiveVpRequest>,
        challenge: &str,
        domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError> {
        let holder = self.holder_did()?;
        let mut types: Vec<String> = requests
            .iter()
            .flat_map(|request| request.credential.types.iter().cloned())
            .collect();
        types.sort();
        types.dedup();
        self.core.confirm_vp(&types, challenge).await?;
        self.backend.confirm_vp().await?;

        let mut vcs = Vec::with_capacity(requests.len());
        let mut disclosures = Vec::new();
        for request in &requests {
            let anchor_id =
                request.credential.anchor_id.as_deref().ok_or_else(|| {
                    DidSdkError::InvalidArgument("VC is missing anchor_id".into())
                })?;
            let bundle = self
                .core
                .vcs
                .get_bundle(anchor_id)?
                .ok_or_else(|| DidSdkError::VcNotFound(anchor_id.to_string()))?;
            let selected = sd::select_disclosures(&bundle.disclosures, &request.disclose)?;
            sd::verify_disclosures(&request.credential, &selected)?;
            vcs.push(request.credential.clone());
            disclosures.extend(selected);
        }

        let disclosures_hash = sd::disclosures_hash(&disclosures)?;
        let vc_hashes = vcs.iter().map(vc::vc_hash).collect::<Result<Vec<_>, _>>()?;
        let signing_input = keyvault_core::signing_input::vp_sd_v1(
            &holder,
            challenge,
            domain,
            &disclosures_hash,
            &vc_hashes,
        );
        let proof = if let Some(vault) = &self.vault {
            let key_id = self.active_key().await?;
            let namespace = if M::IS_CLIENT {
                KeyNamespace::ClientDid
            } else {
                KeyNamespace::ParticipantDid
            };
            let signature = vault
                .sign_checked(&key_id, &signing_input, namespace, KeyAlgorithm::Ed25519)
                .await
                .map_err(map_vault_err)?;
            Some(vc::proof_for(&holder, vc::now_ts(), &signature.0))
        } else {
            None
        };
        Ok(vc::build_vp_object(
            &holder,
            vcs,
            challenge,
            domain,
            Some(disclosures),
            proof,
        ))
    }

    /// 安装用户确认 handler（仅 Client 有意义）。
    pub fn set_request_handler(&self, handler: Arc<dyn ServerRequestHandler>) {
        self.core.set_handler(handler);
    }

    fn issue_vc_local(
        &self,
        claims: serde_json::Value,
        disclosable: &[String],
    ) -> Result<(VerifiableCredential, Vec<Disclosure>), DidSdkError> {
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| DidSdkError::Unsupported("no local signer".into()))?;
        let backend = self.backend.clone();
        block_on_backend(move || async move { backend.confirm_signing().await })?;
        let issuer = self.holder_did()?;
        let key_id = block_on_future(self.active_key())?;
        let namespace = if M::IS_CLIENT {
            KeyNamespace::ClientDid
        } else {
            KeyNamespace::ParticipantDid
        };
        let (claims, disclosures) = if disclosable.is_empty() {
            (claims, Vec::new())
        } else {
            sd::split_selective_claims(claims, disclosable)?
        };
        let mut vc = vc::build_vc(&issuer, claims, None);
        let signing_input = vc::vc_signing_input(&vc)?;
        let signature = block_on_future(vault.sign_checked(
            &key_id,
            &signing_input,
            namespace,
            KeyAlgorithm::Ed25519,
        ))
        .map_err(map_vault_err)?;
        vc.proof = Some(vc::proof_for(&issuer, vc::now_ts(), &signature.0));
        Ok((vc, disclosures))
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
        let namespace = if M::IS_CLIENT {
            KeyNamespace::ClientDid
        } else {
            KeyNamespace::ParticipantDid
        };
        let mut keys = vault
            .list_keys(Some(namespace))
            .await
            .map_err(map_vault_err)?;
        keys.sort_by(|a, b| a.0.cmp(&b.0));
        let key_id = match keys.into_iter().next() {
            Some(key_id) => key_id,
            None => vault
                .generate(namespace, KeyAlgorithm::Ed25519)
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
        self.issue_vc_local(claims, &[]).map(|(vc, _)| vc)
    }

    /// 签发带选择性披露属性的 VC，返回 VC 与对应 Disclosures。
    pub fn issue_selective_vc(
        &self,
        claims: serde_json::Value,
        disclosable: &[String],
    ) -> Result<(VerifiableCredential, Vec<Disclosure>), DidSdkError> {
        self.issue_vc_local(claims, disclosable)
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

    /// 签发发行授权签名（`IssuedVc-v1`）。
    ///
    /// `timestamp` **当前不参与** `IssuedVc-v1`，它不是防重放字段；
    /// 需要时间绑定的委托授权请使用
    /// [`DidSdk::<Client>::sign_delegation_authorization`]。
    /// 如需为 VC 签发授权增加时间绑定，应新增 `IssuedVc-v2`，不得修改本格式。
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

    /// 用户 A 对“授权链主代提交锚定”签名（`DelegationAuthorization-v1`）。
    ///
    /// - `vc_hash` 必须由调用方用 [`crate::anchor_payload_hash`] 计算；
    /// - `delegate_did` / `delegate_operator` 是链主的 `did:web` / SS58；
    /// - `timestamp` 参与签名，调用方负责选取当前 Unix 秒；
    /// - 使用当前 active did:key 的 `ClientDid`/Ed25519 密钥；
    /// - 返回自包含的 [`DelegationAuthorization`]（含 `signer_did` 与 `signature`）。
    ///
    /// 参数校验失败返回 [`DidSdkError::InvalidArgument`]；当前 active DID 不是
    /// `did:key`（例如 `did:peer`）返回
    /// [`DidSdkError::Unsupported`]（POC 限制：委托授权只支持 `did:key`）。
    /// 用户拒绝确认时 `UserRejected` 1:1 透传。
    ///
    /// 签名输入只覆盖：
    ///
    /// ```text
    /// DelegationAuthorization-v1
    /// {vc_hash}
    /// {delegate_did}
    /// {delegate_operator}
    /// {timestamp}
    /// ```
    ///
    /// 由 `keyvault_core::signing_input::delegation_authorization_v1` 生成，
    /// 不覆盖 JSON 外壳。
    pub async fn sign_delegation_authorization(
        &self,
        vc_hash: &str,
        delegate_did: &str,
        delegate_operator: &str,
        timestamp: u64,
    ) -> Result<DelegationAuthorization, DidSdkError> {
        if vc_hash.is_empty() {
            return Err(DidSdkError::InvalidArgument("empty vc_hash".into()));
        }
        if delegate_did.is_empty() {
            return Err(DidSdkError::InvalidArgument("empty delegate_did".into()));
        }
        if !delegate_did.starts_with("did:") {
            return Err(DidSdkError::InvalidArgument(format!(
                "delegate_did must start with the did: scheme: {delegate_did}"
            )));
        }
        if delegate_operator.is_empty() {
            return Err(DidSdkError::InvalidArgument(
                "empty delegate_operator".into(),
            ));
        }
        if timestamp == 0 {
            return Err(DidSdkError::InvalidArgument("timestamp must be > 0".into()));
        }

        self.backend.confirm_authorization().await?;
        self.core
            .confirm_authorization(
                &["DelegationAuthorization".to_string()],
                "delegation",
                delegate_did,
            )
            .await?;

        let signer_did = self.holder_did()?;
        if !signer_did.starts_with("did:key:") {
            return Err(DidSdkError::Unsupported(
                "delegation authorization requires did:key".into(),
            ));
        }
        let key_id = self.active_key().await?;
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| DidSdkError::Unsupported("no KeyVault".into()))?;
        let signing_input = keyvault_core::signing_input::delegation_authorization_v1(
            vc_hash,
            delegate_did,
            delegate_operator,
            timestamp,
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
        Ok(DelegationAuthorization {
            version: DelegationAuthorization::VERSION,
            vc_hash: vc_hash.to_string(),
            delegate_did: delegate_did.to_string(),
            delegate_operator: delegate_operator.to_string(),
            timestamp,
            signer_did,
            signature: signature.0,
        })
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

        let issuer_registered = issuer_resolved;
        Ok(VcVerificationResult {
            verified: signature_ok && !expired,
            issuer_resolved,
            issuer_registered,
            reason,
        })
    }

    /// 验证选择性披露 VP（holder 签名 + challenge + VC + Disclosure 哈希）。
    ///
    /// 锚定查询不在此处执行（R1：由 chain-sdk 负责）。
    pub async fn verify_vp(
        &self,
        vp: &VerifiablePresentation,
        expected_challenge: &str,
    ) -> Result<VpVerificationResult, DidSdkError> {
        let mut reason = None;
        let challenge_ok = vp.challenge == expected_challenge;
        if !challenge_ok {
            reason = Some("challenge mismatch".into());
        }

        let holder_key = {
            let docs = self
                .docs
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            did::public_key_from_did_with_docs(&vp.holder, &docs)
        };
        let holder_resolved = holder_key.is_ok();
        let holder_ok = match (holder_key, &vp.proof) {
            (Ok(key), Some(proof)) => match keyvault_core::crypto::base58::decode(&proof.jws) {
                Ok(signature) => {
                    let vc_hashes = vp
                        .verifiable_credential
                        .iter()
                        .map(vc::vc_hash)
                        .collect::<Result<Vec<_>, _>>()?;
                    let signing_input = match &vp.disclosures {
                        Some(disclosures) => {
                            let body_hash = sd::disclosures_hash(disclosures)?;
                            keyvault_core::signing_input::vp_sd_v1(
                                &vp.holder,
                                &vp.challenge,
                                &vp.domain,
                                &body_hash,
                                &vc_hashes,
                            )
                        }
                        None => keyvault_core::signing_input::vp_v1(
                            &vp.holder,
                            &vp.challenge,
                            &vp.domain,
                            &vc_hashes,
                        ),
                    };
                    keyvault_core::crypto::ed25519::verify(&key, &signing_input, &signature)
                }
                Err(error) => {
                    reason = Some(format!("invalid VP proof encoding: {error}"));
                    false
                }
            },
            (Err(error), _) => {
                reason = Some(error.to_string());
                false
            }
            (_, None) => {
                reason = Some("VP has no proof".into());
                false
            }
        };

        let mut credentials = Vec::with_capacity(vp.verifiable_credential.len());
        for credential in &vp.verifiable_credential {
            let result = self.verify_vc(credential).await?;
            if !result.verified && reason.is_none() {
                reason = result.reason.clone();
            }
            credentials.push(result);
        }

        let disclosure_count = match &vp.disclosures {
            Some(disclosures) => {
                let mut names = std::collections::HashSet::new();
                let mut hash_sets = Vec::with_capacity(vp.verifiable_credential.len());
                for credential in &vp.verifiable_credential {
                    hash_sets.push(sd::sd_hashes(credential)?);
                }
                for disclosure in disclosures {
                    if !names.insert(disclosure.name.as_str()) {
                        return Err(DidSdkError::DisclosureDuplicate(disclosure.name.clone()));
                    }
                    let hash = disclosure.hash_string()?;
                    if !hash_sets.iter().any(|set| set.contains(&hash)) {
                        return Err(DidSdkError::DisclosureHashMismatch(disclosure.name.clone()));
                    }
                }
                disclosures.len()
            }
            None => 0,
        };

        let credentials_ok = credentials.iter().all(|result| result.verified);
        let verified = challenge_ok && holder_ok && credentials_ok;
        Ok(VpVerificationResult {
            verified,
            holder_resolved,
            credentials,
            disclosure_count,
            reason,
        })
    }

    /// 是否配置了本地签名器（开发/测试/试运行）。
    pub fn has_signer(&self) -> bool {
        self.vault.is_some()
    }

    /// 用 `participant-did/` 本地密钥签名（仅配置了 key_vault 时可用）。
    pub async fn sign_with_participant_key(
        &self,
        message: &[u8],
        ctx: SigningContext,
    ) -> Result<Signature, DidSdkError> {
        let _ = ctx;
        self.backend.confirm_signing().await?;
        let key_id = self.active_key().await?;
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| DidSdkError::Unsupported("server has no local signer".into()))?;
        let signature = vault
            .sign_checked(
                &key_id,
                message,
                KeyNamespace::ParticipantDid,
                KeyAlgorithm::Ed25519,
            )
            .await
            .map_err(map_vault_err)?;
        Ok(Signature(signature.0))
    }

    /// 使用本地 `participant-did/` 密钥签发 VC（开发/测试/试运行）。
    pub fn issue_self_asserted_vc(
        &self,
        claims: serde_json::Value,
    ) -> Result<VerifiableCredential, DidSdkError> {
        self.issue_vc_local(claims, &[]).map(|(vc, _)| vc)
    }

    /// 用本地签名器签发带选择性披露属性的 VC。
    pub fn issue_selective_vc(
        &self,
        claims: serde_json::Value,
        disclosable: &[String],
    ) -> Result<(VerifiableCredential, Vec<Disclosure>), DidSdkError> {
        self.issue_vc_local(claims, disclosable)
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
