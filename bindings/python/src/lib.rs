//! did-sdk Python 绑定（Client 模式）。

#![allow(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;

use pyo3::create_exception;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict};
use secrecy::SecretString;
use serde::Serialize;
use serde::de::DeserializeOwned;

use did_sdk::config::{ConfigOverrides, resolve_config};
use did_sdk::{
    ClientConfig, DidSdkError as CoreError, DidSdkMode, PeerNumalgo, Proof, ServerConfig,
    VerifiableCredential, build_client_sdk, build_server_sdk,
};

type Sdk = did_sdk::DidSdk<did_sdk::Client>;

create_exception!(_did_sdk, DidSdkError, PyRuntimeError);
create_exception!(_did_sdk, UserRejectedError, PyRuntimeError);
create_exception!(_did_sdk, NotFoundError, PyRuntimeError);
create_exception!(_did_sdk, InvalidArgumentError, PyValueError);

fn to_pyerr(error: CoreError) -> PyErr {
    match error {
        CoreError::UserRejected => UserRejectedError::new_err("UserRejected"),
        CoreError::VcNotFound(message) => NotFoundError::new_err(message),
        CoreError::InvalidArgument(message)
        | CoreError::UnsupportedDidMethod(message)
        | CoreError::DidResolutionFailed(message) => InvalidArgumentError::new_err(message),
        CoreError::VcVerificationFailed(message) => DidSdkError::new_err(message),
        other => DidSdkError::new_err(other.to_string()),
    }
}

fn to_py_object<T: Serialize>(py: Python<'_>, value: &T) -> PyResult<Py<PyAny>> {
    let value =
        serde_json::to_value(value).map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok(pythonize::pythonize(py, &value)?.unbind())
}

fn from_py_object<T: DeserializeOwned>(value: &Bound<'_, PyAny>) -> PyResult<T> {
    pythonize::depythonize(value).map_err(PyErr::from)
}

fn bytes(py: Python<'_>, data: Vec<u8>) -> Py<PyBytes> {
    PyBytes::new(py, &data).unbind()
}

fn parse_overrides(dict: Option<&Bound<'_, PyDict>>) -> PyResult<ConfigOverrides> {
    let mut overrides = ConfigOverrides::default();
    let Some(dict) = dict else {
        return Ok(overrides);
    };
    for (key, value) in dict.iter() {
        let key: String = key.extract()?;
        if value.is_none() {
            continue;
        }
        match key.as_str() {
            "mode" => overrides.mode = Some(value.extract()?),
            "vc_storage_path" => {
                overrides.vc_storage_path = Some(PathBuf::from(value.extract::<String>()?));
            }
            "key_vault_path" => {
                overrides.key_vault_path = Some(PathBuf::from(value.extract::<String>()?));
            }
            "key_vault_scheme" => overrides.key_vault_scheme = Some(value.extract()?),
            "key_vault_password" => overrides.key_vault_password = Some(value.extract()?),
            "key_vault_password_file" => {
                overrides.key_vault_password_file = Some(PathBuf::from(value.extract::<String>()?));
            }
            "centralized_endpoint" => overrides.centralized_endpoint = Some(value.extract()?),
            "cache_ttl_secs" => overrides.cache_ttl_secs = Some(value.extract()?),
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown DidSdk override: {other}"
                )));
            }
        }
    }
    Ok(overrides)
}

fn parse_numalgo(value: &str) -> PyResult<PeerNumalgo> {
    match value.to_ascii_lowercase().as_str() {
        "0" | "zero" => Ok(PeerNumalgo::Zero),
        "1" | "one" => Ok(PeerNumalgo::One),
        "2" | "two" => Ok(PeerNumalgo::Two),
        other => Err(PyValueError::new_err(format!(
            "invalid PeerNumalgo: {other}"
        ))),
    }
}

/// did-sdk Client Python 客户端。
#[pyclass]
pub struct DidSdk {
    inner: Arc<Sdk>,
    config: ClientConfig,
}

#[pymethods]
impl DidSdk {
    /// 构造 SDK。
    #[new]
    #[pyo3(signature = (**overrides))]
    fn new(overrides: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let overrides = parse_overrides(overrides)?;
        let config = resolve_config(overrides).map_err(to_pyerr)?;
        let sdk = build_client_sdk(&config).map_err(to_pyerr)?;
        Ok(Self { inner: sdk, config })
    }

    /// 生成 did:key。
    fn generate_did_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.generate_did_key().map_err(to_pyerr)
        })
    }

    /// 生成 did:peer（numalgo "0" / "1" / "2"）。
    fn generate_did_peer<'py>(
        &self,
        py: Python<'py>,
        numalgo: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let numalgo = parse_numalgo(numalgo)?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.generate_did_peer(numalgo).map_err(to_pyerr)
        })
    }

    /// 用 active key 签名。
    #[pyo3(signature = (message, *, purpose = "", payload_summary = "", requestor = None))]
    fn sign_with_did_key<'py>(
        &self,
        py: Python<'py>,
        message: Vec<u8>,
        purpose: &str,
        payload_summary: &str,
        requestor: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let purpose = purpose.to_string();
        let payload_summary = payload_summary.to_string();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let context = did_sdk::SigningContext {
                purpose,
                payload_summary,
                requestor,
            };
            let signature = inner
                .sign_with_did_key(&message, context)
                .await
                .map_err(to_pyerr)?;
            Python::with_gil(|py| Ok::<_, PyErr>(bytes(py, signature.0)))
        })
    }

    /// 解析 did:key。
    fn resolve_did_key(&self, py: Python<'_>, did: &str) -> PyResult<Py<PyBytes>> {
        let key = self.inner.resolve_did_key(did).map_err(to_pyerr)?;
        Ok(bytes(py, key.0.to_vec()))
    }

    /// 解析 did:peer。
    fn resolve_did_peer(&self, py: Python<'_>, did: &str) -> PyResult<Py<PyAny>> {
        let document = self.inner.resolve_did_peer(did).map_err(to_pyerr)?;
        to_py_object(py, &document)
    }

    /// 创建 did:key 记录。
    fn create_did<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let record = inner.create_did().map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &record))
        })
    }

    /// 解析 DID。
    fn resolve_did(&self, py: Python<'_>, did: String) -> PyResult<Py<PyAny>> {
        match self.inner.resolve_did(&did).map_err(to_pyerr)? {
            Some(record) => to_py_object(py, &record),
            None => Ok(py.None()),
        }
    }

    /// 签发 self-asserted VC。
    fn issue_self_asserted_vc<'py>(
        &self,
        py: Python<'py>,
        claims: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let claims: serde_json::Value = from_py_object(claims)?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vc = inner.issue_self_asserted_vc(claims).map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &vc))
        })
    }

    /// 存储 VC。
    fn store_vc<'py>(
        &self,
        py: Python<'py>,
        vc: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let vc: VerifiableCredential = from_py_object(vc)?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.store_vc(vc).await.map_err(to_pyerr)
        })
    }

    /// 获取 VC。
    fn get_vc<'py>(&self, py: Python<'py>, anchor_id: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vc = inner.get_vc(&anchor_id).await.map_err(to_pyerr)?;
            Python::with_gil(|py| match vc {
                Some(vc) => Ok(to_py_object(py, &vc)?),
                None => Ok(py.None()),
            })
        })
    }

    /// 列出 VC。
    fn list_vcs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vcs = inner.list_vcs().await.map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &vcs))
        })
    }

    /// 删除 VC。
    fn remove_vc<'py>(&self, py: Python<'py>, anchor_id: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.remove_vc(&anchor_id).await.map_err(to_pyerr)
        })
    }

    /// 构造 VP。
    fn build_vp<'py>(
        &self,
        py: Python<'py>,
        vcs: &Bound<'py, PyAny>,
        challenge: String,
        domain: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let vcs: Vec<VerifiableCredential> = from_py_object(vcs)?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vp = inner
                .build_vp(vcs, &challenge, &domain)
                .await
                .map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &vp))
        })
    }

    /// 构造 DID-Signature header。
    fn build_did_signature_header<'py>(
        &self,
        py: Python<'py>,
        from_: String,
        anchor_id: String,
        body_hash: String,
        rcpt_hash: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner
                .build_did_signature_header(&from_, &anchor_id, &body_hash, &rcpt_hash)
                .await
                .map_err(to_pyerr)
        })
    }

    /// 验证 DID-Signature header。
    fn verify_did_signature_header(
        &self,
        py: Python<'_>,
        header: &str,
        from_: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> PyResult<Py<PyAny>> {
        let result = self
            .inner
            .verify_did_signature_header(header, from_, body_hash, rcpt_hash)
            .map_err(to_pyerr)?;
        to_py_object(py, &result)
    }

    /// 签发授权签名（返回 bytes）。
    fn sign_issue_authorization<'py>(
        &self,
        py: Python<'py>,
        subject_did: String,
        vc_type: String,
        vc_hash: String,
        timestamp: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let signature = inner
                .sign_issue_authorization(&subject_did, &vc_type, &vc_hash, timestamp)
                .await
                .map_err(to_pyerr)?;
            Python::with_gil(|py| Ok::<_, PyErr>(bytes(py, signature.0)))
        })
    }

    /// 解析后的配置。
    fn resolved_config(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        to_py_object(py, &self.config)
    }

    #[staticmethod]
    fn did_signature_v1_bytes(
        py: Python<'_>,
        did: &str,
        from_: &str,
        timestamp: u64,
        anchor_ref: &str,
        body_hash: &str,
        rcpt_hash: &str,
    ) -> Py<PyBytes> {
        bytes(
            py,
            keyvault_core::signing_input::did_signature_v1(
                did, from_, timestamp, anchor_ref, body_hash, rcpt_hash,
            ),
        )
    }

    #[staticmethod]
    fn issued_vc_v1_bytes(
        py: Python<'_>,
        issuer_did: &str,
        subject_did: &str,
        vc_type: &str,
        vc_hash: &str,
    ) -> Py<PyBytes> {
        bytes(
            py,
            keyvault_core::signing_input::issued_vc_v1(issuer_did, subject_did, vc_type, vc_hash),
        )
    }

    #[staticmethod]
    fn vp_v1_bytes(
        py: Python<'_>,
        holder: &str,
        challenge: &str,
        domain: &str,
        vc_hashes: Vec<String>,
    ) -> Py<PyBytes> {
        bytes(
            py,
            keyvault_core::signing_input::vp_v1(holder, challenge, domain, &vc_hashes),
        )
    }

    #[staticmethod]
    fn gateway_access_v1_bytes(
        py: Python<'_>,
        did: &str,
        agent_email: &str,
        challenge: &str,
    ) -> Py<PyBytes> {
        bytes(
            py,
            keyvault_core::signing_input::gateway_access_v1(did, agent_email, challenge),
        )
    }

    #[staticmethod]
    #[pyo3(signature = (participant_id, controller_did, operator, chain_role, business_types, authorized_domains))]
    fn participant_registration_v1_bytes(
        py: Python<'_>,
        participant_id: u32,
        controller_did: &str,
        operator: &str,
        chain_role: &str,
        business_types: Vec<String>,
        authorized_domains: Vec<String>,
    ) -> Py<PyBytes> {
        bytes(
            py,
            keyvault_core::signing_input::participant_registration_v1(
                participant_id,
                controller_did,
                operator,
                chain_role,
                &business_types,
                &authorized_domains,
            ),
        )
    }

    #[staticmethod]
    fn operator_rotation_v1_bytes(
        py: Python<'_>,
        participant_id: u32,
        new_operator: &str,
        timestamp: u64,
    ) -> Py<PyBytes> {
        bytes(
            py,
            keyvault_core::signing_input::operator_rotation_v1(
                participant_id,
                new_operator,
                timestamp,
            ),
        )
    }

    #[staticmethod]
    fn controller_did_rotation_v1_bytes(
        py: Python<'_>,
        participant_id: u32,
        new_controller_did: &str,
        timestamp: u64,
    ) -> Py<PyBytes> {
        bytes(
            py,
            keyvault_core::signing_input::controller_did_rotation_v1(
                participant_id,
                new_controller_did,
                timestamp,
            ),
        )
    }

    #[staticmethod]
    fn delegation_authorization_v1_bytes(
        py: Python<'_>,
        vc_hash: &str,
        delegate_did: &str,
        delegate_operator: &str,
        timestamp: u64,
    ) -> Py<PyBytes> {
        bytes(
            py,
            keyvault_core::signing_input::delegation_authorization_v1(
                vc_hash,
                delegate_did,
                delegate_operator,
                timestamp,
            ),
        )
    }

    #[staticmethod]
    fn ed25519_sign_with_seed(
        py: Python<'_>,
        seed_hex: &str,
        payload: Vec<u8>,
    ) -> PyResult<Py<PyBytes>> {
        let seed = hex::decode(seed_hex)
            .map_err(|error| PyValueError::new_err(format!("invalid seed hex: {error}")))?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| PyValueError::new_err("seed must be 32 bytes"))?;
        Ok(bytes(
            py,
            keyvault_core::crypto::ed25519::sign_with_seed(&seed, &payload),
        ))
    }
}

fn parse_mode(value: &str) -> PyResult<DidSdkMode> {
    match value.to_ascii_lowercase().as_str() {
        "mock" => Ok(DidSdkMode::Mock),
        "centralized" => Ok(DidSdkMode::Centralized),
        other => Err(PyValueError::new_err(format!("invalid mode: {other}"))),
    }
}

fn server_config(participant_did: String, overrides: ConfigOverrides) -> PyResult<ServerConfig> {
    let mut config = ServerConfig::default();
    config.participant_did = participant_did;
    if let Some(mode) = overrides.mode {
        config.mode = parse_mode(&mode)?;
    }
    if let Some(path) = overrides.vc_storage_path {
        config.vc_storage_path = path;
    }
    if let Some(endpoint) = overrides.centralized_endpoint {
        config.centralized_endpoint = endpoint;
    }
    if let Some(ttl) = overrides.cache_ttl_secs {
        config.cache_ttl_secs = ttl;
    }
    if let Some(scheme) = overrides.key_vault_scheme {
        if scheme == "none" {
            config.key_vault = None;
        } else {
            let mut key_vault = config.key_vault.unwrap_or_default();
            key_vault.scheme = scheme;
            if let Some(path) = overrides.key_vault_path {
                key_vault.path = path;
            }
            if let Some(file) = overrides.key_vault_password_file {
                key_vault.password_file = file;
            }
            config.key_vault = Some(key_vault);
        }
    }
    if let Some(password) = overrides.key_vault_password {
        config.resolved_password = Some(SecretString::from(password));
    }
    Ok(config)
}

/// did-sdk Server Python 客户端。
#[pyclass]
pub struct ServerDidSdk {
    inner: Arc<did_sdk::DidSdk<did_sdk::Server>>,
    config: ServerConfig,
}

#[pymethods]
impl ServerDidSdk {
    #[new]
    #[pyo3(signature = (participant_did, **overrides))]
    fn new(participant_did: String, overrides: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let overrides = parse_overrides(overrides)?;
        let config = server_config(participant_did, overrides)?;
        let sdk = build_server_sdk(&config).map_err(to_pyerr)?;
        Ok(Self { inner: sdk, config })
    }

    #[getter]
    fn participant_did(&self) -> String {
        self.config.participant_did.clone()
    }

    #[getter]
    fn has_signer(&self) -> bool {
        self.inner.has_signer()
    }

    /// 解析 did:web。
    fn resolve_did_web<'py>(&self, py: Python<'py>, did: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let document = inner.resolve_did_web(&did).await.map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &document))
        })
    }

    /// 用外部 proof 组装 VC。
    fn assemble_vc_with_proof(
        &self,
        py: Python<'_>,
        claims: &Bound<'_, PyAny>,
        subject_did: String,
        proof: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let claims: serde_json::Value = from_py_object(claims)?;
        let proof: Proof = from_py_object(proof)?;
        let vc = self
            .inner
            .assemble_vc_with_proof(claims, &subject_did, proof)
            .map_err(to_pyerr)?;
        to_py_object(py, &vc)
    }

    /// 校验 VC。
    fn verify_vc<'py>(
        &self,
        py: Python<'py>,
        vc: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let vc: VerifiableCredential = from_py_object(vc)?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let result = inner.verify_vc(&vc).await.map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &result))
        })
    }

    fn store_vc<'py>(
        &self,
        py: Python<'py>,
        vc: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let vc: VerifiableCredential = from_py_object(vc)?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.store_vc(vc).await.map_err(to_pyerr)
        })
    }

    fn get_vc<'py>(&self, py: Python<'py>, anchor_id: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vc = inner.get_vc(&anchor_id).await.map_err(to_pyerr)?;
            Python::with_gil(|py| match vc {
                Some(vc) => Ok(to_py_object(py, &vc)?),
                None => Ok(py.None()),
            })
        })
    }

    fn list_vcs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vcs = inner.list_vcs().await.map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &vcs))
        })
    }

    fn remove_vc<'py>(&self, py: Python<'py>, anchor_id: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.remove_vc(&anchor_id).await.map_err(to_pyerr)
        })
    }

    fn build_vp<'py>(
        &self,
        py: Python<'py>,
        vcs: &Bound<'py, PyAny>,
        challenge: String,
        domain: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let vcs: Vec<VerifiableCredential> = from_py_object(vcs)?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vp = inner
                .build_vp(vcs, &challenge, &domain)
                .await
                .map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &vp))
        })
    }

    fn resolve_did(&self, py: Python<'_>, did: String) -> PyResult<Py<PyAny>> {
        match self.inner.resolve_did(&did).map_err(to_pyerr)? {
            Some(record) => to_py_object(py, &record),
            None => Ok(py.None()),
        }
    }

    /// 本地签名器签名（配置 key_vault 时）。
    #[pyo3(signature = (message, purpose = "", payload_summary = "", requestor = None))]
    fn sign_with_participant_key<'py>(
        &self,
        py: Python<'py>,
        message: Vec<u8>,
        purpose: &str,
        payload_summary: &str,
        requestor: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let purpose = purpose.to_string();
        let payload_summary = payload_summary.to_string();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let signature = inner
                .sign_with_participant_key(
                    &message,
                    did_sdk::SigningContext {
                        purpose,
                        payload_summary,
                        requestor,
                    },
                )
                .await
                .map_err(to_pyerr)?;
            Python::with_gil(|py| Ok::<_, PyErr>(bytes(py, signature.0)))
        })
    }

    /// 本地签名器签发 VC（配置 key_vault 时）。
    fn issue_self_asserted_vc<'py>(
        &self,
        py: Python<'py>,
        claims: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let claims: serde_json::Value = from_py_object(claims)?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vc = inner.issue_self_asserted_vc(claims).map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &vc))
        })
    }

    fn resolved_config(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        to_py_object(py, &self.config)
    }
}

#[pymodule]
fn _did_sdk(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<DidSdk>()?;
    module.add_class::<ServerDidSdk>()?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add("DidSdkError", py.get_type::<DidSdkError>())?;
    module.add("UserRejectedError", py.get_type::<UserRejectedError>())?;
    module.add("NotFoundError", py.get_type::<NotFoundError>())?;
    module.add(
        "InvalidArgumentError",
        py.get_type::<InvalidArgumentError>(),
    )?;
    Ok(())
}
