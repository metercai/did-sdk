//! did-sdk Python 绑定（PyO3 + maturin）。

#![allow(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;

use pyo3::create_exception;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict};
use serde::Serialize;
use serde::de::DeserializeOwned;

use did_sdk::config::{ConfigOverrides, resolve_config};
use did_sdk::{
    DidSdk as DidSdkTrait, DidSdkConfig, DidSdkError as CoreError, VerifiableCredential,
    build_did_sdk,
};

create_exception!(_did_sdk, DidSdkError, PyRuntimeError);
create_exception!(_did_sdk, UserRejectedError, PyRuntimeError);
create_exception!(_did_sdk, NotFoundError, PyRuntimeError);
create_exception!(_did_sdk, InvalidArgumentError, PyValueError);

fn to_pyerr(error: CoreError) -> PyErr {
    match error {
        CoreError::UserRejected => UserRejectedError::new_err("UserRejected"),
        CoreError::VcNotFound(message) | CoreError::AnchorNotFound(message) => {
            NotFoundError::new_err(message)
        }
        CoreError::InvalidArgument(message) => InvalidArgumentError::new_err(message),
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
            "chain_endpoint" => overrides.chain_endpoint = Some(value.extract()?),
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

/// did-sdk 的统一 Python 客户端。
#[pyclass]
pub struct DidSdk {
    inner: Arc<dyn DidSdkTrait>,
    config: DidSdkConfig,
}

#[pymethods]
impl DidSdk {
    /// 构造 SDK；所有关键字参数可省略，使用内置默认值。
    #[new]
    #[pyo3(signature = (**overrides))]
    fn new(overrides: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let overrides = parse_overrides(overrides)?;
        let config = resolve_config(overrides).map_err(to_pyerr)?;
        let sdk = build_did_sdk(&config).map_err(to_pyerr)?;
        Ok(Self { inner: sdk, config })
    }

    /// 生成一把新的 Ed25519 key，返回 `did:key:...`。
    fn generate_did_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.generate_did_key().await.map_err(to_pyerr)
        })
    }

    /// 用 active key 对原始消息签名，返回 bytes。
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

    /// 从 `did:key` 解析 Ed25519 公钥（32 字节）。
    fn resolve_did_key(&self, py: Python<'_>, did: &str) -> PyResult<Py<PyBytes>> {
        let key = self.inner.resolve_did_key(did).map_err(to_pyerr)?;
        Ok(bytes(py, key.0.to_vec()))
    }

    /// 创建 DID 记录，返回 dict。
    fn create_did<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let record = inner.create_did().await.map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &record))
        })
    }

    /// 解析 DID，返回 dict 或 None。
    fn resolve_did<'py>(&self, py: Python<'py>, did: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let record = inner.resolve_did(&did).await.map_err(to_pyerr)?;
            Python::with_gil(|py| match record {
                Some(record) => Ok(to_py_object(py, &record)?),
                None => Ok(py.None()),
            })
        })
    }

    /// 签发 self-asserted VC，返回 dict。
    fn issue_self_asserted_vc<'py>(
        &self,
        py: Python<'py>,
        claims: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let claims: serde_json::Value = from_py_object(claims)?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let vc = inner
                .issue_self_asserted_vc(claims)
                .await
                .map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &vc))
        })
    }

    /// 存储 VC（接受 dict 或 VC 对象）。
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

    /// 按 anchor id 获取 VC，返回 dict 或 None。
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

    /// 列出本地 VC，返回 list[dict]。
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

    /// 构造并签名 VP，返回 dict。
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

    /// 验证 DID-Signature header，返回 dict。
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

    /// 签发 VC 授权签名，返回 dict。
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
            Python::with_gil(|py| to_py_object(py, &signature))
        })
    }

    /// 获取 Anchor，返回 dict。
    fn get_anchor<'py>(&self, py: Python<'py>, anchor_id: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let anchor = inner.get_anchor(&anchor_id).await.map_err(to_pyerr)?;
            Python::with_gil(|py| to_py_object(py, &anchor))
        })
    }

    /// 返回解析后的配置 dict（密码字段不包含）。
    fn resolved_config(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        to_py_object(py, &self.config)
    }

    /// 纯函数：DID-Signature-v1 待签名字节。
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

    /// 纯函数：IssuedVc-v1 待签名字节。
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

    /// 纯函数：VP-v1 待签名字节。
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

    /// 纯函数：固定 seed 的 Ed25519 签名（golden vector / 测试用）。
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

/// 模块入口。
#[pymodule]
fn _did_sdk(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<DidSdk>()?;
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
