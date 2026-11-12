//! did-sdk Python 绑定（PyO3）。
//!
//! 初始化阶段提供可导入的最小模块；完整 API 在 P4 阶段实现。

use pyo3::prelude::*;

#[pymodule]
fn _did_sdk(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
