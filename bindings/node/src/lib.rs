//! did-sdk Node 绑定（napi-rs）。
//!
//! 初始化阶段提供最小导出；完整 API 在 P5 阶段实现。

use napi_derive::napi;

/// 返回原生模块的 crate 版本，用于安装冒烟检查。
#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
