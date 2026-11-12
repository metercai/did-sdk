//! did-sdk Client-mode product artifact.
//!
//! 只暴露 Client 构造入口；底层类型仍来自 `did-sdk` core。

pub use did_sdk::{
    Client, ClientConfig, DidSdk, DidSdkMode, SigningContext, SigningContext as Context,
    build_client_sdk, build_client_sdk_with_backend,
};
