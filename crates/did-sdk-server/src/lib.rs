//! did-sdk Server-mode product artifact.
//!
//! 暴露 Server 构造入口、Server/VC 类型；本地 FileKeystore 签名器可选。

pub use did_sdk::{
    DidSdk, DidSdkMode, Proof, Server, ServerConfig, SigningContext, VcVerificationResult,
    VerifiableCredential, VerifiablePresentation, build_server_sdk, build_server_sdk_with_backend,
};
