//! 最小可执行示例：生成 did:key、签一段字节、打印结果。

use did_sdk::config::resolve_config;
use did_sdk::{SigningContext, build_client_sdk};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = resolve_config(Default::default())?;
    let sdk = build_client_sdk(&config)?;

    let did = sdk.generate_did_key()?;
    let signature = sdk
        .sign_with_did_key(
            b"hello static world",
            SigningContext {
                purpose: "smoke".into(),
                payload_summary: "static".into(),
                requestor: None,
            },
        )
        .await?;

    println!("did={did}\nsig_len={}", signature.0.len());
    Ok(())
}
