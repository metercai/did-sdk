//! Client 模式共享一致性断言。

#![allow(dead_code)]

use did_sdk::{Client, DidSdk, SigningContext};
use serde_json::json;

/// 对任意 Client SDK 跑同一组本地语义断言。
pub async fn assert_roundtrip(sdk: &DidSdk<Client>) {
    let created = sdk.create_did().expect("create_did");
    assert!(created.did.starts_with("did:key:z"));
    assert_eq!(
        sdk.resolve_did(&created.did).expect("resolve_did"),
        Some(created.clone())
    );

    let public = sdk.resolve_did_key(&created.did).expect("resolve_did_key");
    assert_eq!(public.0.len(), 32);

    let message = b"consistency payload";
    let signature = sdk
        .sign_with_did_key(
            message,
            SigningContext {
                purpose: "consistency".into(),
                payload_summary: "roundtrip".into(),
                requestor: Some("test".into()),
            },
        )
        .await
        .expect("sign");
    assert!(keyvault_core::crypto::ed25519::verify(
        &public.0,
        message,
        &signature.0
    ));

    let header = sdk
        .build_did_signature_header(
            "alice@example.com",
            "anchor:abc",
            "blake2b:1111",
            "blake2b:2222",
        )
        .await
        .expect("header");
    let verified = sdk
        .verify_did_signature_header(&header, "alice@example.com", "blake2b:1111", "blake2b:2222")
        .expect("verify header");
    assert!(verified.verified, "reason: {:?}", verified.reason);

    let wrong_from = sdk
        .verify_did_signature_header(&header, "bob@example.com", "blake2b:1111", "blake2b:2222")
        .expect("verify wrong from");
    assert!(!wrong_from.verified);
    let malformed = sdk
        .verify_did_signature_header("not-a-header", "alice@example.com", "b", "r")
        .expect("verify malformed");
    assert!(!malformed.verified);

    let vc = sdk
        .issue_self_asserted_vc(json!({"name": "Alice", "type": "TestCredential"}))
        .expect("issue vc");
    assert_eq!(vc.issuer, created.did);
    assert!(vc.proof.is_some());
    let anchor_id = vc.anchor_id.clone().expect("anchor id");
    sdk.store_vc(vc.clone()).await.expect("store vc");
    let loaded = sdk.get_vc(&anchor_id).await.expect("get vc").expect("vc");
    assert_eq!(loaded.id, vc.id);
    assert_eq!(loaded.proof, vc.proof);
    assert_eq!(sdk.list_vcs().await.expect("list vcs").len(), 1);

    let presentation = sdk
        .build_vp(vec![vc.clone()], "challenge-1", "example.com")
        .await
        .expect("build vp");
    assert_eq!(presentation.holder, created.did);
    assert_eq!(presentation.challenge, "challenge-1");
    assert!(presentation.proof.is_some());

    let authorization = sdk
        .sign_issue_authorization(&created.did, "TestCredential", "vc-hash", 1_700_000_000)
        .await
        .expect("authorization");
    assert_eq!(authorization.0.len(), 64);

    let delegation = sdk
        .sign_delegation_authorization(
            &did_sdk::anchor_payload_hash(&vc).expect("anchor payload hash"),
            "did:web:identity.example.com:chain-owner",
            "5GrwvaEF5zXb26Fz9rcQpDWSZ",
            1_700_000_000,
        )
        .await
        .expect("delegation authorization");
    assert_eq!(delegation.signer_did, created.did);
    delegation
        .verify()
        .expect("delegation authorization verifies");

    sdk.remove_vc(&anchor_id).await.expect("remove vc");
    assert!(sdk.get_vc(&anchor_id).await.expect("get removed").is_none());
    assert!(sdk.remove_vc(&anchor_id).await.is_err());
}
