//! `DelegationAuthorization-v1`（路径三：用户 A 委托链主代提交锚定）测试。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use did_sdk::server_request::{
    AuthorizationResponse, ServerRequestHandler, SignatureResponse, VpResponse,
};
use did_sdk::{
    Client, ClientConfig, DelegationAuthorization, DidSdk, DidSdkError, DidSdkMode, MockBackend,
    PeerNumalgo, build_client_sdk, build_client_sdk_with_backend,
};
use keyvault_core::MemoryKeystore;
use secrecy::SecretString;
use serde_json::json;

const CHAIN_DID: &str = "did:web:identity.example.com:chain-owner";
const CHAIN_OPERATOR: &str = "5GrwvaEF5zXb26Fz9rcQpDWSZ";
const TIMESTAMP: u64 = 1_700_000_000;

fn config(dir: &Path) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.mode = DidSdkMode::Mock;
    config.vc_storage_path = dir.join("vc");
    config.key_vault.scheme = "memory-keystore".into();
    config.resolved_password = Some(SecretString::from("test".to_string()));
    config
}

fn sdk(dir: &Path) -> Arc<DidSdk<Client>> {
    build_client_sdk(&config(dir)).unwrap()
}

/// 用户拒绝授权确认的 handler。
struct RejectingHandler;

#[async_trait]
impl ServerRequestHandler for RejectingHandler {
    async fn on_challenge(
        &self,
        _challenge: &str,
        _requestor: &str,
    ) -> Result<SignatureResponse, DidSdkError> {
        Ok(SignatureResponse {
            approved: false,
            reason: Some("rejected".into()),
        })
    }

    async fn on_vp_request(
        &self,
        _credential_types: &[String],
        _challenge: &str,
    ) -> Result<VpResponse, DidSdkError> {
        Ok(VpResponse {
            approved: false,
            reason: Some("rejected".into()),
        })
    }

    async fn on_authorization_request(
        &self,
        _fields: &[String],
        _purpose: &str,
        _requestor: &str,
    ) -> Result<AuthorizationResponse, DidSdkError> {
        Ok(AuthorizationResponse {
            approved: false,
            reason: Some("rejected".into()),
        })
    }
}

#[tokio::test]
async fn signs_with_active_did_key_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = sdk(dir.path());
    let did = sdk.generate_did_key().unwrap();

    let vc = sdk
        .issue_self_asserted_vc(json!({"name": "Alice", "type": "TestCredential"}))
        .unwrap();
    let vc_hash = did_sdk::anchor_payload_hash(&vc).unwrap();
    assert!(vc_hash.starts_with("blake2b:"));

    let authorization = sdk
        .sign_delegation_authorization(&vc_hash, CHAIN_DID, CHAIN_OPERATOR, TIMESTAMP)
        .await
        .unwrap();

    assert_eq!(authorization.version, 1);
    assert_eq!(authorization.vc_hash, vc_hash);
    assert_eq!(authorization.delegate_did, CHAIN_DID);
    assert_eq!(authorization.delegate_operator, CHAIN_OPERATOR);
    assert_eq!(authorization.timestamp, TIMESTAMP);
    assert_eq!(authorization.signer_did, did);
    assert_eq!(authorization.signature.len(), 64);

    // 链主侧视角：did:key 自包含公钥 + keyvault-core 的签名对象构造。
    let public_key = sdk.resolve_did_key(&authorization.signer_did).unwrap();
    let signing_input = keyvault_core::signing_input::delegation_authorization_v1(
        &vc_hash,
        CHAIN_DID,
        CHAIN_OPERATOR,
        TIMESTAMP,
    );
    assert_eq!(authorization.signing_input(), signing_input);
    assert!(keyvault_core::crypto::ed25519::verify(
        &public_key.0,
        &signing_input,
        &authorization.signature
    ));

    // 便捷自检方法。
    authorization.verify().unwrap();
}

#[test]
fn signing_input_matches_golden_vector() {
    let json: serde_json::Value =
        serde_json::from_str(include_str!("vectors/signing_vectors.json")).unwrap();
    let cases = json["delegation_authorization_v1"]
        .as_array()
        .expect("array");
    assert!(!cases.is_empty());
    for case in cases {
        let input = &case["input"];
        let authorization = DelegationAuthorization {
            version: 1,
            vc_hash: input["vc_hash"].as_str().unwrap().to_string(),
            delegate_did: input["delegate_did"].as_str().unwrap().to_string(),
            delegate_operator: input["delegate_operator"].as_str().unwrap().to_string(),
            timestamp: input["timestamp"].as_u64().unwrap(),
            signer_did: "did:key:z6MkSigner".into(),
            signature: vec![0u8; 64],
        };
        assert_eq!(
            String::from_utf8(authorization.signing_input()).unwrap(),
            case["expected_bytes_utf8"].as_str().unwrap()
        );
    }
}

#[test]
fn fixed_seed_signature_is_deterministic() {
    let mut seed = [0u8; 32];
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let signer_did = keyvault_core::crypto::encode_did_key(&public_key);

    let signing_input = keyvault_core::signing_input::delegation_authorization_v1(
        "blake2b:fixed-vc-hash",
        CHAIN_DID,
        CHAIN_OPERATOR,
        1_700_000_001,
    );
    let signature = keyvault_core::crypto::ed25519::sign_with_seed(&seed, &signing_input);
    let authorization = DelegationAuthorization {
        version: 1,
        vc_hash: "blake2b:fixed-vc-hash".into(),
        delegate_did: CHAIN_DID.into(),
        delegate_operator: CHAIN_OPERATOR.into(),
        timestamp: 1_700_000_001,
        signer_did,
        signature,
    };
    authorization.verify().unwrap();

    // 同一输入重复签名逐字节一致。
    let again = keyvault_core::crypto::ed25519::sign_with_seed(&seed, &signing_input);
    assert_eq!(authorization.signature, again);
}

#[tokio::test]
async fn tampered_fields_fail_verification() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = sdk(dir.path());
    sdk.generate_did_key().unwrap();
    let authorization = sdk
        .sign_delegation_authorization("blake2b:abc", CHAIN_DID, CHAIN_OPERATOR, TIMESTAMP)
        .await
        .unwrap();
    authorization.verify().unwrap();

    let mut tampered = authorization.clone();
    tampered.vc_hash = "blake2b:abcd".into();
    assert!(tampered.verify().is_err());

    let mut tampered = authorization.clone();
    tampered.delegate_did = "did:web:identity.example.com:other-owner".into();
    assert!(tampered.verify().is_err());

    let mut tampered = authorization.clone();
    tampered.delegate_operator = "5OtherOperator".into();
    assert!(tampered.verify().is_err());

    let mut tampered = authorization.clone();
    tampered.timestamp += 1;
    assert!(tampered.verify().is_err());

    let mut tampered = authorization.clone();
    tampered.signature[0] ^= 0x01;
    assert!(tampered.verify().is_err());

    // JSON 外壳不参与签名：等价内容的字段顺序变化不影响验签。
    let as_value: serde_json::Value = serde_json::to_value(&authorization).unwrap();
    let reordered: DelegationAuthorization = serde_json::from_value(as_value).unwrap();
    reordered.verify().unwrap();
}

#[tokio::test]
async fn invalid_arguments_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = sdk(dir.path());
    sdk.generate_did_key().unwrap();

    for (vc_hash, delegate_did, delegate_operator, timestamp) in [
        ("", CHAIN_DID, CHAIN_OPERATOR, TIMESTAMP),
        ("blake2b:abc", "", CHAIN_OPERATOR, TIMESTAMP),
        ("blake2b:abc", "not-a-did", CHAIN_OPERATOR, TIMESTAMP),
        ("blake2b:abc", CHAIN_DID, "", TIMESTAMP),
        ("blake2b:abc", CHAIN_DID, CHAIN_OPERATOR, 0),
    ] {
        let error = sdk
            .sign_delegation_authorization(vc_hash, delegate_did, delegate_operator, timestamp)
            .await
            .unwrap_err();
        assert!(
            matches!(error, DidSdkError::InvalidArgument(_)),
            "unexpected error: {error:?}"
        );
    }
}

#[tokio::test]
async fn did_peer_signer_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = sdk(dir.path());
    let peer = sdk.generate_did_peer(PeerNumalgo::Zero).unwrap();
    assert!(peer.starts_with("did:peer:"));

    let error = sdk
        .sign_delegation_authorization("blake2b:abc", CHAIN_DID, CHAIN_OPERATOR, TIMESTAMP)
        .await
        .unwrap_err();
    match error {
        DidSdkError::Unsupported(message) => {
            assert_eq!(message, "delegation authorization requires did:key");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn json_roundtrip_and_validation() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = sdk(dir.path());
    sdk.generate_did_key().unwrap();
    let authorization = sdk
        .sign_delegation_authorization("blake2b:roundtrip", CHAIN_DID, CHAIN_OPERATOR, TIMESTAMP)
        .await
        .unwrap();

    let bytes = authorization.to_bytes().unwrap();
    let parsed = DelegationAuthorization::from_bytes(&bytes).unwrap();
    assert_eq!(parsed, authorization);
    parsed.verify().unwrap();

    // `signature` 以字节数组编码，链主可无损解析。
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["signature"].as_array().unwrap().len(), 64);
    assert_eq!(value["version"].as_u64().unwrap(), 1);

    // 拒绝 version != 1。
    let mut wrong_version = value.clone();
    wrong_version["version"] = json!(2);
    let error = DelegationAuthorization::from_bytes(&serde_json::to_vec(&wrong_version).unwrap())
        .unwrap_err();
    assert!(matches!(error, DidSdkError::InvalidArgument(_)));

    // 拒绝空 signer_did。
    let mut empty_signer = value.clone();
    empty_signer["signer_did"] = json!("");
    let error = DelegationAuthorization::from_bytes(&serde_json::to_vec(&empty_signer).unwrap())
        .unwrap_err();
    assert!(matches!(error, DidSdkError::InvalidArgument(_)));

    // 拒绝 did:peer signer。
    let mut peer_signer = value.clone();
    peer_signer["signer_did"] = json!("did:peer:0z6MkPeer");
    let error = DelegationAuthorization::from_bytes(&serde_json::to_vec(&peer_signer).unwrap())
        .unwrap_err();
    assert!(matches!(error, DidSdkError::InvalidArgument(_)));

    // 拒绝无法解析的字节。
    assert!(DelegationAuthorization::from_bytes(b"not json").is_err());
}

#[tokio::test]
async fn user_rejection_propagates() {
    let dir = tempfile::tempdir().unwrap();
    let sdk = sdk(dir.path());
    sdk.set_request_handler(Arc::new(RejectingHandler));
    sdk.generate_did_key().unwrap();
    let error = sdk
        .sign_delegation_authorization("blake2b:abc", CHAIN_DID, CHAIN_OPERATOR, TIMESTAMP)
        .await
        .unwrap_err();
    assert!(matches!(error, DidSdkError::UserRejected));

    let dir = tempfile::tempdir().unwrap();
    let rejecting = build_client_sdk_with_backend(
        &config(dir.path()),
        Arc::new(MockBackend::new().with_auto_reject()),
        Arc::new(MemoryKeystore::new()),
    )
    .unwrap();
    rejecting.generate_did_key().unwrap();
    let error = rejecting
        .sign_delegation_authorization("blake2b:abc", CHAIN_DID, CHAIN_OPERATOR, TIMESTAMP)
        .await
        .unwrap_err();
    assert!(matches!(error, DidSdkError::UserRejected));
}
