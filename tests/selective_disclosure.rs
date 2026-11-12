//! SD-JWT 选择性披露：签发、存储、筛选、VP 构造与验证。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]

use std::path::Path;

use did_sdk::{
    ClientConfig, DidSdkError, DidSdkMode, SelectiveVpRequest, ServerConfig, build_client_sdk,
    build_server_sdk,
};
use secrecy::SecretString;

fn client_config(dir: &Path) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.mode = DidSdkMode::Mock;
    config.vc_storage_path = dir.join("client-vc");
    config.key_vault.scheme = "memory-keystore".into();
    config.resolved_password = Some(SecretString::from("test".to_string()));
    config
}

fn server_config(dir: &Path) -> ServerConfig {
    let mut config = ServerConfig::default();
    config.mode = DidSdkMode::Mock;
    config.participant_did = "did:web:issuer.example.com".into();
    config.vc_storage_path = dir.join("server-vc");
    config.key_vault = None;
    config
}

#[tokio::test]
async fn issue_selective_store_and_verify_vp() {
    let dir = tempfile::tempdir().unwrap();
    let client = build_client_sdk(&client_config(dir.path())).unwrap();
    client.generate_did_key().unwrap();

    let (vc, disclosures) = client
        .issue_selective_vc(
            serde_json::json!({
                "type": "IDCardVC",
                "idCardNumber": "110101199001011234",
                "name": "张三",
                "gender": "男",
                "birthday": "1990-01-01"
            }),
            &["name".into(), "gender".into(), "birthday".into()],
        )
        .unwrap();
    assert_eq!(vc.credential_subject["_sd"].as_array().unwrap().len(), 3);
    assert_eq!(vc.credential_subject["_sd_alg"], "sha-256");
    assert!(vc.credential_subject.get("name").is_none());
    assert_eq!(disclosures.len(), 3);

    client
        .store_vc_with_disclosures(vc.clone(), disclosures.clone())
        .await
        .unwrap();
    let (stored, stored_disclosures) = client
        .get_vc_with_disclosures(vc.anchor_id.as_deref().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.id, vc.id);
    assert_eq!(stored_disclosures.len(), 3);

    let vp = client
        .build_vp_selective(
            vec![SelectiveVpRequest {
                credential: vc.clone(),
                disclose: vec!["name".into()],
            }],
            "challenge-1",
            "example.com",
        )
        .await
        .unwrap();
    let vp_disclosures = vp.disclosures.as_ref().unwrap();
    assert_eq!(vp_disclosures.len(), 1);
    assert_eq!(vp_disclosures[0].name, "name");
    assert!(vp.proof.is_some());

    let server = build_server_sdk(&server_config(dir.path())).unwrap();
    let result = server.verify_vp(&vp, "challenge-1").await.unwrap();
    assert!(result.verified, "reason: {:?}", result.reason);
    assert_eq!(result.disclosure_count, 1);
    assert!(result.credentials[0].verified);
}

#[tokio::test]
async fn empty_selection_hides_everything_but_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let client = build_client_sdk(&client_config(dir.path())).unwrap();
    client.generate_did_key().unwrap();
    let (vc, disclosures) = client
        .issue_selective_vc(
            serde_json::json!({"type": "IDCardVC", "name": "张三", "gender": "男"}),
            &["name".into(), "gender".into()],
        )
        .unwrap();
    client
        .store_vc_with_disclosures(vc.clone(), disclosures)
        .await
        .unwrap();
    let vp = client
        .build_vp_selective(
            vec![SelectiveVpRequest {
                credential: vc,
                disclose: vec![],
            }],
            "c",
            "d",
        )
        .await
        .unwrap();
    assert!(vp.disclosures.as_ref().unwrap().is_empty());
    let server = build_server_sdk(&server_config(dir.path())).unwrap();
    assert!(server.verify_vp(&vp, "c").await.unwrap().verified);
}

#[tokio::test]
async fn tampered_disclosure_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let client = build_client_sdk(&client_config(dir.path())).unwrap();
    client.generate_did_key().unwrap();
    let (vc, disclosures) = client
        .issue_selective_vc(
            serde_json::json!({"type": "IDCardVC", "name": "张三"}),
            &["name".into()],
        )
        .unwrap();
    client
        .store_vc_with_disclosures(vc.clone(), disclosures)
        .await
        .unwrap();
    let mut vp = client
        .build_vp_selective(
            vec![SelectiveVpRequest {
                credential: vc,
                disclose: vec!["name".into()],
            }],
            "c",
            "d",
        )
        .await
        .unwrap();
    vp.disclosures.as_mut().unwrap()[0].value = serde_json::json!("Mallory");
    let server = build_server_sdk(&server_config(dir.path())).unwrap();
    assert!(matches!(
        server.verify_vp(&vp, "c").await,
        Err(DidSdkError::DisclosureHashMismatch(_))
    ));
}

#[tokio::test]
async fn duplicate_selection_and_unknown_attribute_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let client = build_client_sdk(&client_config(dir.path())).unwrap();
    client.generate_did_key().unwrap();
    let (vc, disclosures) = client
        .issue_selective_vc(
            serde_json::json!({"type": "IDCardVC", "name": "张三"}),
            &["name".into()],
        )
        .unwrap();
    client
        .store_vc_with_disclosures(vc.clone(), disclosures)
        .await
        .unwrap();
    let err = client
        .build_vp_selective(
            vec![SelectiveVpRequest {
                credential: vc.clone(),
                disclose: vec!["name".into(), "name".into()],
            }],
            "c",
            "d",
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DidSdkError::DisclosureDuplicate(_)));
    let err = client
        .build_vp_selective(
            vec![SelectiveVpRequest {
                credential: vc,
                disclose: vec!["birthday".into()],
            }],
            "c",
            "d",
        )
        .await
        .unwrap_err();
    assert!(matches!(err, DidSdkError::DisclosureMissing(_)));
}
