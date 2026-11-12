//! 三语言 golden vector 的 Rust 侧测试。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;

const VECTORS: &str = include_str!("vectors/signing_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("valid vector JSON")
}

fn hex_decode(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid hex")
}

#[test]
fn did_signature_v1_bytes() {
    let json = vectors();
    for case in json["did_signature_v1"].as_array().expect("array") {
        let input = &case["input"];
        let bytes = keyvault_core::signing_input::did_signature_v1(
            input["did"].as_str().unwrap(),
            input["from"].as_str().unwrap(),
            input["timestamp"].as_u64().unwrap(),
            input["anchor_ref"].as_str().unwrap(),
            input["body_hash"].as_str().unwrap(),
            input["rcpt_hash"].as_str().unwrap(),
        );
        let expected = case["expected_bytes_utf8"].as_str().unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), expected);
    }
}

#[test]
fn issued_vc_v1_bytes() {
    let json = vectors();
    for case in json["issued_vc_v1"].as_array().expect("array") {
        let input = &case["input"];
        let bytes = keyvault_core::signing_input::issued_vc_v1(
            input["issuer_did"].as_str().unwrap(),
            input["subject_did"].as_str().unwrap(),
            input["vc_type"].as_str().unwrap(),
            input["vc_hash"].as_str().unwrap(),
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            case["expected_bytes_utf8"].as_str().unwrap()
        );
    }
}

#[test]
fn vp_v1_bytes() {
    let json = vectors();
    for case in json["vp_v1"].as_array().expect("array") {
        let input = &case["input"];
        let hashes = input["vc_hashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let bytes = keyvault_core::signing_input::vp_v1(
            input["holder"].as_str().unwrap(),
            input["challenge"].as_str().unwrap(),
            input["domain"].as_str().unwrap(),
            &hashes,
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            case["expected_bytes_utf8"].as_str().unwrap()
        );
    }
}

#[test]
fn fixed_seed_signature() {
    let json = vectors();
    for case in json["fixed_seed_signature"].as_array().expect("array") {
        let seed_bytes = hex_decode(case["seed_hex"].as_str().unwrap());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let payload = case["payload_utf8"].as_str().unwrap().as_bytes();
        let signature = keyvault_core::crypto::ed25519::sign_with_seed(&seed, payload);
        assert_eq!(
            hex::encode(&signature),
            case["expected_signature_hex"].as_str().unwrap()
        );

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        assert!(keyvault_core::crypto::ed25519::verify(
            &public_key,
            payload,
            &signature
        ));
    }
}

#[test]
fn governance_signing_inputs() {
    let json = vectors();
    for case in json["participant_registration_v1"]
        .as_array()
        .expect("array")
    {
        let input = &case["input"];
        let business_types = input["business_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let authorized_domains = input["authorized_domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let bytes = keyvault_core::signing_input::participant_registration_v1(
            input["participant_id"].as_u64().unwrap() as u32,
            input["controller_did"].as_str().unwrap(),
            input["operator"].as_str().unwrap(),
            input["chain_role"].as_str().unwrap(),
            &business_types,
            &authorized_domains,
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            case["expected_bytes_utf8"].as_str().unwrap()
        );
    }
    for case in json["operator_rotation_v1"].as_array().expect("array") {
        let input = &case["input"];
        let bytes = keyvault_core::signing_input::operator_rotation_v1(
            input["participant_id"].as_u64().unwrap() as u32,
            input["new_operator"].as_str().unwrap(),
            input["timestamp"].as_u64().unwrap(),
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            case["expected_bytes_utf8"].as_str().unwrap()
        );
    }
    for case in json["controller_did_rotation_v1"]
        .as_array()
        .expect("array")
    {
        let input = &case["input"];
        let bytes = keyvault_core::signing_input::controller_did_rotation_v1(
            input["participant_id"].as_u64().unwrap() as u32,
            input["new_controller_did"].as_str().unwrap(),
            input["timestamp"].as_u64().unwrap(),
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            case["expected_bytes_utf8"].as_str().unwrap()
        );
    }
    for case in json["delegation_authorization_v1"]
        .as_array()
        .expect("array")
    {
        let input = &case["input"];
        let bytes = keyvault_core::signing_input::delegation_authorization_v1(
            input["vc_hash"].as_str().unwrap(),
            input["delegate_did"].as_str().unwrap(),
            input["delegate_operator"].as_str().unwrap(),
            input["timestamp"].as_u64().unwrap(),
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            case["expected_bytes_utf8"].as_str().unwrap()
        );
    }
}

#[test]
fn gateway_access_v1_bytes() {
    let json = vectors();
    for case in json["gateway_access_v1"].as_array().expect("array") {
        let input = &case["input"];
        let bytes = keyvault_core::signing_input::gateway_access_v1(
            input["did"].as_str().unwrap(),
            input["agent_email"].as_str().unwrap(),
            input["challenge"].as_str().unwrap(),
        );
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            case["expected_bytes_utf8"].as_str().unwrap()
        );
    }
}
