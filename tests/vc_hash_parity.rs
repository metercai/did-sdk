//! VC 哈希语义与跨仓（`chain-sdk`）golden vector 比对。
//!
//! 三个函数对 `serde_json::to_vec` 的紧凑 JSON 计算 BLAKE2b-256，
//! 字段顺序由 `VerifiableCredential` 结构体固定：
//!
//! | 函数 | 去掉 `proof` | 去掉 `anchor_id` | 返回 |
//! |---|---|---|---|
//! | `vc_hash_without_proof` | 是 | 否 | 小写 hex |
//! | `vc_hash` | 否 | 否 | 小写 hex |
//! | `anchor_payload_hash` | 是 | 是 | `blake2b:<hex>` |

#![allow(clippy::unwrap_used, clippy::expect_used)]

use did_sdk::{Proof, VerifiableCredential};
use keyvault_core::crypto::blake2::blake2b256;
use serde_json::json;

fn fixed_vc() -> VerifiableCredential {
    VerifiableCredential {
        context: vec!["https://www.w3.org/ns/credentials/v2".into()],
        id: "urn:did-sdk:vc:9f2c1a".into(),
        types: vec!["VerifiableCredential".into(), "IdentityCredential".into()],
        issuer: "did:key:z6MkFixedIssuer".into(),
        issuance_date: "2026-11-13T00:00:00Z".into(),
        expiration_date: Some("2030-11-13T00:00:00Z".into()),
        credential_subject: json!({
            "id": "did:key:z6MkFixedSubject",
            "_sd": ["sd-hash-1", "sd-hash-2"],
            "_sd_alg": "sha-256",
            "name": "Alice"
        }),
        proof: Some(Proof {
            type_: "Ed25519Signature2020".into(),
            created: 1_763_000_000,
            verification_method: "did:key:z6MkFixedIssuer#key-1".into(),
            jws: "3sigFixedValue".into(),
        }),
        anchor_id: Some("anchor-fixed-001".into()),
    }
}

/// 期望值按 `chain-sdk v0.1.1` 的 `sd::payload_hash` / `vc_signing_input` /
/// `vp_signing_input` 算法冻结：同一个 `did_sdk::VerifiableCredential` 的紧凑
/// JSON（`serde_json::to_vec`，字段顺序由结构体固定）经 BLAKE2b-256。
/// `chain-sdk` 直接复用 `did_sdk::VerifiableCredential`，因此结果逐字节相同。
const EXPECTED_WITHOUT_PROOF: &str =
    "ad0a38fe89d31c2553f863671abf043c9da481934369134d5406aa4ec367bd9e";
const EXPECTED_FULL: &str = "50a1e628e7163603bc06a2ea5187178513f05e3547c8113694e6a3d2e589a671";
const EXPECTED_ANCHOR: &str =
    "blake2b:e23b5971006782108e206879b1681831ac93835c4323c692ef4587e493ab63b4";

#[test]
fn golden_vectors() {
    let vc = fixed_vc();
    assert_eq!(
        did_sdk::vc_hash_without_proof(&vc).unwrap(),
        EXPECTED_WITHOUT_PROOF
    );
    assert_eq!(did_sdk::vc_hash(&vc).unwrap(), EXPECTED_FULL);
    assert_eq!(did_sdk::anchor_payload_hash(&vc).unwrap(), EXPECTED_ANCHOR);
}

#[test]
fn anchor_payload_hash_equals_vc_hash_of_stripped_vc() {
    let vc = fixed_vc();
    let mut stripped = vc.clone();
    stripped.proof = None;
    stripped.anchor_id = None;
    // `anchor_payload_hash` 就是“去掉 proof 与 anchor_id 后的完整 VC 哈希 + 前缀”。
    assert_eq!(
        did_sdk::anchor_payload_hash(&vc).unwrap(),
        format!("blake2b:{}", did_sdk::vc_hash(&stripped).unwrap())
    );
    assert_eq!(
        did_sdk::anchor_payload_hash(&vc).unwrap(),
        format!(
            "blake2b:{}",
            hex::encode(blake2b256(&serde_json::to_vec(&stripped).unwrap()))
        )
    );
}

#[test]
fn only_vc_hash_covers_proof() {
    let vc = fixed_vc();
    let mut without_proof = vc.clone();
    without_proof.proof = None;

    assert_ne!(
        did_sdk::vc_hash(&vc).unwrap(),
        did_sdk::vc_hash(&without_proof).unwrap(),
        "vc_hash must cover proof"
    );
    assert_ne!(
        did_sdk::vc_hash(&vc).unwrap(),
        did_sdk::vc_hash_without_proof(&vc).unwrap()
    );
    assert_eq!(
        did_sdk::vc_hash_without_proof(&vc).unwrap(),
        did_sdk::vc_hash_without_proof(&without_proof).unwrap()
    );
    assert_eq!(
        did_sdk::anchor_payload_hash(&vc).unwrap(),
        did_sdk::anchor_payload_hash(&without_proof).unwrap(),
        "anchor_payload_hash must not cover proof"
    );
}

#[test]
fn vc_hash_without_proof_covers_anchor_id_but_anchor_payload_hash_does_not() {
    let vc = fixed_vc();
    let mut reanchored = vc.clone();
    reanchored.anchor_id = Some("anchor-fixed-002".into());

    assert_ne!(
        did_sdk::vc_hash_without_proof(&vc).unwrap(),
        did_sdk::vc_hash_without_proof(&reanchored).unwrap()
    );
    assert_ne!(
        did_sdk::vc_hash(&vc).unwrap(),
        did_sdk::vc_hash(&reanchored).unwrap()
    );
    assert_eq!(
        did_sdk::anchor_payload_hash(&vc).unwrap(),
        did_sdk::anchor_payload_hash(&reanchored).unwrap()
    );
}

#[test]
fn hash_formats() {
    let vc = fixed_vc();
    for hash in [
        did_sdk::vc_hash_without_proof(&vc).unwrap(),
        did_sdk::vc_hash(&vc).unwrap(),
    ] {
        assert_eq!(hash.len(), 64);
        assert!(
            hash.chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        );
    }
    let anchor = did_sdk::anchor_payload_hash(&vc).unwrap();
    let hex_part = anchor.strip_prefix("blake2b:").expect("blake2b: prefix");
    assert_eq!(hex_part.len(), 64);
    assert!(
        hex_part
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    );
}
