//! keyvault-core 公共 API 集成测试。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::Signer as _;
use keyvault_core::crypto::{blake2::blake2b256, decode_did_key_pubkey, encode_did_key};
use keyvault_core::{FileKeystore, KeyId, KeyVault, KeyVaultError, MemoryKeystore, PasswordSource};
use secrecy::SecretString;

#[tokio::test]
async fn memory_keystore_roundtrip() {
    let vault = MemoryKeystore::new();
    let key_id = vault.generate().await.expect("generate");
    let public = vault.public_key(&key_id).await.expect("public");
    let keyvault_core::PublicKey::Ed25519(public_bytes) = public else {
        panic!("expected ed25519");
    };
    assert_eq!(
        encode_did_key(&public_bytes),
        key_id.0,
        "did:key must round-trip"
    );

    let payload = b"hello keyvault";
    let signature = vault.sign(&key_id, payload).await.expect("sign");
    assert!(keyvault_core::crypto::ed25519::verify(
        &public_bytes,
        payload,
        &signature.0
    ));

    assert_eq!(vault.list_keys().await.expect("list"), vec![key_id.clone()]);
    vault.delete(&key_id).await.expect("delete");
    assert!(vault.list_keys().await.expect("list").is_empty());
    assert!(matches!(
        vault.load(&key_id).await,
        Err(KeyVaultError::KeyNotFound(_))
    ));
}

#[tokio::test]
async fn file_keystore_roundtrip_and_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys");
    let password = SecretString::from("correct horse battery staple".to_string());

    let vault = FileKeystore::new(path.clone(), password.clone()).expect("new");
    let key_id = vault.generate().await.expect("generate");
    let payload = b"file keystore payload";
    let signature = vault.sign(&key_id, payload).await.expect("sign");
    let public = match vault.public_key(&key_id).await.expect("public") {
        keyvault_core::PublicKey::Ed25519(bytes) => bytes,
        _ => panic!("expected ed25519"),
    };
    assert!(keyvault_core::crypto::ed25519::verify(
        &public,
        payload,
        &signature.0
    ));

    // 新实例必须能从磁盘解密并签名。
    let reopened = FileKeystore::new(path.clone(), password).expect("reopen");
    reopened
        .load(&key_id)
        .await
        .expect("load with right password");
    let signature2 = reopened.sign(&key_id, payload).await.expect("sign again");
    assert!(keyvault_core::crypto::ed25519::verify(
        &public,
        payload,
        &signature2.0
    ));

    // 错误密码必须失败。
    let wrong = FileKeystore::new(path, SecretString::from("wrong password".to_string()))
        .expect("new wrong");
    assert!(matches!(
        wrong.load(&key_id).await,
        Err(KeyVaultError::InvalidPassword)
    ));
}

#[tokio::test]
async fn file_keystore_delete_removes_file_and_index() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("keys");
    let vault =
        FileKeystore::new(path.clone(), SecretString::from("password".to_string())).expect("new");
    let key_id = vault.generate().await.expect("generate");
    vault.delete(&key_id).await.expect("delete");
    assert!(vault.list_keys().await.expect("list").is_empty());
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).expect("read index"))
            .expect("parse index");
    assert_eq!(index["keys"].as_array().map(Vec::len), Some(0));
}

#[test]
fn did_key_roundtrip_and_rejects_bad_prefix() {
    let public = [7u8; 32];
    let did = encode_did_key(&public);
    assert!(did.starts_with("did:key:z"));
    assert_eq!(decode_did_key_pubkey(&did).expect("decode"), public);
    assert!(decode_did_key_pubkey("did:key:zNotAKey").is_err());
    assert!(decode_did_key_pubkey("did:example:123").is_err());
}

#[test]
fn blake2b256_known_vector() {
    // BLAKE2b-256("abc")
    assert_eq!(
        hex::encode(blake2b256(b"abc")),
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
    );
}

#[tokio::test]
async fn password_sources() {
    let dir = tempfile::tempdir().expect("tempdir");

    let direct = PasswordSource::Direct(SecretString::from("direct".to_string()));
    assert_eq!(
        secrecy::ExposeSecret::expose_secret(
            &keyvault_core::resolve_password(&direct).expect("direct")
        ),
        "direct"
    );

    let file = dir.path().join("password.txt");
    std::fs::write(&file, "from-file\n").expect("write");
    let source = PasswordSource::File(file);
    assert_eq!(
        secrecy::ExposeSecret::expose_secret(
            &keyvault_core::resolve_password(&source).expect("file")
        ),
        "from-file"
    );

    let target = dir.path().join("auto.password");
    let source = PasswordSource::AutoGenerate {
        target_file: target.clone(),
    };
    let generated = keyvault_core::resolve_password(&source).expect("auto");
    assert!(target.exists());
    let generated_again = keyvault_core::resolve_password(&source).expect("auto again");
    assert_eq!(
        secrecy::ExposeSecret::expose_secret(&generated),
        secrecy::ExposeSecret::expose_secret(&generated_again)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&target)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn env_password_source() {
    temp_env::with_vars([("KV_TEST_PASSWORD", Some("from-env"))], || {
        let source = PasswordSource::Env("KV_TEST_PASSWORD".into());
        let password = keyvault_core::resolve_password(&source).expect("env");
        assert_eq!(secrecy::ExposeSecret::expose_secret(&password), "from-env");
    });
}

#[tokio::test]
async fn fixed_seed_signature_is_deterministic() {
    let seed = [0x11u8; 32];
    let payload = b"deterministic";
    let first = keyvault_core::crypto::ed25519::sign_with_seed(&seed, payload);
    let second = keyvault_core::crypto::ed25519::sign_with_seed(&seed, payload);
    assert_eq!(first, second);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let expected = signing_key.sign(payload).to_bytes().to_vec();
    assert_eq!(first, expected);
}

#[tokio::test]
async fn user_rejected_variant_exists() {
    // 变体本身可构造、可匹配；FileKeystore 不会返回它。
    let error = KeyVaultError::UserRejected;
    assert!(matches!(error, KeyVaultError::UserRejected));
    let _ = KeyId("did:key:zTest".into());
}

#[test]
fn sr25519_verify_matches_schnorrkel() {
    use schnorrkel::{ExpansionMode, MiniSecretKey, signing_context};

    let mini = MiniSecretKey::from_bytes(&[7u8; 32]).expect("mini secret");
    let keypair = mini.expand_to_keypair(ExpansionMode::Ed25519);
    let public = keypair.public.to_bytes();
    let message = b"sr25519 message";
    let signature = keypair.sign(signing_context(b"substrate").bytes(message));

    assert!(keyvault_core::crypto::sr25519::verify(
        &public,
        message,
        &signature.to_bytes()
    ));
    assert!(!keyvault_core::crypto::sr25519::verify(
        &public,
        b"other message",
        &signature.to_bytes()
    ));
}
