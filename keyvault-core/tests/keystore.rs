//! keyvault-core 公共 API 集成测试（namespace 版本）。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::Signer as _;
use keyvault_core::crypto::{
    account_id_to_ss58, blake2::blake2b256, encode_did_key, ss58_to_account_id,
};
use keyvault_core::{
    FileKeystore, KeyAlgorithm, KeyId, KeyNamespace, KeyVault, KeyVaultError, MemoryKeystore,
    PasswordSource,
};
use secrecy::SecretString;

#[tokio::test]
async fn memory_keystore_namespace_roundtrip() {
    let vault = MemoryKeystore::new();
    let client_key = vault
        .generate(KeyNamespace::ClientDid, KeyAlgorithm::Ed25519)
        .await
        .unwrap();
    assert!(client_key.0.starts_with("client-did/"));
    assert_eq!(client_key.namespace(), Some(KeyNamespace::ClientDid));
    let public = vault.public_key(&client_key).await.unwrap();
    let keyvault_core::PublicKey::Ed25519(public_bytes) = public else {
        panic!("expected ed25519");
    };
    let signature = vault.sign(&client_key, b"hello").await.unwrap();
    assert!(keyvault_core::crypto::ed25519::verify(
        &public_bytes,
        b"hello",
        &signature.0
    ));
    assert_eq!(
        vault
            .list_keys(Some(KeyNamespace::ClientDid))
            .await
            .unwrap(),
        vec![client_key.clone()]
    );

    let chain_key = vault
        .generate(KeyNamespace::ChainAccount, KeyAlgorithm::Sr25519)
        .await
        .unwrap();
    assert!(chain_key.0.starts_with("chain-account/"));
    let keyvault_core::PublicKey::Sr25519(chain_public) =
        vault.public_key(&chain_key).await.unwrap()
    else {
        panic!("expected sr25519");
    };
    let signature = vault.sign(&chain_key, b"extrinsic").await.unwrap();
    assert!(keyvault_core::crypto::sr25519::verify(
        &chain_public,
        b"extrinsic",
        &signature.0
    ));
    assert_eq!(
        vault
            .list_keys(Some(KeyNamespace::ChainAccount))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(vault.list_keys(None).await.unwrap().len(), 2);

    vault.delete(&client_key).await.unwrap();
    assert!(matches!(
        vault.load(&client_key).await,
        Err(KeyVaultError::KeyNotFound(_))
    ));
}

#[tokio::test]
async fn rejects_invalid_namespace_algorithm_combination() {
    let vault = MemoryKeystore::new();
    let error = vault
        .generate(KeyNamespace::ClientDid, KeyAlgorithm::Sr25519)
        .await
        .unwrap_err();
    assert!(matches!(error, KeyVaultError::AlgorithmMismatch { .. }));
}

#[tokio::test]
async fn sign_checked_enforces_namespace_and_algorithm() {
    let vault = MemoryKeystore::new();
    let client_key = vault
        .generate(KeyNamespace::ClientDid, KeyAlgorithm::Ed25519)
        .await
        .unwrap();
    let chain_key = vault
        .generate(KeyNamespace::ChainAccount, KeyAlgorithm::Sr25519)
        .await
        .unwrap();

    let error = vault
        .sign_checked(
            &client_key,
            b"x",
            KeyNamespace::ChainAccount,
            KeyAlgorithm::Sr25519,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, KeyVaultError::NamespaceViolation { .. }));

    let error = vault
        .sign_checked(
            &chain_key,
            b"x",
            KeyNamespace::ChainAccount,
            KeyAlgorithm::Ed25519,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, KeyVaultError::AlgorithmMismatch { .. }));

    assert!(
        vault
            .sign_checked(
                &client_key,
                b"x",
                KeyNamespace::ClientDid,
                KeyAlgorithm::Ed25519
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn file_keystore_namespace_layout_and_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys");
    let password = SecretString::from("correct horse battery staple".to_string());

    let vault = FileKeystore::new(path.clone(), password.clone()).unwrap();
    let client_key = vault
        .generate(KeyNamespace::ClientDid, KeyAlgorithm::Ed25519)
        .await
        .unwrap();
    let participant_key = vault
        .generate(KeyNamespace::ParticipantDid, KeyAlgorithm::Ed25519)
        .await
        .unwrap();
    let chain_key = vault
        .generate(KeyNamespace::ChainAccount, KeyAlgorithm::Sr25519)
        .await
        .unwrap();

    assert!(path.join("client-did").exists());
    assert!(path.join("participant-did").exists());
    assert!(path.join("chain-account").exists());
    for key in [&client_key, &participant_key, &chain_key] {
        let entry = key.local_id().unwrap();
        assert!(!entry.is_empty());
    }

    let signature = vault.sign(&client_key, b"payload").await.unwrap();
    let public = match vault.public_key(&client_key).await.unwrap() {
        keyvault_core::PublicKey::Ed25519(bytes) => bytes,
        _ => panic!("expected ed25519"),
    };
    assert!(keyvault_core::crypto::ed25519::verify(
        &public,
        b"payload",
        &signature.0
    ));

    let reopened = FileKeystore::new(path.clone(), password.clone()).unwrap();
    reopened.load(&client_key).await.unwrap();
    reopened.load(&participant_key).await.unwrap();
    reopened.load(&chain_key).await.unwrap();
    assert_eq!(reopened.list_keys(None).await.unwrap().len(), 3);
    assert_eq!(
        reopened
            .list_keys(Some(KeyNamespace::ParticipantDid))
            .await
            .unwrap()
            .len(),
        1
    );

    let wrong = FileKeystore::new(path, SecretString::from("wrong".to_string())).unwrap();
    assert!(matches!(
        wrong.load(&client_key).await,
        Err(KeyVaultError::InvalidPassword)
    ));
}

#[tokio::test]
async fn file_keystore_sign_checked_rejects_cross_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let vault = FileKeystore::new(
        dir.path().join("keys"),
        SecretString::from("password".to_string()),
    )
    .unwrap();
    let client_key = vault
        .generate(KeyNamespace::ClientDid, KeyAlgorithm::Ed25519)
        .await
        .unwrap();
    let error = vault
        .sign_checked(
            &client_key,
            b"x",
            KeyNamespace::ChainAccount,
            KeyAlgorithm::Sr25519,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, KeyVaultError::NamespaceViolation { .. }));
}

#[test]
fn did_key_roundtrip_and_rejects_bad_prefix() {
    let public = [7u8; 32];
    let did = encode_did_key(&public);
    assert!(did.starts_with("did:key:z"));
    assert_eq!(
        keyvault_core::crypto::decode_did_key_pubkey(&did).unwrap(),
        public
    );
    assert!(keyvault_core::crypto::decode_did_key_pubkey("did:key:zNotAKey").is_err());
    assert!(keyvault_core::crypto::decode_did_key_pubkey("did:example:123").is_err());
}

#[test]
fn ss58_roundtrip_and_checksum() {
    let account = [9u8; 32];
    let address = account_id_to_ss58(&account, 42);
    assert_eq!(ss58_to_account_id(&address).unwrap(), account);
    let mut corrupted = address.clone();
    corrupted.pop();
    corrupted.push('x');
    assert!(ss58_to_account_id(&corrupted).is_err());
}

#[test]
fn blake2b256_known_vector() {
    assert_eq!(
        hex::encode(blake2b256(b"abc")),
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
    );
}

#[tokio::test]
async fn password_sources() {
    let dir = tempfile::tempdir().unwrap();

    let direct = PasswordSource::Direct(SecretString::from("direct".to_string()));
    assert_eq!(
        secrecy::ExposeSecret::expose_secret(
            &keyvault_core::resolve_password(&direct).expect("direct")
        ),
        "direct"
    );

    let file = dir.path().join("password.txt");
    std::fs::write(&file, "from-file\n").unwrap();
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
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn env_password_source() {
    temp_env::with_vars([("KV_TEST_PASSWORD", Some("from-env"))], || {
        let source = PasswordSource::Env("KV_TEST_PASSWORD".into());
        let password = keyvault_core::resolve_password(&source).unwrap();
        assert_eq!(secrecy::ExposeSecret::expose_secret(&password), "from-env");
    });
}

#[tokio::test]
async fn corrupt_index_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys");
    let vault =
        FileKeystore::new(path.clone(), SecretString::from("password".to_string())).unwrap();
    vault
        .generate(KeyNamespace::ClientDid, KeyAlgorithm::Ed25519)
        .await
        .unwrap();
    std::fs::write(path.join("index.json"), b"{ not json").unwrap();
    assert!(matches!(
        FileKeystore::new(path, SecretString::from("password".to_string())),
        Err(KeyVaultError::InvalidKeyFormat(_))
    ));
}

#[tokio::test]
async fn tampered_key_file_fails_to_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys");
    let password = SecretString::from("password".to_string());
    let vault = FileKeystore::new(path.clone(), password.clone()).unwrap();
    let key_id = vault
        .generate(KeyNamespace::ClientDid, KeyAlgorithm::Ed25519)
        .await
        .unwrap();

    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("index.json")).unwrap()).unwrap();
    let file = index["keys"][0]["file"].as_str().unwrap();
    let key_path = path.join("client-did").join(file);
    let mut bytes = std::fs::read(&key_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&key_path, bytes).unwrap();

    let reopened = FileKeystore::new(path, password).unwrap();
    assert!(reopened.load(&key_id).await.is_err());
}

#[tokio::test]
async fn user_rejected_variant_exists() {
    let error = KeyVaultError::UserRejected;
    assert!(matches!(error, KeyVaultError::UserRejected));
    let _ = KeyId("client-did/test".into());
}

#[test]
fn sr25519_verify_matches_schnorrkel() {
    use schnorrkel::{ExpansionMode, MiniSecretKey, signing_context};

    let mini = MiniSecretKey::from_bytes(&[7u8; 32]).unwrap();
    let keypair = mini.expand_to_keypair(ExpansionMode::Ed25519);
    let public = keypair.public.to_bytes();
    let message = b"sr25519 message";
    let signature = keypair.sign(signing_context(b"substrate").bytes(message));
    assert!(keyvault_core::crypto::sr25519::verify(
        &public,
        message,
        &signature.to_bytes()
    ));
}

#[test]
fn fixed_seed_signature_is_deterministic() {
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
async fn index_algorithm_mismatch_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys");
    let password = SecretString::from("password".to_string());
    let vault = FileKeystore::new(path.clone(), password.clone()).unwrap();
    let key_id = vault
        .generate(KeyNamespace::ClientDid, KeyAlgorithm::Ed25519)
        .await
        .unwrap();

    let index_path = path.join("index.json");
    let mut index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
    index["keys"][0]["algorithm"] = serde_json::json!("sr25519");
    std::fs::write(&index_path, serde_json::to_vec(&index).unwrap()).unwrap();

    let reopened = FileKeystore::new(path, password).unwrap();
    assert!(matches!(
        reopened.load(&key_id).await,
        Err(KeyVaultError::InvalidKeyFormat(_))
    ));
}
