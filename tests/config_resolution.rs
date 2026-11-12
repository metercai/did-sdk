//! 配置解析测试：默认值、环境变量、TOML、显式覆盖、密码优先级。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use did_sdk::{ConfigOverrides, DidSdkConfig, DidSdkError, DidSdkMode, resolve_config};
use secrecy::ExposeSecret;
use serial_test::serial;

const KEYS: &[&str] = &[
    "DID_SDK_HOME",
    "DID_SDK_MODE",
    "DID_SDK_CONFIG_FILE",
    "DID_SDK_VC_STORAGE_PATH",
    "DID_SDK_KEYVAULT_SCHEME",
    "DID_SDK_KEYVAULT_PATH",
    "DID_SDK_KEYVAULT_PASSWORD",
    "DID_SDK_KEYVAULT_PASSWORD_FILE",
    "DID_SDK_CENTRALIZED_ENDPOINT",
    "DID_SDK_CACHE_TTL_SECS",
];

fn env(
    home: &Path,
    overrides: &[(&'static str, Option<&str>)],
) -> Vec<(&'static str, Option<String>)> {
    let mut map: BTreeMap<&'static str, Option<String>> =
        KEYS.iter().map(|key| (*key, None)).collect();
    map.insert("DID_SDK_HOME", Some(home.to_string_lossy().into_owned()));
    for (key, value) in overrides {
        map.insert(key, value.map(str::to_string));
    }
    map.into_iter().collect()
}

#[test]
#[serial]
fn defaults_when_nothing_set() {
    let dir = tempfile::tempdir().unwrap();
    temp_env::with_vars(env(dir.path(), &[]), || {
        let config = resolve_config(ConfigOverrides::default()).unwrap();
        assert_eq!(config.mode, DidSdkMode::Mock);
        assert_eq!(config.key_vault.scheme, "file-keystore");
        assert_eq!(config.cache_ttl_secs, 600);
        assert_eq!(config.centralized_endpoint, "http://127.0.0.1:8080");
        assert!(config.vc_storage_path.starts_with(dir.path()));
        assert!(config.key_vault.path.starts_with(dir.path()));
        assert!(config.resolved_password.is_some());
        // 默认允许自动生成，密码文件应被创建。
        assert!(config.key_vault.password_file.exists());
    });
}

#[test]
#[serial]
fn env_overrides_defaults() {
    let dir = tempfile::tempdir().unwrap();
    temp_env::with_vars(
        env(
            dir.path(),
            &[
                ("DID_SDK_MODE", Some("centralized")),
                ("DID_SDK_CENTRALIZED_ENDPOINT", Some("http://example.test")),
                ("DID_SDK_CACHE_TTL_SECS", Some("42")),
                ("DID_SDK_KEYVAULT_SCHEME", Some("memory-keystore")),
            ],
        ),
        || {
            let config = resolve_config(ConfigOverrides::default()).unwrap();
            assert_eq!(config.mode, DidSdkMode::Centralized);
            assert_eq!(config.centralized_endpoint, "http://example.test");
            assert_eq!(config.cache_ttl_secs, 42);
            assert_eq!(config.key_vault.scheme, "memory-keystore");
        },
    );
}

#[test]
#[serial]
fn explicit_overrides_beat_env() {
    let dir = tempfile::tempdir().unwrap();
    temp_env::with_vars(
        env(dir.path(), &[("DID_SDK_MODE", Some("centralized"))]),
        || {
            let config = resolve_config(ConfigOverrides {
                mode: Some("mock".into()),
                cache_ttl_secs: Some(7),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(config.mode, DidSdkMode::Mock);
            assert_eq!(config.cache_ttl_secs, 7);
        },
    );
}

#[test]
#[serial]
fn partial_toml_keeps_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("did-sdk.toml");
    std::fs::write(
        &config_path,
        r#"
mode = "centralized"
centralized_endpoint = "http://toml.test"

[key_vault]
scheme = "memory-keystore"
"#,
    )
    .unwrap();

    temp_env::with_vars(
        env(
            dir.path(),
            &[("DID_SDK_CONFIG_FILE", Some(config_path.to_str().unwrap()))],
        ),
        || {
            let config = resolve_config(ConfigOverrides::default()).unwrap();
            assert_eq!(config.mode, DidSdkMode::Centralized);
            assert_eq!(config.centralized_endpoint, "http://toml.test");
            assert_eq!(config.key_vault.scheme, "memory-keystore");
            // 未在 TOML 中出现的字段保持默认值。
            assert_eq!(config.cache_ttl_secs, 600);
            assert!(config.vc_storage_path.starts_with(dir.path()));
        },
    );
}

#[test]
#[serial]
fn password_precedence_env_file_auto() {
    let dir = tempfile::tempdir().unwrap();
    let password_file = dir.path().join("password.txt");
    std::fs::write(&password_file, "file-pass\n").unwrap();
    let password_file_str = password_file.to_str().unwrap();

    // 文件优先于自动生成。
    temp_env::with_vars(
        env(
            dir.path(),
            &[("DID_SDK_KEYVAULT_PASSWORD_FILE", Some(password_file_str))],
        ),
        || {
            let config = resolve_config(ConfigOverrides::default()).unwrap();
            assert_eq!(
                config.resolved_password.as_ref().unwrap().expose_secret(),
                "file-pass"
            );
        },
    );

    // 环境变量优先于文件。
    temp_env::with_vars(
        env(
            dir.path(),
            &[
                ("DID_SDK_KEYVAULT_PASSWORD_FILE", Some(password_file_str)),
                ("DID_SDK_KEYVAULT_PASSWORD", Some("env-pass")),
            ],
        ),
        || {
            let config = resolve_config(ConfigOverrides::default()).unwrap();
            assert_eq!(
                config.resolved_password.as_ref().unwrap().expose_secret(),
                "env-pass"
            );
        },
    );

    // 显式 override 优先于环境变量。
    temp_env::with_vars(
        env(
            dir.path(),
            &[
                ("DID_SDK_KEYVAULT_PASSWORD_FILE", Some(password_file_str)),
                ("DID_SDK_KEYVAULT_PASSWORD", Some("env-pass")),
            ],
        ),
        || {
            let config = resolve_config(ConfigOverrides {
                key_vault_password: Some("explicit-pass".into()),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(
                config.resolved_password.as_ref().unwrap().expose_secret(),
                "explicit-pass"
            );
        },
    );
}

#[test]
#[serial]
fn auto_generate_password_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let password_file = dir.path().join("new.password");
    temp_env::with_vars(
        env(
            dir.path(),
            &[(
                "DID_SDK_KEYVAULT_PASSWORD_FILE",
                Some(password_file.to_str().unwrap()),
            )],
        ),
        || {
            let config = resolve_config(ConfigOverrides::default()).unwrap();
            assert!(password_file.exists());
            let generated = std::fs::read_to_string(&password_file).unwrap();
            assert_eq!(
                config.resolved_password.as_ref().unwrap().expose_secret(),
                generated.trim()
            );
        },
    );
}

#[test]
#[serial]
fn auto_generate_can_be_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("did-sdk.toml");
    std::fs::write(
        &config_path,
        r#"
[key_vault]
allow_auto_generate_password = false
"#,
    )
    .unwrap();
    let missing_password = dir.path().join("missing.password");
    temp_env::with_vars(
        env(
            dir.path(),
            &[
                ("DID_SDK_CONFIG_FILE", Some(config_path.to_str().unwrap())),
                (
                    "DID_SDK_KEYVAULT_PASSWORD_FILE",
                    Some(missing_password.to_str().unwrap()),
                ),
            ],
        ),
        || {
            let result = resolve_config(ConfigOverrides::default());
            assert!(matches!(result, Err(DidSdkError::ConfigError(_))));
        },
    );
}

#[test]
#[serial]
fn invalid_mode_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    temp_env::with_vars(
        env(dir.path(), &[("DID_SDK_MODE", Some("not-a-mode"))]),
        || {
            let config = resolve_config(ConfigOverrides::default()).unwrap();
            assert_eq!(config.mode, DidSdkMode::Mock);
        },
    );
}

#[test]
#[serial]
fn chain_mode_is_rejected_as_invalid() {
    let dir = tempfile::tempdir().unwrap();
    temp_env::with_vars(env(dir.path(), &[("DID_SDK_MODE", Some("chain"))]), || {
        let config = resolve_config(ConfigOverrides::default()).unwrap();
        assert_eq!(config.mode, DidSdkMode::Mock);
    });
}

#[test]
#[serial]
fn defaults_are_stable() {
    let config = DidSdkConfig::default();
    assert_eq!(config.mode, DidSdkMode::Mock);
    assert_eq!(config.key_vault.scheme, "file-keystore");
}

#[test]
#[serial]
fn invalid_toml_is_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("bad.toml");
    std::fs::write(&config_path, "mode = [").unwrap();
    temp_env::with_vars(
        env(
            dir.path(),
            &[("DID_SDK_CONFIG_FILE", Some(config_path.to_str().unwrap()))],
        ),
        || {
            assert!(matches!(
                resolve_config(ConfigOverrides::default()),
                Err(DidSdkError::ConfigError(_))
            ));
        },
    );
}

#[test]
#[serial]
fn missing_config_file_falls_back_to_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.toml");
    temp_env::with_vars(
        env(
            dir.path(),
            &[("DID_SDK_CONFIG_FILE", Some(missing.to_str().unwrap()))],
        ),
        || {
            let config = resolve_config(ConfigOverrides::default()).unwrap();
            assert_eq!(config.mode, DidSdkMode::Mock);
        },
    );
}

#[test]
#[serial]
fn empty_password_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let password_file = dir.path().join("empty.password");
    std::fs::write(&password_file, "\n").unwrap();
    temp_env::with_vars(
        env(
            dir.path(),
            &[(
                "DID_SDK_KEYVAULT_PASSWORD_FILE",
                Some(password_file.to_str().unwrap()),
            )],
        ),
        || {
            assert!(matches!(
                resolve_config(ConfigOverrides::default()),
                Err(DidSdkError::ConfigError(_))
            ));
        },
    );
}

#[test]
#[serial]
fn empty_env_password_falls_back_to_file() {
    let dir = tempfile::tempdir().unwrap();
    let password_file = dir.path().join("password.txt");
    std::fs::write(&password_file, "file-pass\n").unwrap();
    temp_env::with_vars(
        env(
            dir.path(),
            &[
                ("DID_SDK_KEYVAULT_PASSWORD", Some("")),
                (
                    "DID_SDK_KEYVAULT_PASSWORD_FILE",
                    Some(password_file.to_str().unwrap()),
                ),
            ],
        ),
        || {
            let config = resolve_config(ConfigOverrides::default()).unwrap();
            assert_eq!(
                config.resolved_password.as_ref().unwrap().expose_secret(),
                "file-pass"
            );
        },
    );
}

#[test]
#[serial]
fn nested_did_sdk_toml_is_supported() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("nested.toml");
    std::fs::write(
        &config_path,
        r#"
[did_sdk]
mode = "centralized"
subject_kind = "client"
vc_storage_path = "./nested-vc"
cache_ttl_secs = 12

[did_sdk.key_vault]
scheme = "memory-keystore"

[did_sdk.centralized]
endpoint = "http://nested.test"
"#,
    )
    .unwrap();
    temp_env::with_vars(
        env(
            dir.path(),
            &[("DID_SDK_CONFIG_FILE", Some(config_path.to_str().unwrap()))],
        ),
        || {
            let config = resolve_config(ConfigOverrides::default()).unwrap();
            assert_eq!(config.mode, DidSdkMode::Centralized);
            assert_eq!(config.centralized_endpoint, "http://nested.test");
            assert_eq!(config.cache_ttl_secs, 12);
            assert_eq!(config.key_vault.scheme, "memory-keystore");
            assert_eq!(config.vc_storage_path, PathBuf::from("./nested-vc"));
        },
    );
}
