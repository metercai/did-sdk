# KeyVaultCore Interface Contract and Implementation Specification

| Item | Value |
|---|---|
| Document | `keyvault-core` interface contract and implementation specification |
| Package | `keyvault-core` v0.2.0 |
| Status | Implemented; 28 tests passing; CI green |
| Audience | `did-sdk`, `chain-sdk`, `chain-owner-sdk`, binding maintainers |
| Normative | This document is the single source of truth for the KeyVault contract. |

## Related Contracts

| Project | Document |
|---|---|
| did-sdk | [DidSdk Interface Contract](DidSdk-Interface-Contract.md) · [Selective Disclosure Interop](selective-disclosure-interop.md) |
| chain-sdk | [ChainSdk Interface Contract](https://github.com/metercai/chain-sdk/blob/main/docs/ChainSdk-Interface-Contract.md) |

---

## 1. Scope

### 1.1 Purpose

`keyvault-core` is the shared **private-key management and signing-input contract** used by
`did-sdk`, `chain-sdk` and `chain-owner-sdk`. It provides:

- the `KeyVault` trait;
- `FileKeystore` (encrypted files) and `MemoryKeystore` (tests / mock);
- namespace and algorithm isolation;
- Ed25519 / sr25519, SS58, base58, multibase and BLAKE2 primitives;
- the selective-disclosure salt/hash primitives;
- the single implementation of all protocol signing-input byte layouts.

### 1.2 Responsibilities and boundaries

```text
did-sdk ─────────┐
chain-sdk ───────┼──► keyvault-core
chain-owner-sdk ─┘    KeyVault trait + FileKeystore + namespace + signing_input + sd
```

| Concern | Owner |
|---|---|
| Private-key storage and use | **keyvault-core** |
| Namespace / algorithm enforcement | **keyvault-core** |
| Selective-disclosure salt and salted hash | **keyvault-core** (`sd`) |
| Signing-input byte layout | **keyvault-core** (`signing_input`) |
| DID methods, VC wallet, VP construction | `did-sdk` |
| Anchor queries, chain writes | `chain-sdk` |
| Governance transactions | `chain-owner-sdk` |

`keyvault-core` has no chain access and no network dependency.

---

## 2. Namespaces, Algorithms and Key IDs

### 2.1 Namespace mapping

| Namespace | Prefix | Algorithm | Owner / use |
|---|---|---|---|
| `ChainAccount` | `chain-account/` | `Sr25519` only | chain account / extrinsic |
| `ParticipantDid` | `participant-did/` | `Ed25519` only | server participant DID / VC / assertions |
| `ClientDid` | `client-did/` | `Ed25519` only | client DID / DID-Signature / VP |

Invalid namespace × algorithm combinations are rejected with `AlgorithmMismatch`.

### 2.2 `KeyId`

```rust
pub struct KeyId(pub String);
// "{namespace_prefix}{local_id}"
// chain-account/chain-owner-operator
// participant-did/did_web_issuer_example_com
// client-did/did_key_z6Mk...
```

`KeyId::namespace()` and `KeyId::local_id()` parse the prefix.

### 2.3 Three signing entry points

The namespace gate is enforced by `sign_checked`:

| Entry point | Expected namespace | Expected algorithm |
|---|---|---|
| chain extrinsic | `ChainAccount` | `Sr25519` |
| participant assertion / VC | `ParticipantDid` | `Ed25519` |
| client DID signature / VP | `ClientDid` | `Ed25519` |

A key from one namespace cannot be used through another entry point.

---

## 3. `KeyVault` Trait

```rust
#[async_trait]
pub trait KeyVault: Send + Sync {
    async fn generate(
        &self,
        namespace: KeyNamespace,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyId, KeyVaultError>;

    async fn load(&self, key_id: &KeyId) -> Result<(), KeyVaultError>;

    async fn sign(
        &self,
        key_id: &KeyId,
        payload: &[u8],
    ) -> Result<Signature, KeyVaultError>;

    async fn public_key(&self, key_id: &KeyId) -> Result<PublicKey, KeyVaultError>;

    async fn list_keys(
        &self,
        namespace: Option<KeyNamespace>,
    ) -> Result<Vec<KeyId>, KeyVaultError>;

    async fn delete(&self, key_id: &KeyId) -> Result<(), KeyVaultError>;

    async fn sign_checked(
        &self,
        key_id: &KeyId,
        payload: &[u8],
        expected_namespace: KeyNamespace,
        expected_algorithm: KeyAlgorithm,
    ) -> Result<Signature, KeyVaultError>;
}
```

**Semantics**

- `generate` creates a keypair, persists it according to the implementation and returns its `KeyId`.
- `sign` uses the stored algorithm and namespace; it never exports the private key.
- `sign_checked` validates the key's namespace and algorithm against the caller's expectation,
  then signs. It is the only entry point used by the SDKs for namespace-sensitive signing.
- `public_key` returns an `Ed25519([u8; 32])` or `Sr25519([u8; 32])` value.
- `list_keys(None)` returns all keys; `Some(namespace)` filters by namespace.
- `delete` is supported by both current implementations.

```rust
pub enum PublicKey {
    Ed25519([u8; 32]),
    Sr25519([u8; 32]),
}

pub enum Keypair {
    Ed25519(ed25519_dalek::SigningKey),
    Sr25519(schnorrkel::SecretKey),
}
```

`Keypair` deliberately implements neither `Clone`, `Serialize` nor `Debug`.

---

## 4. Errors

| Group | Variants |
|---|---|
| Lookup / lifecycle | `KeyNotFound`, `KeyAlreadyExists`, `Locked` |
| Password / crypto | `InvalidPassword`, `DecryptionFailed`, `SigningFailed` |
| Storage / format | `IoError`, `InvalidKeyFormat`, `SerializationError` |
| Isolation | `NamespaceViolation { key, actual, expected }`, `AlgorithmMismatch { key, actual, expected }` |
| Other | `Unsupported`, `UserRejected` |

`NamespaceViolation` and `AlgorithmMismatch` are the normative isolation errors. Callers must not
degrade them into a generic signing failure.

---

## 5. `FileKeystore`

### 5.1 Layout

```text
./keystore/
├── index.json
├── chain-account/
│   └── chain-owner-operator.enc
├── participant-did/
│   └── did_web_issuer_example_com.enc
└── client-did/
    └── did_key_z6Mk....enc
```

- one namespace subdirectory per class;
- one `.enc` file per key;
- `index.json` is version 2 and records:
  `{ key_id, namespace, algorithm, file, created_at }`;
- `created_at` is Unix seconds.

### 5.2 Encrypted file format

```text
KVLT | version(1 = 0x02) | namespace(1) | algorithm(1) | salt(16) | nonce(12) |
ciphertext | tag(16)
```

- key derivation: Argon2id from the password and per-file salt;
- encryption: ChaCha20-Poly1305;
- AAD: the 23-byte header (`magic | version | namespace | algorithm | salt`);
- private key material is serialised inside the ciphertext;
- atomic write, mode `0600`.

### 5.3 Unlock and validation

`FileKeystore::new(path, password)` creates the namespace directories and loads the index.
Keys are decrypted lazily on first use. On load:

1. the index record must exist;
2. the file header namespace and algorithm must match the index;
3. decryption must succeed;
4. the Ed25519 public key must match the `did_key_...` local id when applicable.

Any mismatch is `InvalidKeyFormat` or `InvalidPassword`; it is never silently ignored.

### 5.4 Password sources

`PasswordSource` supports:

- direct secret;
- environment variable;
- password file;
- auto-generated password file (mode `0600`);
- interactive prompt (POC stdin prompt).

The password is never written into configuration files or logs.

### 5.5 `MemoryKeystore`

`MemoryKeystore` implements the same `KeyVault` trait over an in-process map. It is intended for
tests, `Mock` mode and explicit in-memory operation. It does not persist or encrypt keys.

---

## 6. Crypto Primitives

```rust
pub mod crypto {
    pub use ed25519_dalek;
    pub use schnorrkel;
    pub mod multibase;
    pub mod base58;
    pub mod blake2;

    pub fn decode_did_key_pubkey(did: &str) -> Result<[u8; 32], KeyVaultError>;
    pub fn encode_did_key(pubkey: &[u8; 32]) -> String;
    pub fn ss58_to_account_id(ss58: &str) -> Result<[u8; 32], KeyVaultError>;
    pub fn account_id_to_ss58(account_id: &[u8; 32], prefix: u16) -> String;
}
```

- `did:key` helpers are Ed25519-only and serve `participant-did/` and `client-did/`.
- SS58 helpers are sr25519-only and serve `chain-account/`.
- BLAKE2b-256/512 are used for DID/VC hashing and SS58 checksums.

---

## 7. Selective-Disclosure Utilities

```rust
pub mod sd {
    pub const SALT_LENGTH: usize = 16;

    pub fn generate_salt() -> Result<[u8; 16], KeyVaultError>;
    pub fn base64url_encode(data: &[u8]) -> String;
    pub fn base64url_decode(value: &str) -> Result<Vec<u8>, KeyVaultError>;

    pub fn disclosure_hash(
        salt: &[u8],
        name: &str,
        value: &serde_json::Value,
    ) -> Result<[u8; 32], KeyVaultError>;

    pub fn disclosure_hash_b64(
        salt_b64: &str,
        name: &str,
        value: &serde_json::Value,
    ) -> Result<[u8; 32], KeyVaultError>;

    pub fn disclosure_hash_string(
        salt: &[u8],
        name: &str,
        value: &serde_json::Value,
    ) -> Result<String, KeyVaultError>;
}
```

### 7.1 Hash formula

```text
H = SHA-256( base64url(salt) || base64url(name) || base64url(value) )
```

- `base64url` has no padding;
- strings are encoded as their raw UTF-8 bytes;
- non-string JSON values are encoded from their JSON serialization;
- `_sd` stores `base64url(H)`;
- `salt` must be a 16-byte CSPRNG value, unique per VC and per attribute.

### 7.2 Disclosure

```json
["<salt>", "<name>", <value>]
```

`Disclosure` and `_sd` construction live in `did-sdk`; `keyvault-core` supplies only the salt,
encoding and hash primitives. This keeps the cryptographic primitive in one place and the VC/VP
model in `did-sdk`.

---

## 8. Signing Inputs

`signing_input` is the **single implementation** of all protocol-level signing byte layouts.
All functions return the exact bytes to sign; no trailing newline unless stated.

| Function | Purpose | Layout summary |
|---|---|---|
| `did_signature_v1` | DID-Signature header | `DID-Signature-v1` + 6 lines |
| `issued_vc_v1` | VC issuance | `IssuedVc-v1` + issuer/subject/type/hash |
| `gateway_access_v1` | HTTP gateway auth | `GatewayAccess-v1` + DID/email/challenge |
| `vp_v1` | ordinary VP | `VP-v1` + holder/challenge/domain/VC hashes |
| `vp_sd_v1` | selective-disclosure VP | `VP-SD-v1` + holder/challenge/domain/disclosures hash/VC hashes |
| `participant_registration_v1` | participant registration | `ParticipantRegistration-v1` + fields |
| `operator_rotation_v1` | operator rotation | `OperatorRotation-v1` + participant/operator/timestamp |
| `controller_did_rotation_v1` | controller DID rotation | `ControllerDidRotation-v1` + participant/DID/timestamp |
| `delegation_authorization_v1` | delegated anchoring | `DelegationAuthorization-v1` + VC hash/delegate/operator/timestamp |

### 8.1 `vp_sd_v1`

```text
VP-SD-v1
{holder}
{challenge}
{domain}
{disclosures_hash}
{vc_hash_1}
{vc_hash_2}
...
```

- `disclosures_hash`: SHA-256 hex of the canonical disclosure array;
- `vc_hash`: SHA-256 hex of the full VC JSON;
- order of `vc_hash` matches `verifiableCredential`;
- no trailing newline.

---

## 9. SDK Integration

### 9.1 `did-sdk<Client>`

- namespace: `client-did/`;
- algorithm: `Ed25519`;
- `sign_with_did_key` → `sign_checked(..., ClientDid, Ed25519)`;
- uses `sd` and `vp_sd_v1` for selective disclosure;
- never accesses chain keys.

### 9.2 `did-sdk<Server>`

- production: no `KeyVault`; external `Proof` injection;
- development/test: optional `FileKeystore` with `participant-did/`;
- `sign_with_participant_key` → `sign_checked(..., ParticipantDid, Ed25519)`.

### 9.3 `chain-sdk` / `chain-owner-sdk`

- namespaces: `chain-account/` (sr25519) + `participant-did/` (ed25519);
- extrinsic signing uses `ChainAccount`;
- participant assertions and VC signing use `ParticipantDid`;
- governance signing uses the corresponding `signing_input` function;
- chain-sdk is the only crate that depends on `subxt`.

---

## 10. Security Constraints

| Constraint | Requirement |
|---|---|
| Private-key export | no API returns a private key |
| Namespace isolation | `sign_checked` rejects mismatches |
| Algorithm isolation | `generate` / load reject invalid combinations |
| File format | header and index must agree before use |
| Password handling | env / file / auto / prompt; never logged |
| Chain account keys | only `chain-account/`, sr25519 |
| SD salt | CSPRNG, 16 bytes, independent per VC/attribute |
| Signing input | only this crate defines byte layouts |

---

## 11. Acceptance

| ID | Criterion |
|---|---|
| K1 | Full `KeyVault` trait (generate / load / sign / sign_checked / public_key / list_keys / delete) |
| K2 | Generation writes the correct namespace directory and `.enc` file |
| K3 | Correct password unlocks; wrong password returns `InvalidPassword` |
| K4 | Signatures verify with the corresponding public key |
| K5 | No private-key export API |
| K6 | Password sources: env, file, auto-generated, prompt |
| K7 | `did:key` and SS58 primitives round-trip |
| K8 | Nine signing-input constructors match the protocol |
| K9 | Shared by `did-sdk` / Python / Node |
| K10 | Namespace and header/index consistency enforced |
| K11 | `sign_checked` rejects wrong namespace / algorithm |
| K12 | Three signing entry points are isolated |
| K13 | Signing-input fields match protocol / chain fields |

Additional SD tests:

- salt length and uniqueness;
- base64url round-trip without padding;
- hash stability and sensitivity to salt/name/value;
- `vp_sd_v1` exact layout.

---

## 12. Compatibility

- v0.2.0 storage layout is FileKeystore v2; v1 keystores are not compatible and must be regenerated.
- `MemoryKeystore` is not a persistence mechanism.
- Any change to namespace prefixes, header layout, hash formula or signing-input layout is breaking
  and requires a version bump plus updates to this document and
  `selective-disclosure-interop.md`.
