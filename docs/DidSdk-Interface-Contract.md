# DidSdk Interface Contract and Implementation Specification

| Item | Value |
|---|---|
| Document | DidSdk interface contract and implementation specification |
| Package | `did-sdk` / `did-sdk-client` / `did-sdk-server` v0.2.1 |
| Status | Implemented and released; 68 Rust tests passing; CI green |
| Audience | Client applications, `aimail-sdk`, `chain-sdk`, `chain-owner-sdk`, binding maintainers |
| Normative | This document is the single source of truth for the DidSdk contract. |

## Related Contracts

| Project | Document |
|---|---|
| did-sdk | [KeyVaultCore Interface Contract](KeyVaultCore-Interface-Contract.md) · [Selective Disclosure Interop](selective-disclosure-interop.md) |
| chain-sdk | [ChainSdk Interface Contract](https://github.com/metercai/chain-sdk/blob/main/docs/ChainSdk-Interface-Contract.md) |

---

## 1. Scope

### 1.1 Purpose

`did-sdk` is the **DID method, VC wallet and selective-disclosure contract** shared by client
applications and service-side Rust applications. It is parameterised by two modes:

- `DidSdk<Client>`: local keys, `did:key` / `did:peer`, user-confirmed signing, VC issuance;
- `DidSdk<Server>`: fixed `did:web`, VC holding/verification, optional local signer for
  development and testing.

It supports two backends: `Mock` (in-process) and `Centralized` (read-only HTTP DID resolution).

The selective-disclosure mechanism is **VC-native salted-hash selective disclosure**. The same
salted-hash construction is used inside a W3C VC/VP.

### 1.2 Responsibilities and boundaries

```text
client app / aimail-sdk            chain-sdk / chain-owner-sdk
        │ DidSdk<Client>                    │ DidSdk<Server>
        ▼                                   ▼
                 did-sdk v0.2 (this contract)
        DID methods + VC wallet + selective-disclosure disclosures
        no chain access, no anchor query, no subxt
        │ depends on
        ▼
                 keyvault-core v0.2
        KeyVault, FileKeystore, namespace isolation, SD hashing
```

| Concern | Owner |
|---|---|
| DID methods, VC issuance/storage/presentation | **did-sdk** |
| Selective-disclosure salt/hash, disclosure storage, selective VP | **did-sdk** |
| Anchor queries, anchor writes, revocation checks | **chain-sdk** |
| Participant registration, operator rotation, delegated anchoring | `chain-owner-sdk` |
| Private keys, namespace enforcement | `keyvault-core` |
| `subxt` | **chain-sdk only** |

**R1 boundary (normative).** `did-sdk` has no `Chain` backend, no `get_anchor` method and no
`subxt` / `scale-value` dependency. Signing and verification must not depend on anchor queries.

### 1.3 Non-goals

- Chain RPC, anchor existence/revocation checks, extrinsic submission.
- BBS+ or predicate proofs; salted-hash selective disclosure is the current mechanism.
- UI rendering of attribute-selection screens; the SDK exposes the selection API.
- Production HSM/device secure enclave implementations (future `keyvault-*` crates).

---

## 2. Modes and Backends

### 2.1 Runtime mode

| Mode | DID methods | Keys | VC capabilities |
|---|---|---|---|
| `Client` | `did:key`, `did:peer` | `KeyVault` (`client-did/`) | issue + hold + present + selective disclosure |
| `Server` | fixed `did:web` | production: none; dev/test: optional `FileKeystore` (`participant-did/`) | hold + assemble + verify + selective disclosure |

`Client` and `Server` are distinct Rust types. Invalid mode calls fail at compile time.

### 2.2 Backends

| Backend | DID resolution | External dependency | Use |
|---|---|---|---|
| `Mock` | in-process `DidRecord` map | none | unit tests |
| `Centralized` | `GET /dids/{did}` | centralized service (optional) | integration / staging |

`Centralized` caches DID records for `cache_ttl_secs` (default 600). It has no anchor endpoint.

### 2.3 Capability matrix

| Capability | Client | Server |
|---|---|---|
| `resolve_did` | yes | yes |
| `generate_did_key` / `generate_did_peer` | yes | no |
| `sign_with_did_key` | yes | no |
| `sign_issue_authorization` | yes | no |
| `sign_delegation_authorization` | yes | no |
| `resolve_did_key` / `resolve_did_peer` | yes | no |
| `create_did` | yes | no |
| `resolve_did_web` | no | yes |
| `issue_self_asserted_vc` | yes | local signer only |
| `issue_selective_vc` | yes | local signer only |
| `assemble_vc_with_proof` | no | yes |
| `verify_vc` | no | yes |
| `verify_vp` | no | yes |
| VC wallet | yes | yes |

---

## 3. Public Contract

### 3.1 Shared API

```rust
impl<M: SdkMode> DidSdk<M> {
    pub fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError>;

    pub async fn store_vc(&self, vc: VerifiableCredential) -> Result<(), DidSdkError>;
    pub async fn get_vc(&self, anchor_id: &str)
        -> Result<Option<VerifiableCredential>, DidSdkError>;
    pub async fn list_vcs(&self) -> Result<Vec<VerifiableCredential>, DidSdkError>;
    pub async fn remove_vc(&self, anchor_id: &str) -> Result<(), DidSdkError>;
    pub async fn build_vp(
        &self, vcs: Vec<VerifiableCredential>, challenge: &str, domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError>;

    pub async fn store_vc_with_disclosures(
        &self, vc: VerifiableCredential, disclosures: Vec<Disclosure>,
    ) -> Result<(), DidSdkError>;
    pub async fn get_vc_with_disclosures(&self, anchor_id: &str)
        -> Result<Option<(VerifiableCredential, Vec<Disclosure>)>, DidSdkError>;
    pub async fn list_disclosable_attributes(&self, anchor_id: &str)
        -> Result<Vec<String>, DidSdkError>;
    pub async fn build_vp_selective(
        &self, requests: Vec<SelectiveVpRequest>, challenge: &str, domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError>;

    pub fn set_request_handler(&self, handler: Arc<dyn ServerRequestHandler>);
}
```

`get_vc(anchor_id)` is a **local VC storage key**, not a chain anchor query.

### 3.2 Client API

```rust
impl DidSdk<Client> {
    pub fn generate_did_key(&self) -> Result<String, DidSdkError>;
    pub fn generate_did_peer(&self, numalgo: PeerNumalgo) -> Result<String, DidSdkError>;
    pub async fn sign_with_did_key(
        &self, message: &[u8], ctx: SigningContext,
    ) -> Result<Signature, DidSdkError>;
    pub fn resolve_did_key(&self, did: &str) -> Result<Ed25519PublicKey, DidSdkError>;
    pub fn resolve_did_peer(&self, did: &str) -> Result<DidDocument, DidSdkError>;
    pub fn create_did(&self) -> Result<DidRecord, DidSdkError>;

    pub fn issue_self_asserted_vc(&self, claims: serde_json::Value)
        -> Result<VerifiableCredential, DidSdkError>;
    pub fn issue_selective_vc(
        &self, claims: serde_json::Value, disclosable: &[String],
    ) -> Result<(VerifiableCredential, Vec<Disclosure>), DidSdkError>;

    pub async fn build_did_signature_header(
        &self, from: &str, anchor_id: &str, body_hash: &str, rcpt_hash: &str,
    ) -> Result<String, DidSdkError>;
    pub fn verify_did_signature_header(
        &self, header: &str, from: &str, body_hash: &str, rcpt_hash: &str,
    ) -> Result<VerifyResult, DidSdkError>;

    pub async fn sign_issue_authorization(
        &self, subject_did: &str, vc_type: &str, vc_hash: &str, timestamp: u64,
    ) -> Result<IssueAuthorizationSignature, DidSdkError>;

    pub async fn sign_delegation_authorization(
        &self, vc_hash: &str, delegate_did: &str, delegate_operator: &str, timestamp: u64,
    ) -> Result<DelegationAuthorization, DidSdkError>;
}
```

### 3.3 Server API

```rust
impl DidSdk<Server> {
    pub fn participant_did(&self) -> &str;

    pub fn has_signer(&self) -> bool;
    pub async fn sign_with_participant_key(
        &self, message: &[u8], ctx: SigningContext,
    ) -> Result<Signature, DidSdkError>;
    pub fn issue_self_asserted_vc(&self, claims: serde_json::Value)
        -> Result<VerifiableCredential, DidSdkError>;
    pub fn issue_selective_vc(
        &self, claims: serde_json::Value, disclosable: &[String],
    ) -> Result<(VerifiableCredential, Vec<Disclosure>), DidSdkError>;

    pub async fn resolve_did_web(&self, did: &str) -> Result<DidDocument, DidSdkError>;

    pub fn assemble_vc_with_proof(
        &self, claims: serde_json::Value, subject: &str, proof: Proof,
    ) -> Result<VerifiableCredential, DidSdkError>;

    pub async fn verify_vc(&self, vc: &VerifiableCredential)
        -> Result<VcVerificationResult, DidSdkError>;

    pub async fn verify_vp(
        &self, vp: &VerifiablePresentation, expected_challenge: &str,
    ) -> Result<VpVerificationResult, DidSdkError>;
}
```

**Semantics**

- `Server` never generates a DID. `participant_did` is fixed by configuration.
- Production `Server` sets `key_vault = None`; issuance uses `assemble_vc_with_proof` with an
  externally produced `Proof`.
- Development/test `Server` may load `FileKeystore` and use the local signer methods.
- `verify_vc` checks issuer resolution, issuer proof and expiration; it does **not** query anchors.
- `verify_vp` checks holder proof, challenge, VC proofs, disclosures and `_sd_alg`.

### 3.4 Data types

| Type | Normative fields |
|---|---|
| `SigningContext` | `purpose`, `payload_summary`, `requestor: Option<String>` |
| `Signature` | newtype over `Vec<u8>` |
| `Ed25519PublicKey` | newtype over `[u8; 32]` |
| `IssueAuthorizationSignature` | newtype over `Vec<u8>` |
| `DelegationAuthorization` | `version` (fixed `1`), `vc_hash`, `delegate_did`, `delegate_operator`, `timestamp: u64`, `signer_did`, `signature: Vec<u8>` |
| `DidRecord` | `did`, `method: DidMethod`, `doc_hash`, `owner`, `block_number` |
| `DidMethod` | `Key`, `Peer`, `Web` |
| `PeerNumalgo` | `Zero`, `One`, `Two` |
| `VerifyResult` | `verified`, `integrity: IntegrityStatus`, `address: AddressStatus`, `reason` |
| `VcVerificationResult` | `verified`, `issuer_resolved`, `issuer_registered`, `reason` |
| `Proof` | `type_`, `created`, `verification_method`, `jws` (base58btc POC) |
| `VerifiableCredential` | W3C fields, `credentialSubject: serde_json::Value`, `proof`, `anchor_id` |
| `VerifiablePresentation` | W3C fields, `holder`, `verifiableCredential`, `challenge`, `domain`, `disclosures`, `proof` |
| `Disclosure` | `salt` (base64url), `name`, `value: serde_json::Value` |
| `SelectiveVpRequest` | `credential: VerifiableCredential`, `disclose: Vec<String>` |
| `VpVerificationResult` | `verified`, `holder_resolved`, `credentials`, `disclosure_count`, `reason` |

Enums:

- `AddressStatus`: `Active`, `Revoked`, `Expired`, `Pending`.
- `IntegrityStatus`: `Valid`, `Invalid`, `Revoked`, `Expired`, `Unknown`.

`Disclosure` is serialised as `[salt, name, value]`.

### 3.5 Errors

| Group | Variants |
|---|---|
| Key / signing | `KeyGenerationFailed`, `SigningFailed`, `KeyNotFound`, `UserRejected`, `Timeout` |
| VC / DID | `VcNotFound`, `UnsupportedDidMethod`, `DidResolutionFailed`, `VcVerificationFailed` |
| Selective disclosure | `DisclosureHashMismatch`, `DisclosureDuplicate`, `DisclosureMissing`, `SdAlgUnsupported` |
| Backend / input | `BackendUnavailable`, `InvalidArgument`, `Unsupported`, `ConfigError` |

`UserRejected` is a first-class variant and maps 1:1 to Python `UserRejectedError` and Node
`code === "UserRejected"`.

### 3.6 Server request handler

```rust
#[async_trait]
pub trait ServerRequestHandler: Send + Sync {
    async fn on_challenge(&self, challenge: &str, requestor: &str)
        -> Result<SignatureResponse, DidSdkError>;
    async fn on_vp_request(&self, credential_types: &[String], challenge: &str)
        -> Result<VpResponse, DidSdkError>;
    async fn on_authorization_request(&self, fields: &[String], purpose: &str, requestor: &str)
        -> Result<AuthorizationResponse, DidSdkError>;
}
```

Responses contain `approved: bool` and `reason: Option<String>`; rejection maps to
`DidSdkError::UserRejected`.

### 3.7 Signing objects

`did-sdk` produces two different authorization declarations. They are not interchangeable.

| Signing object | Produced by | Purpose |
|---|---|---|
| `IssuedVc-v1` → `IssueAuthorizationSignature` | issuer (`DidSdk<Client>`) | authorise issuance of a VC |
| `DelegationAuthorization-v1` → `DelegationAuthorization` | user A / holder (`DidSdk<Client>`) | authorise a chain owner to submit an anchor on the user's behalf (path 3) |

Byte layouts (UTF-8, `\n` between lines, no trailing newline, built only by
`keyvault_core::signing_input::*`):

```text
IssuedVc-v1
{issuer_did}
{subject_did}
{vc_type}
{vc_hash}
```

```text
DelegationAuthorization-v1
{vc_hash}
{delegate_did}
{delegate_operator}
{timestamp}
```

`sign_issue_authorization(subject_did, vc_type, vc_hash, timestamp)`:

- the `timestamp` argument is **not** part of `IssuedVc-v1`; it is not a replay-protection field;
- use `sign_delegation_authorization` when a time-bound authorization is required;
- adding time binding to issuance requires a new `IssuedVc-v2`; `IssuedVc-v1` must not change.

`sign_delegation_authorization(vc_hash, delegate_did, delegate_operator, timestamp)`:

- signs `DelegationAuthorization-v1` with the active `did:key` `ClientDid`/Ed25519 key;
- requires an active `did:key`; with `did:peer` it returns
  `DidSdkError::Unsupported("delegation authorization requires did:key")`;
- validates non-empty `vc_hash` / `delegate_did` / `delegate_operator`, a `did:` prefixed
  `delegate_did`, and `timestamp > 0`; violations return `DidSdkError::InvalidArgument`;
- goes through `ServerRequestHandler::on_authorization_request` (`fields = ["DelegationAuthorization"]`,
  `purpose = "delegation"`, `requestor = delegate_did`); rejection returns `UserRejected`;
- `DelegationAuthorization` is self-contained: `signer_did` is the did:key whose public key verifies
  `signature`, so the chain owner needs no did-sdk internals.

JSON envelope (`DelegationAuthorization::to_bytes`, compact `serde_json::to_vec`):

```json
{"version":1,"vc_hash":"blake2b:<hex>","delegate_did":"did:web:...","delegate_operator":"5...","timestamp":1700000000,"signer_did":"did:key:z...","signature":[0,1,...]}
```

- the signature covers only the `DelegationAuthorization-v1` bytes above, never the JSON envelope
  (field order is therefore irrelevant to verification);
- `signature` is a raw 64-byte Ed25519 signature, JSON-encoded as an array of byte values;
- `from_bytes` re-validates `version == 1`, non-empty fields, `did:` `delegate_did`,
  `did:key:` `signer_did` and `timestamp > 0`;
- `DelegationAuthorization::verify()` re-derives the signing input and verifies it with the
  `signer_did` key (client-side self-check and tests; the chain owner must still verify independently).

### 3.8 VC hash functions

The three hash functions are exported at the crate root (`did_sdk::...`).

| Function | Drops `proof` | Drops `anchor_id` | Returns |
|---|---|---|---|
| `vc_hash_without_proof` | yes | no | lowercase hex (64 chars, no prefix) |
| `vc_hash` | no | no | lowercase hex (64 chars, no prefix) |
| `anchor_payload_hash` | yes | yes | `blake2b:<lowercase hex>` |

- all three hash the compact `serde_json::to_vec` JSON with BLAKE2b-256; field order is fixed by the
  `VerifiableCredential` struct (no canonical-JSON sorting);
- `anchor_payload_hash` is byte-identical to `chain-sdk::sd::payload_hash` (v0.1.1);
  `vc_hash_without_proof` matches the per-VC hash used by `chain-sdk::sd::vc_signing_input`, and
  `vc_hash` matches the per-VC hash used by `chain-sdk::sd::vp_signing_input`;
- `anchor_payload_hash` is the value user A signs in `DelegationAuthorization.vc_hash`; the chain
  owner recomputes it from the VC when verifying (see 8.4).

---

## 4. DID Methods

| Method | Generation / resolution | Offline proof verification | Rotation |
|---|---|---|---|
| `did:key` | client generates; decode Ed25519 key from string | yes | replace DID |
| `did:peer:0/2` | client generates; key embedded | yes | static |
| `did:peer:1` | client generates; document hash + local document | yes, with local document | static |
| `did:web` | server resolves HTTPS `did.json` | requires document | document-defined |

POC encoding:

- `did:peer:0/2`: `did:peer:<0|2>z<multibase(0xED01 || key)>`;
- `did:peer:1`: `did:peer:1z<base58btc(blake2b256(document))>`, document cached locally.

`did:web`:

- `did:web:example.com` → `https://example.com/.well-known/did.json`;
- `did:web:example.com:user:alice` → `https://example.com/user/alice/did.json`;
- percent-encoded port (`%3A`) is decoded.

---

## 5. Configuration and Construction

### 5.1 Client TOML

```toml
[did_sdk]
mode = "mock"                 # mock | centralized
subject_kind = "client"
vc_storage_path = "./vc_store"
cache_ttl_secs = 600

[did_sdk.key_vault]
scheme = "file-keystore"      # file-keystore | memory-keystore
path = "./identity-keys"
password_env = "DID_SDK_KEYVAULT_PASSWORD"

[did_sdk.centralized]
endpoint = "http://127.0.0.1:8080"
```

### 5.2 Server TOML

```toml
[did_sdk]
mode = "centralized"
subject_kind = "server"
participant_did = "did:web:issuer.example.com:mail"
vc_storage_path = "./participant-vc-store"

# enabled by default; set key_vault = None for production
[did_sdk.key_vault]
scheme = "file-keystore"
path = "./participant-keys"

[did_sdk.centralized]
endpoint = "http://127.0.0.1:8080"
```

`[did_sdk.chain]`, `DID_SDK_CHAIN_ENDPOINT` and `DID_SDK_CHAIN_PALLET` do not exist.

### 5.3 Factories

```rust
pub fn build_client_sdk(cfg: &ClientConfig) -> Result<Arc<DidSdk<Client>>, DidSdkError>;
pub fn build_server_sdk(cfg: &ServerConfig) -> Result<Arc<DidSdk<Server>>, DidSdkError>;

pub fn build_client_sdk_with_backend(
    cfg: &ClientConfig, backend: Arc<dyn Backend>, vault: Arc<dyn KeyVault>,
) -> Result<Arc<DidSdk<Client>>, DidSdkError>;
pub fn build_server_sdk_with_backend(
    cfg: &ServerConfig, backend: Arc<dyn Backend>,
) -> Result<Arc<DidSdk<Server>>, DidSdkError>;
```

`ServerConfig.key_vault` defaults to `Some(FileKeystore)`; `None` disables the local signer.

### 5.4 Environment variables

| Variable | Overrides |
|---|---|
| `DID_SDK_HOME` | root directory |
| `DID_SDK_MODE` | `mock` / `centralized` |
| `DID_SDK_CONFIG_FILE` | TOML path |
| `DID_SDK_VC_STORAGE_PATH` | VC directory |
| `DID_SDK_KEYVAULT_SCHEME` | file / memory |
| `DID_SDK_KEYVAULT_PATH` | key directory |
| `DID_SDK_KEYVAULT_PASSWORD` | password |
| `DID_SDK_KEYVAULT_PASSWORD_FILE` | password file |
| `DID_SDK_CENTRALIZED_ENDPOINT` | centralized endpoint |
| `DID_SDK_CACHE_TTL_SECS` | DID cache TTL |
| `DID_SDK_VC_STORAGE_PASSWORD` | VC encryption password when no KeyVault |

### 5.5 Distribution artifacts

| Artifact | Client | Server |
|---|---|---|
| Rust | `did-sdk-client` | `did-sdk-server` |
| Python | `did-sdk-client` (`did_sdk`) | `did-sdk-server` (`did_sdk_server`) |
| Node | `@did-sdk/client` | `@did-sdk/server` |

---

## 6. Backends

### 6.1 Mock

```rust
impl MockBackend {
    pub fn new() -> Self;
    pub fn with_auto_confirm(self) -> Self;
    pub fn with_auto_reject(self) -> Self;
    pub fn with_signing_delay(self, ms: u64) -> Self;
    pub async fn insert_did(&self, record: DidRecord);
}
```

No anchor state and no `get_anchor`.

### 6.2 Centralized

Only `GET /dids/{did}`. DID records are cached for `cache_ttl_secs`. There is no anchor preview
endpoint in `did-sdk`; anchor checks belong to `chain-sdk`.

### 6.3 R1 boundary

- No `ChainBackend`, no `DidSdkMode::Chain`.
- No `get_anchor` on `DidSdk`, `Backend` or bindings.
- No `subxt` / `scale-value` in `Cargo.toml` or the dependency tree.
- Signing and verification are independent of anchor state.

---

## 7. Key Management

| Mode | Namespace | Key type | Notes |
|---|---|---|---|
| Client | `client-did/` | Ed25519 | `FileKeystore` POC; device keystore in production |
| Server (dev/test) | `participant-did/` | Ed25519 | optional local signer |
| Server (production) | — | — | `key_vault = None`; external `Proof` |

- Private keys never leave `KeyVault`.
- Client signing is user-confirmed; rejection is `UserRejected`.
- Neither mode holds chain-account private keys or submits extrinsics.
- FileKeystore uses Argon2id + ChaCha20-Poly1305 and namespace subdirectories.

---

## 8. VC Wallet and Encryption

| Capability | Client | Server |
|---|---|---|
| `store_vc` / `get_vc` / `list_vcs` / `remove_vc` | yes | yes |
| `build_vp` | signed | signed if signer, otherwise unsigned |
| `assemble_vc_with_proof` | — | yes |
| `verify_vc` | — | yes |
| `store_vc_with_disclosures` / `get_vc_with_disclosures` | yes | yes |
| `list_disclosable_attributes` | yes | yes |
| `build_vp_selective` | yes | signed if signer |
| `verify_vp` | — | yes |

### 8.1 Encrypted storage

Each VC file:

```text
DVCS | version | nonce(12) | ciphertext | tag(16)
```

- ChaCha20-Poly1305, AAD `DVCS`;
- key derived from the KeyVault password by default;
- without a KeyVault, `DID_SDK_VC_STORAGE_PASSWORD` or auto-generated `.vc_password` (0600);
- the encrypted envelope contains `{ vc, disclosures }`;
- legacy plaintext VC files are migrated on read.

### 8.2 Selective Disclosure for VCs

#### 8.2.1 VC shape

```json
{
  "credentialSubject": {
    "id": "did:key:zHolder",
    "idCardNumber": "110101...",
    "_sd": ["<hash>", "..."],
    "_sd_alg": "sha-256"
  }
}
```

Mandatory claims stay in plaintext. Disclosable claims are removed from the subject and represented
only by salted hashes in `_sd`.

#### 8.2.2 Hash and disclosure

```text
Disclosure = [salt, name, value]
H = SHA-256( base64url(salt) || base64url(name) || base64url(value) )
```

- 16-byte CSPRNG salt per VC **and** per attribute;
- base64url without padding;
- `_sd` stores base64url(H), `_sd_alg = "sha-256"`;
- disclosures are not part of the VC body; they are stored in the same encrypted envelope.

#### 8.2.3 Issuance

```rust
let (vc, disclosures) =
    sdk.issue_selective_vc(claims, &["name".into(), "gender".into()])?;
sdk.store_vc_with_disclosures(vc, disclosures).await?;
```

Supported by `DidSdk<Client>` and by `DidSdk<Server>` when a local signer is configured.

#### 8.2.4 Presentation

```rust
let vp = sdk.build_vp_selective(
    vec![SelectiveVpRequest {
        credential: vc,
        disclose: vec!["name".into()], // empty = disclose nothing
    }],
    "challenge",
    "example.com",
).await?;
```

- only selected disclosures are sent;
- `disclosures` is present (possibly `[]`);
- holder signature uses `vp_sd_v1`:

```text
VP-SD-v1
{holder}
{challenge}
{domain}
{disclosures_hash}
{vc_hash_1}
...
```

`disclosures_hash` is SHA-256 (hex) of the canonical disclosure array; `vc_hash` is SHA-256 (hex)
of the full VC JSON. See `selective-disclosure-interop.md` for the byte-level contract.

#### 8.2.5 Verification

`verify_vp` order:

1. challenge matches;
2. holder proof over `vp_sd_v1`;
3. each VC issuer proof and expiration;
4. each disclosure hash matches an `_sd` entry;
5. reject duplicate names;
6. reject unsupported `_sd_alg`;
7. anchor/revocation checks are performed separately by `chain-sdk`.

### 8.3 Privacy boundaries

- Prevented: hidden claims, forged disclosures, cross-VC linkability, dictionary attacks.
- Not prevented: linkability across presentations of the same VC, colluding verifiers, verifier
  retention of disclosed data.
- BBS+ is not included; it is a future upgrade path for unlinkability and predicates.

### 8.4 Delegated anchoring (path 3)

User A issues a VC with `did-sdk` and authorises a chain owner to submit the anchor on the user's
behalf. `did-sdk` does not submit anchors or query chains; it only produces the self-contained
authorization that the chain owner carries to `submit_delegated_anchor`.

```rust
let now = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)?
    .as_secs(); // caller-chosen Unix seconds
let (vc, disclosures) = sdk.issue_selective_vc(claims, &["name".into()])?;
sdk.store_vc_with_disclosures(vc.clone(), disclosures).await?;

// Anchor payload hash: VC without proof / anchor_id, "blake2b:<hex>".
let vc_hash = did_sdk::anchor_payload_hash(&vc)?;

let authorization = sdk
    .sign_delegation_authorization(
        &vc_hash,
        "did:web:identity.example.com:chain-owner", // chain owner did:web
        "5GrwvaEF5zXb26Fz9rcQpDWSZ",                // chain owner SS58
        now,
    )
    .await?;
let bytes = authorization.to_bytes()?; // passed to the chain owner as authorization_signature
```

Chain-owner verification (outside `did-sdk`):

1. parse with `DelegationAuthorization::from_bytes` (or the JSON shape in 3.7);
2. verify `signature` with the `signer_did` did:key public key (`DelegationAuthorization::verify`
   may be used for a self-check);
3. check `signer_did == issuer_did`, `vc_hash` matches the submitted VC, and `timestamp` freshness;
4. check `delegate_did` / `delegate_operator` against the chain owner's own identity;
5. submit the anchor with `payload_hash = "blake2b:" + H(IssuedVc-v1 input)`.

The chain owner recomputes `anchor_payload_hash` from the VC and compares it with the signed
`vc_hash`; it never trusts unsigned fields.

---

## 9. Security Constraints

| Constraint | Requirement |
|---|---|
| Mode isolation | no illegal Client/Server calls |
| Client key isolation | keys never leave `KeyVault` |
| User confirmation | `UserRejected` on denial |
| Server production | no signing private key |
| Chain account keys | never held; no extrinsics |
| Chain queries | none; no `get_anchor` / `subxt` |
| VC encryption | `DVCS` ciphertext for VC + disclosures |
| SD signatures | `vp_sd_v1` covers VC hashes and disclosure hash |
| Delegation signatures | `DelegationAuthorization-v1` covers `vc_hash`, `delegate_did`, `delegate_operator`, `timestamp` |

---

## 10. Acceptance

### 10.1 Core contract

| ID | Criterion |
|---|---|
| D1 | Contract covers DID methods, VC wallet and selective disclosure |
| D2 | Client/Server methods are compile-time isolated |
| D3 | `mock` / `centralized` mode switching |
| D4 | Both backends have identical semantics and errors |
| D5 | `did:key`, `did:peer:0/1/2`, `did:web` |
| D6 | Mock confirm/reject/delay policies |
| D7 | Centralized performs only read-only DID GETs |
| D8 | No Chain backend and no `subxt` |
| D9 | Client keys stay in KeyVault; user confirmation |
| D10 | No chain-account private keys or extrinsics |
| D11 | `keyvault-core` integration with namespace isolation |
| D12 | One VC wallet semantic for both modes |
| D13 | Production Server holds no signing key |
| D14 | Cross-backend consistency tests |
| D15 | `verify_vc`: issuer + proof + expiration |
| D16 | `cargo tree -p did-sdk` has no `subxt` |
| D17 | No `get_anchor` / chain-query interface |
| D18 | Signing/verification do not read anchor state |
| D19 | `DelegationAuthorization` / `sign_delegation_authorization` match `DelegationAuthorization-v1`; tampering fails verification and `UserRejected` propagates |
| D20 | `anchor_payload_hash` is byte-identical to `chain-sdk::sd::payload_hash`; hash functions follow the 3.8 table |

### 10.2 Selective disclosure

| ID | Criterion |
|---|---|
| I1–I6 | Salt, `_sd`, independent salts, disclosures, encrypted delivery |
| SD-D1–D5 | Bound encrypted storage, user selection, filtering, VP field, signature coverage |
| V1–V7 | Holder/VC signatures, hash matching, hidden claims, tamper and duplicate detection |
| P1–P3 | Per-VC salt uniqueness, same-VC linkability documented, dictionary resistance |

### 10.3 Release evidence

`v0.2.1` (additive delegation authorization):

- Implementation commit: `8fe8ba3`; Rust tests: keyvault-core 28, did-sdk 68 (96 total).
- Local gates: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --locked --all-features`, `cargo doc --no-deps` — all green.
- Release tag: `v0.2.1` (annotated); `.github/workflows/release.yml` runs on tag push.

`v0.2.0` (selective disclosure):

- Implementation commit: `ffd59fd`; tests: keyvault-core 28, did-sdk 55, Python 13, Node 11.
- Release tag: `v0.2.0` (`6e1b97d`); release workflow: `43271664581`.
- CI: `ci` 43268561991, `rust-musl` 43268561636, `python` 43268561958,
  `node` 43268561892, `cross-lang` 43268561597.

---

## 11. Compatibility and Change Control

- `v0.1.0` did not contain selective disclosure; `v0.2.0` does.
- `v0.2.1` is additive over `v0.2.0`: `DelegationAuthorization`, `sign_delegation_authorization`,
  `anchor_payload_hash`, public `vc_hash` / `vc_hash_without_proof`, and
  `DelegationAuthorization::verify`. Existing signatures, wire formats and error variants are unchanged.
- `v0.1.0` used `chain` backend; R1 removed it before `v0.2.0`.
- Breaking changes require a major/minor version decision and updates to this document,
  `KeyVaultCore-Interface-Contract.md` and `selective-disclosure-interop.md`.
- The code is authoritative; this document must be updated in the same change as any public API
  modification.
