# Selective Disclosure Interoperability Contract

This document fixes the byte-level contract between `did-sdk` / `keyvault-core` and `chain-sdk`
for SD-JWT selective disclosure. Both sides must use the same primitives; no independent
implementations are permitted.

---

## 1. Disclosure

JSON array:

```json
["<base64url(salt)>", "<claim_name>", <claim_value>]
```

- `salt`: 16 bytes from a CSPRNG, base64url without padding;
- `claim_value`: strings are encoded as their raw UTF-8 bytes; non-strings use JSON serialization.

`Disclosure` lives in `did-sdk`; salt and hash primitives live in `keyvault_core::sd`.

---

## 2. `_sd` Hash

```text
H = SHA-256( base64url(salt) || base64url(name) || base64url(value) )
```

- `base64url` has no padding;
- `_sd` stores `base64url(H)`;
- `credentialSubject._sd_alg = "sha-256"`;
- each VC and each attribute has an independent 16-byte salt.

---

## 3. `vp_sd_v1` Signing Input

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

- `vc_hash`: SHA-256 **hex** of the full VC JSON;
- `disclosures_hash`: SHA-256 **hex** of the canonical disclosure array JSON;
- order of `vc_hash` matches `verifiableCredential`;
- no trailing newline.

The only implementation is `keyvault_core::signing_input::vp_sd_v1`; `chain-sdk` must call it
directly.

---

## 4. VP Shape

```json
{
  "holder": "did:key:...",
  "verifiableCredential": [ ... ],
  "challenge": "...",
  "domain": "...",
  "disclosures": [ ["salt", "name", "value"] ],
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "...",
    "jws": "..."
  }
}
```

- if `disclosures` is present (including `[]`), the holder signs with `vp_sd_v1`;
- if `disclosures` is absent, the VP is an ordinary VP signed with `vp_v1` for backward
  compatibility;
- `proof.jws` is base58btc in the POC, consistent with `did-sdk`.

---

## 5. Verification Order

1. `challenge` equals the expected value;
2. holder proof verifies over `vp_sd_v1`;
3. each VC issuer proof verifies (existing VC signature);
4. each disclosure hash matches an `_sd` entry;
5. duplicate names are rejected (`disclosure_duplicate`);
6. unsupported `_sd_alg` is rejected (`sd_alg_unsupported`);
7. anchor / revocation checks are performed by `chain-sdk` separately; `did-sdk` performs none.

---

## 6. Error Codes

| Code | Meaning |
|---|---|
| `disclosure_hash_mismatch` | recomputed hash is not in `_sd` |
| `disclosure_duplicate` | same attribute disclosed twice |
| `disclosure_missing` | requested/required disclosure is absent |
| `sd_alg_unsupported` | `_sd_alg` is not `sha-256` |

---

## 7. Privacy Boundary

SD-JWT prevents hidden-claim disclosure, forged claims, cross-VC linkage (distinct salts) and
dictionary attacks. It does **not** prevent linkability across presentations of the same VC,
colluding verifiers reconstructing attributes, or verifier retention of disclosed values.

BBS+ is not part of v0.2.0. Any future upgrade must add a new, explicitly versioned mechanism
rather than changing `vp_sd_v1`.
