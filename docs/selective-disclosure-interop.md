# 选择性披露（SD-JWT）互操作约定

本文档固定 `did-sdk` / `keyvault-core` 与 `chain-sdk` 之间的字节级约定，避免两端各自实现产生偏差。

## 1. Disclosure

JSON 数组：

```json
["<base64url(salt)>", "<claim_name>", <claim_value>]
```

- `salt`：16 字节 CSPRNG，base64url 无 padding；
- `claim_value`：字符串按原样；非字符串按 JSON 序列化。

## 2. `_sd` 哈希

```text
H = SHA-256( base64url(salt) || base64url(name) || base64url(value) )
```

- `base64url` 无 padding；
- `H` 以 base64url 写入 `credentialSubject._sd`；
- `credentialSubject._sd_alg = "sha-256"`。

## 3. VP 签名对象 `vp_sd_v1`

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

- `vc_hash_i`：完整 VC JSON 的 SHA-256 **hex**；
- `disclosures_hash`：Disclosures 数组 canonical JSON 的 SHA-256 **hex**；
- 无尾随换行；`vc_hash` 顺序与 VP `verifiableCredential` 顺序一致。

`keyvault_core::signing_input::vp_sd_v1` 是唯一实现，chain-sdk 必须直接调用。

## 4. VP 结构

```json
{
  "holder": "did:key:...",
  "verifiableCredential": [ ... ],
  "challenge": "...",
  "domain": "...",
  "disclosures": [ ["salt","name","value"] ],
  "proof": { "type": "Ed25519Signature2020", "verificationMethod": "...", "jws": "..." }
}
```

- `disclosures` 存在（即使为空）时使用 `vp_sd_v1`；
- 非选择性披露 VP 不带 `disclosures` 字段，使用 `vp_v1` 以兼容旧版。

## 5. 验证顺序

1. 校验 `challenge`；
2. 校验 holder 对 `vp_sd_v1` 的签名；
3. 校验每个 VC 的 issuer proof（现有 `VC` 签名）；
4. 对每条 Disclosure 重算哈希，必须命中某个 VC 的 `_sd`；
5. 拒绝重复属性名（`disclosure_duplicate`）；
6. 锚定/撤销由 `chain-sdk` 另行查询（`did-sdk` 不做链上查询）。

## 6. 边界

同一 VC 的跨出示可关联、跨验证方合谋拼接属性，是 SD-JWT 的固有边界，见补充附件第 5 章。
