# VC 选择性披露特性补充附件
## 基于 SD-JWT 盐化哈希机制，对现有 DID+VC 信任链的扩展

> **实现状态（2026-11-13）**：已落地于 `did-sdk` / `keyvault-core`：
> `_sd`/`_sd_alg`、Disclosure、16 字节盐、SD-JWT 哈希、加密绑定存储、
> 选择性 VP 构造与 `verify_vp`；`vp_sd_v1` 签名对象。
> `chain-sdk` 的 Issuer/Verifier 扩展由同期的 chain-sdk 实施承接。

## 0. 文档定位

### 0.1 目的

本附件定义如何在**不修改链上锚定原语、不修改发行方注册机制、不修改撤销机制**的前提下，为现有 DID+VC 信任链增加**可验证凭证的选择性披露（Selective Disclosure）能力**。

应用场景示例：身份证 VC 包含姓名、生日、性别、血型、民族、出生地等属性。持有者向验证方出示时，可以只披露姓名和性别，其余属性对验证方**完全不可见**，同时验证方仍能确认被披露属性是发行方真实签发且未被篡改。

### 0.2 与主规范的关系

| 主规范内容 | 本附件的关系 |
|---|---|
| `AnchorRecord` 通用锚定原语 | **不变**——链上仍只存 VC 整体哈希 |
| `EmailBinding` / `DomainControl` 锚定类型 | **不变** |
| `DID-Signature` / `DID-Auth-Results` 邮件头 | **不变** |
| `revoked` / `valid_until` 生命周期语义 | **不变** |
| VC 原文结构（`credentialSubject`） | **扩展**——增加 `_sd` 和 `_sd_alg` 字段 |
| 发行方签发流程 | **扩展**——增加盐化哈希生成和 Disclosures 交付 |
| 持有者出示流程 | **扩展**——增加按用户选择筛选 Disclosure |
| 验证方验证流程 | **扩展**——增加 Disclosure 哈希比对 |

### 0.3 设计原则

1. **最小侵入**：链上锚定层零改动，只在 VC 原文结构和 SDK 能力上扩展。
2. **标准对齐**：盐化哈希和 Disclosure 的计算方式完全遵循 SD-JWT（RFC 9901 / SD-JWT VC 草案），不发明新密码学。
3. **验证方独立验证**：Disclosure 哈希比对是纯本地计算，不依赖发行方在线服务。
4. **诚实披露边界**：明确选择性披露能防什么、不能防什么，不夸大隐私保证。
5. **渐进升级**：当前实现 SD-JWT 机制；未来如需更强的不可关联性，平滑升级到 BBS+。

---

## 1. 改进后的 VC 结构

### 1.1 签发时的 VC 原文

在现有 W3C VC 外壳的 `credentialSubject` 内部，用"明文与哈希混排"的方式表达哪些属性可选择性披露。

**示例：身份证 VC（发行方签发时）**

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "IDCardVC"],
  "issuer": "did:key:z6MkIssuer...",
  "issuanceDate": "2026-01-01T00:00:00Z",
  "expirationDate": "2036-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkHolder...",
    "idCardNumber": "110101199001011234",
    "_sd": [
      "pFndZ4Yx2kQ9...",
      "hT7mN3sK8wL2...",
      "xR5vB9cF1jD6...",
      "qW2eT4yU7iO8...",
      "nM6bV1xC3zA9...",
      "kL8jH5gF2dS4..."
    ],
    "_sd_alg": "sha-256"
  },
  "credentialStatus": {
    "type": "AnchorStatus",
    "anchorId": "anchor-idcard-001"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:key:z6MkIssuer...#key-1",
    "proofValue": "..."
  }
}
```

### 1.2 字段说明

| 字段 | 位置 | 说明 |
|---|---|---|
| `idCardNumber` | `credentialSubject` 明文 | **必须披露的属性**，直接以明文存在 |
| `_sd` | `credentialSubject` 数组 | **可选择性披露属性**的盐化哈希列表 |
| `_sd_alg` | `credentialSubject` | 哈希算法标识，当前固定为 `sha-256` |
| `proof` | VC 顶层 | 发行方对**整个 VC JSON**（含 `_sd`）的签名 |

**`_sd` 数组中每个哈希的计算方式**：

```text
H_i = SHA-256( base64url(salt_i) || base64url(claim_name_i) || base64url(claim_value_i) )
```

其中 `||` 表示字符串拼接，`base64url` 编码不带 padding。

### 1.3 Disclosures（伴随数据，不放入 VC 原文）

发行方为每个可披露属性生成一条 Disclosure，格式为：

```json
[salt, claim_name, claim_value]
```

身份证 VC 的完整 Disclosures 集合示例：

```json
[
  ["a1b2c3d4e5f6...", "name", "张三"],
  ["b2c3d4e5f6a1...", "gender", "男"],
  ["c3d4e5f6a1b2...", "birthday", "1990-01-01"],
  ["d4e5f6a1b2c3...", "blood_type", "A"],
  ["e5f6a1b2c3d4...", "ethnicity", "汉族"],
  ["f6a1b2c3d4e5...", "birth_place", "北京"]
]
```

**Disclosures 不放入 VC 原文**，由发行方在签发后单独交付给持有者，持有者本地加密存储。这样：

- VC 原文在链上锚定时，哈希的是**不含 Disclosures 的完整 VC JSON**，链上锚定逻辑无需任何改动；
- Disclosures 的泄露不会影响 VC 本身的完整性（VC 签名只覆盖哈希，不覆盖原文值）。

### 1.4 每个 VC、每个属性独立随机盐

发行方签发时，为**每张 VC 的每个可披露属性**生成独立的随机盐（建议 16 字节以上，使用 CSPRNG）。

**作用**：
- **防止跨 VC 关联**：同一主体持有的身份证 VC 和驾照 VC，即使都有 `name` 属性，盐不同则哈希不同，验证方无法通过哈希判断"这两张 VC 属于同一个人"；
- **防止字典攻击**：哈希 `SHA-256("男")` 可被穷举，加盐后 `SHA-256(salt || "男")` 不可反推。

**明确边界**：独立随机盐**不能**防止"同一张 VC 的跨出示关联"——同一张身份证 VC 的 `name` 属性盐在签发时固定，多次出示时哈希不变，验证方之间合谋仍可判断"这两次出示来自同一张 VC"。这是 SD-JWT 机制的固有边界，见第 5 章。

---

## 2. 签发流程（发行方侧）

### 2.1 流程

```text
1. 发行方决定哪些属性可选择性披露（如 name、gender、birthday 等）
2. 发行方决定哪些属性必须披露（如 id、idCardNumber），保持明文
3. 对每个可披露属性：
   a. 生成 16 字节随机盐 salt_i
   b. 计算 H_i = SHA-256(base64url(salt_i) || base64url(name_i) || base64url(value_i))
   c. 把 H_i 填入 credentialSubject._sd 数组
   d. 把 [salt_i, name_i, value_i] 加入 Disclosures 集合
4. 构造不含 Disclosures 的完整 VC JSON（含 _sd 数组和 _sd_alg）
5. 计算 VC JSON 的整体哈希
6. 链上锚定：create_anchor(IDCardVC, payload_hash, valid_until)
   （锚定逻辑与现有方案完全一致）
7. 签发 EmailBindingVC 或其他 VC（含 credentialStatus.anchorId 指向锚定记录）
8. 将 VC 原文和 Disclosures 集合一并交付给持有者
```

### 2.2 交付方式

| 交付内容 | 传输方式 | 持有者存储位置 |
|---|---|---|
| VC 原文（含 `_sd`） | 与现有 VC 交付方式一致 | `did-sdk` 的 VC 加密存储 |
| Disclosures 集合 | 与 VC 原文一并交付（如放在同一个加密信封中） | `did-sdk` 的 Disclosures 加密存储 |

**Disclosures 必须与 VC 原文绑定存储**，持有者丢失 Disclosures 后，该 VC 的所有可披露属性都无法再出示（因为无法重算出与 `_sd` 匹配的哈希）。

### 2.3 `payload_hash` 覆盖范围

`payload_hash` 覆盖的是**完整 VC JSON（含 `_sd` 数组，不含 Disclosures）**的 SHA-256。这与现有锚定逻辑一致：链上只存 VC 整体哈希，不感知 VC 内部结构。

```text
payload_hash = SHA-256(canonicalized VC JSON without Disclosures)
```

**链上锚定层不需要知道 `_sd` 数组的存在**。对 `pallet-anchor` 而言，这只是一个普通的 VC 哈希。

---

## 3. 出示流程（持有者侧，`did-sdk`）

### 3.1 用户选择

持有者在 `did-sdk` 界面中看到 VC 的所有可披露属性列表，逐项勾选要披露的属性。默认全部不勾选，用户主动选择后才披露。

### 3.2 构造 Verifiable Presentation

```text
1. 持有者选择要披露的属性集合 S（如 {name, gender}）
2. 从 Disclosures 集合中筛选出 S 对应的 Disclosure 子集：
   D_S = { [salt_i, name_i, value_i] | i ∈ S }
3. 构造 VP：
   {
     "@context": ["https://www.w3.org/2018/credentials/v1"],
     "type": ["VerifiablePresentation"],
     "verifiableCredential": [VC 原文],
     "disclosures": D_S,
     "proof": {
       "type": "Ed25519Signature2020",
       "challenge": "<验证方挑战>",
       "domain": "<验证方标识>",
       "verificationMethod": "did:key:z6MkHolder...#key-1",
       "proofValue": "<持有者对 VP 的签名>"
     }
   }
4. 将 VP 发给验证方
```

### 3.3 关键约束

- **`disclosures` 字段是 VP 层面的扩展字段**，不在 VC 原文内。VC 原文保持完整（含全部 `_sd` 哈希），验证方通过 `disclosures` 与 `_sd` 的比对来确认被披露属性的真实性。
- **持有者签名覆盖整个 VP**（含 `disclosures`），防止验证方篡改披露集合。
- **未被选中属性的 Disclosure 不发给验证方**，验证方只看到它们的哈希，看不到原始值。

---

## 4. 验证流程（验证方侧，`chain-sdk`）

### 4.1 流程

```text
1. 验证 VP 的持有者签名：
   a. 从 VP.proof.verificationMethod 解析持有者 DID
   b. 离线解码 did:key，获取公钥
   c. 用公钥验证 VP.proof 签名（覆盖 VC 原文 + disclosures + challenge + domain）
   d. 检查 challenge 与本次会话一致，防重放

2. 验证 VC 的发行方签名：
   a. 从 VC.proof 解析发行方 DID
   b. 离线解码 did:key，获取公钥
   c. 用公钥验证 VC.proof 签名（覆盖完整 VC JSON）

3. 对每一条 Disclosure [salt_i, name_i, value_i]：
   a. 计算 H_i' = SHA-256(base64url(salt_i) || base64url(name_i) || base64url(value_i))
   b. 检查 H_i' 是否存在于 VC.credentialSubject._sd 数组中
   c. 如果不存在 → 验证失败，reason = "disclosure_hash_mismatch"
   d. 如果存在 → 该属性被确认是发行方签发的

4. 链上锚定查询：
   a. chain_sdk.get_anchor(VC.credentialStatus.anchorId)
   b. 检查 revoked == false
   c. 检查 valid_until == 0 || now <= valid_until
   d. 重建 payload_hash（对完整 VC JSON），与链上值比对

5. 全部通过 → 验证成功
   验证方确信：
   - 被披露的属性（name、gender）是发行方真实签发的
   - 未被披露的属性（birthday、blood_type 等）存在且未被篡改
   - VC 未被撤销、未过期
```

### 4.2 验证方看到的信息

| 信息 | 验证方可见 |
|---|---|
| 被披露属性的原始值（如 `name=张三`、`gender=男`） | ✅ 可见 |
| 未被披露属性的原始值（如 `birthday`、`blood_type`） | ❌ 不可见 |
| 未被披露属性的哈希（在 `_sd` 数组中） | ✅ 可见（但无法反推原始值） |
| VC 的发行方、签发时间、锚定记录 | ✅ 可见 |
| 持有者 DID、VP 签名 | ✅ 可见 |

### 4.3 新增错误码

| 错误码 | 含义 |
|---|---|
| `disclosure_hash_mismatch` | Disclosure 重算的哈希不在 `_sd` 数组中 |
| `disclosure_duplicate` | 同一属性被多次披露（异常） |
| `disclosure_missing` | VP 缺少必要的 `disclosures` 字段 |
| `sd_alg_unsupported` | `_sd_alg` 不是支持的算法 |

---

## 5. 隐私边界：能防什么，不能防什么

### 5.1 能防住的

| 威胁 | 是否防住 | 机制 |
|---|---|---|
| 验证方看到未披露属性 | ✅ | Disclosure 只包含被选中的属性 |
| 验证方伪造或篡改被披露属性 | ✅ | 哈希比对 + 发行方签名 |
| 验证方伪造未披露属性存在 | ✅ | `_sd` 数组中有哈希，说明属性存在 |
| 跨 VC 关联（身份证 VC 与驾照 VC 是否同一人） | ✅ | 每张 VC 独立随机盐 |
| 字典攻击反推属性值 | ✅ | 盐值随机化 |

### 5.2 不能防住的

| 威胁 | 是否防住 | 原因 |
|---|---|---|
| **同一 VC 的跨出示关联** | ❌ | 同一张 VC 的 `_sd` 哈希固定，验证方 A 和 B 合谋可判断"两次出示来自同一张 VC" |
| **多个验证方合谋拼接属性** | ❌ | 验证方 A 拿到 `name`，验证方 B 拿到 `birthday`，合谋后拼出完整画像 |
| **验证方长期存储已披露属性** | ❌ | 属性一旦披露，验证方就拥有了该信息，无法收回 |

**这三项不是 SD-JWT 机制的缺陷，而是选择性披露的固有边界**。密码学只能保证"单次出示的真实性和完整性"，不能保证"跨验证方的信息隔离"。

### 5.3 缓解措施（协议层 + 治理层）

| 威胁 | 缓解措施 |
|---|---|
| 同一 VC 跨出示关联 | 接受有界风险；或升级到 BBS+（见第 7 章） |
| 多验证方合谋拼接 | 协议层强制最小披露原则；敏感属性改用谓词证明；验证方注册与分级；披露行为审计 |
| 验证方长期存储 | 短期 VP 有效期；用户可撤销授权；披露历史可查 |

---

## 6. 对现有架构的影响

### 6.1 链上部分：零改动

| 组件 | 是否改动 | 说明 |
|---|---|---|
| `pallet-anchor` | **否** | 链上只存 VC 整体哈希，不感知 `_sd` 结构 |
| `pallet-issuer` | **否** | 发行方注册逻辑不变 |
| `pallet-did` | **否** | DID 锚定逻辑不变 |
| `AnchorRecord` 结构 | **否** | 不需要新增字段 |
| `payload_hash` 计算 | **否** | 仍然是对完整 VC JSON 的 SHA-256 |

### 6.2 SDK 部分：能力扩展

| 组件 | 需要改动 | 说明 |
|---|---|---|
| `chain-sdk`（`Issuer`） | **扩展** | 签发 VC 时生成盐化哈希和 Disclosures |
| `chain-sdk`（`Verifier`） | **扩展** | 验证 VP 时执行 Disclosure 哈希比对 |
| `did-sdk` | **扩展** | 存储 Disclosures；出示时按用户选择筛选；构造含 `disclosures` 的 VP |
| `keyvault-core` | **可能扩展** | 新增盐值生成和哈希计算工具函数；签名对象构造新增 VP 签名对象 |

### 6.3 协议规范部分：结构扩展

| 章节 | 扩展内容 |
|---|---|
| VC 原文结构（第 4.2 节） | 新增 `_sd` 和 `_sd_alg` 字段 |
| VP 结构（新增） | 新增 `disclosures` 字段 |
| 验证流程（第 6 节） | 新增 Disclosure 哈希比对步骤 |
| 错误码（第 5.3 节） | 新增 `disclosure_hash_mismatch` 等 |

### 6.4 不影响的现有能力

- `EmailBinding` 锚定和 `DID-Signature` 邮件签名：**完全不受影响**——邮件场景的 VC 不涉及选择性披露；
- 撤销机制：**完全不受影响**——撤销的是 VC 整体，与内部属性结构无关；
- 发行方信任框架：**完全不受影响**——发行方类型和资格判定不变。

---

## 7. 升级路径：从 SD-JWT 到 BBS+

### 7.1 什么时候需要升级

| 场景特征 | 建议 |
|---|---|
| 验证方数量少、无合谋动机、接受同一 VC 跨出示关联 | **SD-JWT 足够**（本附件方案） |
| 验证方数量多、可能合谋、同一 VC 频繁向不同方出示 | **考虑 BBS+** |
| 需要谓词证明（"年龄>18"而不暴露生日） | **必须上 BBS+ 或等价 ZKP** |

### 7.2 BBS+ 的能力差异

| 维度 | SD-JWT（本附件） | BBS+ |
|---|---|---|
| 跨 VC 不可关联 | ✅ | ✅ |
| 同一 VC 跨出示不可关联 | ❌ | ✅ |
| 谓词证明 | ❌ | ✅ |
| 证明大小 | 随披露属性线性增长 | 恒定（约 140 字节） |
| 验证开销 | <10ms | 约 12ms |
| 实现复杂度 | 低 | 高（配对密码学） |
| 后量子安全 | 依赖底层签名 | 存疑 |
| 生态成熟度 | 高（IETF 标准化后期） | W3C 候选推荐 |

### 7.3 升级策略

**不在当前阶段引入 BBS+**。理由：

1. SD-JWT 已经满足"隐藏未披露属性"的核心需求；
2. BBS+ 的实现复杂度、验证开销、后量子风险都需要评估；
3. 未来如果确实需要强不可关联性或谓词证明，可以在 `did-sdk` 和 `chain-sdk` 中增加 BBS+ 作为**并存的第二种机制**——VC 格式中增加 `_bbs` 字段标识，验证方按 VC 格式选择对应验证器。

**升级的触发条件**：出现明确的"验证方合谋关联"或"谓词证明"业务需求，且 SD-JWT 的缓解措施无法满足。

---

## 8. 验收清单

### 8.1 签发侧（`chain-sdk` Issuer）

| 编号 | 验收项 | 通过标准 |
|---|---|---|
| I1 | 盐化哈希生成 | 为每个可披露属性生成 16 字节随机盐，哈希计算符合 SD-JWT 规范 |
| I2 | `_sd` 数组构造 | VC 原文包含正确的 `_sd` 数组和 `_sd_alg` |
| I3 | 独立随机盐 | 同一主体的不同 VC 使用不同盐；同一 VC 的不同属性使用不同盐 |
| I4 | Disclosures 生成 | 每条 Disclosure 格式为 `[salt, name, value]` |
| I5 | 链上锚定不变 | `payload_hash` 覆盖完整 VC JSON（含 `_sd`，不含 Disclosures） |
| I6 | Disclosures 交付 | 与 VC 原文一并安全交付给持有者 |

### 8.2 出示侧（`did-sdk`）

| 编号 | 验收项 | 通过标准 |
|---|---|---|
| D1 | Disclosures 存储 | 与 VC 原文绑定加密存储 |
| D2 | 用户选择界面 | 逐项展示可披露属性，默认全不勾选 |
| D3 | Disclosure 筛选 | 只发送用户选中的 Disclosure 子集 |
| D4 | VP 构造 | 包含 VC 原文、`disclosures`、持有者签名 |
| D5 | 持有者签名 | 签名覆盖 VC 原文 + disclosures + challenge + domain |

### 8.3 验证侧（`chain-sdk` Verifier）

| 编号 | 验收项 | 通过标准 |
|---|---|---|
| V1 | VP 签名验证 | 持有者签名有效；challenge 与本次会话一致 |
| V2 | VC 签名验证 | 发行方签名有效 |
| V3 | Disclosure 哈希比对 | 每条 Disclosure 重算哈希，与 `_sd` 数组中某一项匹配 |
| V4 | 未披露属性不可见 | 验证方只看到 `_sd` 哈希，看不到原始值 |
| V5 | 链上锚定查询 | `get_anchor` 检查 `revoked` 和 `valid_until` |
| V6 | 篡改检测 | 篡改 Disclosure 中的盐或值 → `disclosure_hash_mismatch` |
| V7 | 重复披露检测 | 同一属性多次披露 → `disclosure_duplicate` |

### 8.4 隐私边界

| 编号 | 验收项 | 通过标准 |
|---|---|---|
| P1 | 跨 VC 不可关联 | 同一主体两张不同 VC 的同一属性哈希不同 |
| P2 | 同一 VC 跨出示可关联（已接受） | 文档中明确标注这是 SD-JWT 固有边界 |
| P3 | 字典攻击防护 | 哈希不可反推属性值 |

---

## 9. 交付物

1. 本附件文档（VC 结构扩展、签发/出示/验证流程、隐私边界说明）；
2. `chain-sdk`（`Issuer`）的盐化哈希和 Disclosures 生成模块；
3. `chain-sdk`（`Verifier`）的 Disclosure 哈希比对模块；
4. `did-sdk` 的 Disclosures 存储、用户选择、VP 构造模块；
5. `keyvault-core` 的盐值生成和哈希计算工具函数；
6. 新增错误码定义；
7. 测试套件（签发、出示、验证、篡改检测、隐私边界）；
8. 验收记录（I1–I6、D1–D5、V1–V7、P1–P3）。

---

## 10. 与其它文档的关系

| 文档 | 关系 |
|---|---|
| **《基于 DID 签名的邮件地址真实性与完整性增强协议规范》** | 本附件是主规范的补充，扩展了 VC 原文结构和 VP 构造 |
| **《DidSdk 接口契约与实现规格书》** | `did-sdk` 新增 Disclosures 存储和 VP 构造能力 |
| **《ChainSdk 接口契约与实现规格书》** | `chain-sdk` 的 `Issuer` 新增盐化哈希生成，`Verifier` 新增 Disclosure 哈希比对 |
| **《keyvault-core crate 规格书》** | 新增盐值生成和哈希计算工具函数 |
| **《Solochain 增量开发任务书》** | **无影响**——链上锚定层零改动 |
| **《中心化模拟链独立服务规格书》** | **无影响**——中心化服务不感知 VC 内部结构 |

---

## 11. 一句话总结

**在现有 DID+VC 信任链上增加选择性披露，不需要修改链上锚定层，只需在 VC 原文的 `credentialSubject` 中增加 `_sd` 盐化哈希数组、在 VP 中增加 `disclosures` 字段，并在 `chain-sdk`（签发和验证）和 `did-sdk`（存储和出示）中实现对应的哈希生成与比对逻辑。每张 VC 的每个可披露属性使用独立随机盐，防住跨 VC 关联和字典攻击；同一 VC 的跨出示关联和跨验证方合谋拼接是选择性披露的固有边界，SD-JWT 防不住，需要协议层的最小披露约束、治理层的验证方审计、或升级到 BBS+ 的零知识证明来缓解。**
