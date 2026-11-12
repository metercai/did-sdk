# 修订说明：did-sdk 移除链上查询与 subxt 依赖
## 变更记录 · 适用于文档一 / 文档二 / 文档三 · 版本 R1

## 0. 修订摘要

| 项 | 内容 |
|---|---|
| 修订编号 | R1 |
| 修订主题 | `did-sdk` 移除链上查询能力与 `subxt` 依赖；锚定查询职责上移至 `chain-sdk`（Verifier） |
| 影响文档 | 文档一（总体架构）、文档二（DidSdk）、文档三（ChainSdk） |
| 不涉及 | 文档四（ChainOwnerSdk）、文档五（keyvault-core）、文档六（Solochain 增量）、文档七（中心化模拟链） |
| 核心结论 | `did-sdk` 保留两后端（`Mock` / `Centralized`），删除 `Chain` 后端与 `get_anchor`；`subxt` 从 `did-sdk` 依赖树移除 |

## 1. 背景与决策依据

### 1.1 问题

`did-sdk` 当前依赖 `subxt` 以支持 `Chain` 后端并暴露 `get_anchor` 只读方法。评估后发现：

1. `subxt` 依赖体积在 19–50 MB 量级，SLoC 约 713K，对客户端 SDK（尤其需编译到 WASM、嵌入桌面/移动端）负担过重。
2. 社区已有更轻量替代品（如 `Sube`）明确以“可在浏览器等受限环境运行”为卖点，从侧面印证 `subxt` 在客户端场景偏重。
3. `did-sdk` 的核心职责——DID 密钥管理、签名、VC 钱包、`did:key`/`did:peer` 离线验签——全部不需要连接链。
4. 为单个可选的 `get_anchor` 查询引入整条 Substrate RPC 栈，性价比不成立。

### 1.2 职责归属判断

| 问题 | 结论 |
|---|---|
| `did:key` 验签需要链吗？ | 不需要。公钥自包含于 DID 字符串，离线确定性解析。 |
| 客户端构造 `DID-Signature` 头需要链吗？ | 不需要。签名只需本地私钥；`anchor_id` 由调用方传入。 |
| 锚定状态核对是谁的职责？ | 验证方（网关、场景应用）的职责，不是签名方的职责。 |
| 委托锚定（路径三）中客户端需要查链吗？ | 不需要。链主代提交后返回 `anchor_id`，客户端把它写进后续签名头；验证方用 `chain-sdk` 查锚定。 |
| Centralized 后端能否满足锚定预览？ | 能。`reqwest` 一个 HTTP GET 即可，不需要 `subxt`。 |

### 1.3 决策

- `did-sdk` 的 `DidSdk` trait 删除 `get_anchor`。
- `did-sdk` 删除 `Chain` 后端模式，只保留 `Mock` 与 `Centralized`。
- `did-sdk` 从依赖中移除 `subxt`。
- `get_anchor` 职责上移至 `chain-sdk`（`Verifier` 角色）；`chain-sdk` 的 `Chain` 后端保留 `subxt`，服务端环境可接受。
- 客户端若确有锚定预览需求，走 `Centralized` 后端的 HTTP 只读接口（`reqwest`），或由上层应用自行调用验证方接口。

## 2. 影响范围

| 文档 | 章节 | 改动类型 |
|---|---|---|
| 文档一 | 0.4 SDK 职责与层次 | 修改 |
| 文档一 | 0.5 核心决策表 | 新增/修改 |
| 文档一 | 0.7 三种后端模式 | 修改（区分 did-sdk 与 chain-sdk 的后端集） |
| 文档一 | 1 项目目标 | 修改 |
| 文档一 | 3 技术选型 | 修改 `did-sdk` 依赖 |
| 文档一 | 7 验收清单 V13 | 修改 |
| 文档一 | 9 风险与禁止事项 | 新增边界 |
| 文档二 | 0.1 定位 | 修改 |
| 文档二 | 0.3 三种后端模式 | 修改为两种 |
| 文档二 | 1.1 模式特定能力 | 删除 `get_anchor` |
| 文档二 | 3 配置与构造 | 删除 `[did_sdk.chain]` |
| 文档二 | 5 Centralized | 保留，说明用途为可选预览 |
| 文档二 | 6 Chain（原） | 删除 |
| 文档二 | 9 三后端对比 | 修改为两后端 |
| 文档二 | 11 验收清单 D8 | 修改 |
| 文档二 | 13 与其它文档关系 | 修改 |
| 文档三 | 1 接口契约 | 无需改（`get_anchor` 本就在） |
| 文档三 | 1 接口说明 | 新增职责边界说明 |
| 文档三 | 0.1 定位 | 新增一句职责归属 |

## 3. 文档一修订点

### 3.1 修订 0.4 节 SDK 职责表（`did-sdk` 行）

原文（节选）：

> `did-sdk` | ... | DID 方法 + VC 钱包的统一能力层 ...

修订为：

> `did-sdk` | 独立身份客户端、`aimail-sdk`、其他客户端应用 | 客户端 / 能力层 | **DID 方法 + VC 钱包的统一能力层**。类型参数区分 `DidSdk<Client>`（`did:key`/`did:peer`，设备安全区）与 `DidSdk<Server>`（`did:web`，签名私钥在服务端安全域，由 `chain-sdk` 注入 `Signer`）。**不承担链上查询，不依赖 `subxt`；锚定查询由验证方的 `chain-sdk` 完成。**

### 3.2 修订 0.4 节层次图

原文：

```text
did-sdk（能力层：DID 方法 + VC 钱包；类型参数 Client/Server）
        │ 依赖
        ▼
keyvault-core（密钥管理抽象，多 namespace）
```

修订为：

```text
did-sdk（能力层：DID 方法 + VC 钱包；类型参数 Client/Server；无链上查询）
        │ 依赖
        ▼
keyvault-core（密钥管理抽象，多 namespace）
        │（可选）
        ▼
reqwest（仅 Centralized 后端下的可选锚定预览）

注：subxt 依赖只存在于 chain-sdk / chain-owner-sdk，不出现在 did-sdk。
```

### 3.3 修订 0.5 节核心决策表（新增一行）

| 决策点 | 结论 | 理由 |
|---|---|---|
| `did-sdk` 链上查询 | **移除 `get_anchor` 与 `subxt` 依赖；`did-sdk` 只保留 `Mock` / `Centralized` 两后端** | 客户端核心职责不需链；`subxt` 对客户端过重；锚定核对是验证方职责 |

### 3.4 修订 0.7 节后端模式表

原表为统一的三种后端。修订为**按 SDK 区分**：

| SDK | `Mock` | `Centralized` | `Chain` | 说明 |
|---|---|---|---|---|
| `did-sdk` | 是 | 是 | **否** | 客户端不承担链上查询；Centralized 仅用于可选锚定预览（HTTP 只读） |
| `chain-sdk` | 是 | 是 | 是 | 服务端承担锚定查询与写链 |
| `chain-owner-sdk` | 是 | 是 | 是 | 同 `chain-sdk` |

### 3.5 修订 1 节项目目标

将：

> `did-sdk` 完成 `Client` / `Server` 两模式、三种 DID 方法、VC 钱包、只读链查询；

修订为：

> `did-sdk` 完成 `Client` / `Server` 两模式、三种 DID 方法、VC 钱包，**不承担链上查询**（`get_anchor` 归属 `chain-sdk` 的 Verifier 角色）；

### 3.6 修订 3 节技术选型（`did-sdk` 行）

原文：

> `did-sdk` | Rust crate，依赖 `keyvault-core`、`subxt`（Chain）、`reqwest`（Centralized）；类型参数 `DidSdk<Client>` / `DidSdk<Server>`

修订为：

> `did-sdk` | Rust crate，依赖 `keyvault-core`、`reqwest`（Centralized，可选）；**不依赖 `subxt`**；类型参数 `DidSdk<Client>` / `DidSdk<Server>`

### 3.7 修订 7 节验收清单 V13

原文：

> V13 | `did-sdk` 三后端模式 | Mock/Centralized/Chain 行为一致

修订为：

> V13 | `did-sdk` 两后端模式 | Mock/Centralized 行为一致；`did-sdk` 不提供 Chain 后端；依赖树中无 `subxt`

### 3.8 修订 9 节风险与禁止事项（新增一条）

> **`did-sdk` 依赖边界**：`did-sdk` 不得依赖 `subxt`；不得提供 `Chain` 后端；不得提供 `get_anchor`。锚定查询一律由验证方的 `chain-sdk`（Verifier）完成。若客户端有锚定预览需求，走 `Centralized` 的 HTTP 只读接口或上层应用自有通道。

## 4. 文档二修订点

### 4.1 修订 0.1 节定位

原文（节选）：

> 它同时支持三种 DID 方法（`did:key`、`did:peer`、`did:web`）和 VC 签发/存储管理，通过类型参数在编译期区分两种运行模式：

修订为（追加一段）：

> 它同时支持三种 DID 方法（`did:key`、`did:peer`、`did:web`）和 VC 签发/存储管理，通过类型参数在编译期区分两种运行模式。**`did-sdk` 不承担链上查询，不依赖 `subxt`；锚定查询由验证方的 `chain-sdk` 完成。**

### 4.2 修订 0.2 节设计原则（新增第 7 条）

> 7. **客户端不承担链上查询**。`DidSdk` 不暴露 `get_anchor`，不依赖 `subxt`。`did:key`/`did:peer` 的验签是离线自包含的；锚定状态核对应由验证方（`chain-sdk`）完成。

### 4.3 修订 0.3 节三种后端模式

原文：

| 模式 | 后端 | 部署形态 | 适用阶段 |
|---|---|---|---|
| `Mock` | ... |
| `Centralized` | ... |
| `Chain` | 真实链节点 | Substrate RPC | 生产 |

修订为：

| 模式 | 后端 | 部署形态 | 适用阶段 |
|---|---|---|---|
| `Mock` | 进程内状态 | 无外部依赖 | 单元测试 |
| `Centralized` | 中心化模拟链（只读） | 独立 HTTP 服务，SDK 通过 HTTP 访问 | 集成测试、试生产；**可选**用于锚定预览 |

**`did-sdk` 不提供 `Chain` 后端。** 需要锚定查询与写链能力的场景使用 `chain-sdk`。

### 4.4 修订 1.1 节模式特定能力（删除 `get_anchor`）

原文（共享 impl）：

```rust
impl<M: SdkMode> DidSdk<M> {
    pub fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError>;
    pub async fn get_anchor(&self, anchor_id: &str) -> Result<AnchorRecord, DidSdkError>;

    // VC 钱包（持有侧，两模式共享）
    ...
}
```

修订为：

```rust
impl<M: SdkMode> DidSdk<M> {
    pub fn resolve_did(&self, did: &str) -> Result<Option<DidRecord>, DidSdkError>;
    // get_anchor 已移除：锚定查询归属 chain-sdk（Verifier）

    // VC 钱包（持有侧，两模式共享）
    pub async fn store_vc(&self, vc: VerifiableCredential) -> Result<(), DidSdkError>;
    pub async fn get_vc(&self, anchor_id: &str) -> Result<Option<VerifiableCredential>, DidSdkError>;
    pub async fn list_vcs(&self) -> Result<Vec<VerifiableCredential>, DidSdkError>;
    pub async fn remove_vc(&self, anchor_id: &str) -> Result<(), DidSdkError>;
    pub async fn build_vp(
        &self, vcs: Vec<VerifiableCredential>, challenge: &str, domain: &str,
    ) -> Result<VerifiablePresentation, DidSdkError>;
}
```

**注意**：VC 钱包的 `get_vc(anchor_id)` 是本地 VC 存储的查询键，与链上锚定查询无关，保留不变。

### 4.5 修订 1.3 节错误码（可选精简）

`DidSdkError::AnchorNotFound` / `AnchorRevoked` / `AnchorExpired` 在 `did-sdk` 中不再由 `get_anchor` 触发。保留用于 VC 钱包的本地状态表达（如 VC 对应的锚定已撤销时的本地标记），但**不得**用于链上查询结果。**实现约束**：`did-sdk` 不得因这几个错误码而引入任何链交互。

若实现层希望进一步简化，可将这三个错误码标注为“本地状态语义”，并在文档中说明其不承载链上查询含义。

### 4.6 修订 3 节配置与构造

**删除**以下配置段：

```toml
[did_sdk.chain]
endpoint = "wss://rpc.identity-chain.com:9944"
```

**保留**的配置：

```toml
# Client（客户端）
[did_sdk]
mode = "centralized"          # 后端：mock / centralized
subject_kind = "client"
vc_storage_path = "./vc_store"

[did_sdk.key_vault]
scheme = "file-keystore"
path = "./identity-keys"
password_env = "DID_KEYSTORE_PASSWORD"

[did_sdk.centralized]
endpoint = "http://localhost:8080"   # 可选：仅用于锚定预览
```

```toml
# Server（服务端，由 chain-sdk / chain-owner-sdk 装配）
[did_sdk]
mode = "centralized"
subject_kind = "server"
participant_did = "did:web:issuer.example.com:mail"
vc_storage_path = "./participant-vc-store"
# Server 模式不配置 key_vault —— 参与方签名私钥在 chain-sdk / chain-owner-sdk
```

### 4.7 修订第 6 节（原“后端模式三：Chain”）

**整节删除**。原第 6 节内容替换为一句说明：

> **`did-sdk` 不提供 `Chain` 后端。** 需要 Substrate RPC 直连的场景，使用 `chain-sdk` 的 `Chain` 后端；`did-sdk` 的 `Centralized` 后端仅提供可选的 HTTP 只读锚定预览。

原第 5 节（Centralized）内容调整为：

### 5. 后端模式二：Centralized（只读，可选）

`CentralizedBackend` 通过 HTTP 访问中心化模拟链单一端点，**只调只读接口**：

| 操作 | HTTP | 说明 |
|---|---|---|
| `resolve_did(did)` | `GET /dids/{did}` | DID 记录解析 |
| 锚定预览（可选） | `GET /anchors/{id}` | **仅供 UI 预览，不参与签名与验签决策** |

**约束**：
- `did-sdk` 不通过该后端做任何写操作；
- `did:web` 解析直连 HTTPS，不经中心化服务；
- 锚定预览结果**不得**作为签名或验签的输入依据；验证决策由验证方的 `chain-sdk` 做出。

### 4.8 修订第 9 节后端对比（两后端）

原文为三后端对比表。修订为：

| 维度 | Mock | Centralized |
|---|---|---|
| 外部依赖 | 无 | 中心化服务进程（可选） |
| 配置项 | `mode="mock"` | `mode="centralized"`+`endpoint` |
| 私钥存储（Client） | 内存 | `FileKeystore` |
| 链访问 | 无 | HTTP 只读（可选锚定预览） |
| 信任模型 | 信任测试代码 | 信任服务运营方 |
| 适用阶段 | 单元测试 | 集成测试、试生产 |
| 应用代码改动 | 零 | 零 |

**`Chain` 后端不在 `did-sdk` 的选项内。**

### 4.9 修订第 10 节安全约束（`did-sdk` 约束表，新增一行）

| 约束 | 说明 |
|---|---|
| **不承担链上查询** | `did-sdk` 不暴露 `get_anchor`，不依赖 `subxt`；锚定查询归 `chain-sdk`（Verifier） |

### 4.10 修订第 11 节验收清单

| 编号 | 原验收项 | 修订后 |
|---|---|---|
| D3 | 三后端模式切换 | **两后端模式切换**：同一二进制经 `mode` 字段在 `mock` / `centralized` 间切换，需重启 |
| D4 | 三后端模式语义一致 | **两后端语义一致**：同一操作结果与错误码一致 |
| D8 | Chain 只读：只调链只读 storage | **删除**。替换为：**`did-sdk` 不提供 `Chain` 后端，不依赖 `subxt`；依赖树检查通过** |
| D14 | 一致性测试：同一用例在三后端下结果一致 | **两后端**一致 |

新增验收项：

| 编号 | 验收项 | 通过标准 |
|---|---|---|
| **D16** | **无 `subxt` 依赖** | **`cargo tree -p did-sdk` 中不出现 `subxt`；Cargo.toml 不含 `subxt`** |
| **D17** | **无链上查询接口** | **`DidSdk` trait 不暴露 `get_anchor`；无任何 Substrate RPC 调用路径** |
| **D18** | **锚定核对职责边界** | **`did-sdk` 的签名与验签不依赖任何锚定查询结果；验证决策由 `chain-sdk` 完成** |

### 4.11 修订第 13 节与其它文档关系

| 文档 | 关系 |
|---|---|
| 文档三：ChainSdk 规格书 | `chain-sdk` 承担锚定查询（`get_anchor`）与写链；`did-sdk` 不提供链上查询 |

## 5. 文档三修订点

### 5.1 修订 0.1 节定位（追加一句）

> **职责边界**：锚定查询（`get_anchor` / `list_anchors`）由本 crate 的 `Verifier` / `Issuer` 角色承担；客户端 SDK（`did-sdk`）不提供链上查询。

### 5.2 修订 1 节接口说明（追加职责说明）

在 `get_anchor` 方法附近追加说明：

> `get_anchor` / `list_anchors` 是**验证方**核对锚定状态的入口。客户端（`did-sdk`）不提供此能力；签名方只负责把 `anchor_id` 写入签名头，锚定核对由验证方通过本 crate 完成。

### 5.3 其余部分无需改动

`chain-sdk` 的 `Chain` 后端、`subxt` 依赖、`Verifier` 角色能力矩阵保持不变。

## 6. 对端到端流程的影响

| 流程 | 影响 | 说明 |
|---|---|---|
| 邮件协议 5.1 第 3 步（客户端签名） | 无实质影响 | 客户端构造 `DID-Signature` 头时，`anchor_id` 由业务层传入；不需要客户端查链 |
| 邮件协议 5.1 第 4 步（网关验证） | 无影响 | 网关本就用 `chain-sdk`（Verifier）查锚定 |
| 路径三 5.2 第 2–3 步（A 签发 VC、签授权声明） | 无影响 | A 在 `did-sdk` 本地完成签名 |
| 路径三 5.2 第 4 步（链主代提交） | 无影响 | `chain-owner-sdk` 提交后返回 `anchor_id` |
| 路径三 5.2 第 5 步（验证方验证） | 无影响 | 验证方用 `chain-sdk` 查锚定 |

**结论**：移除 `did-sdk` 的链上查询不改变任何端到端流程的职责划分，只是把原本就属于验证方的查询从客户端依赖中剥离。

## 7. 实施检查清单

| 检查项 | 验证命令/方法 | 通过标准 |
|---|---|---|
| `did-sdk` 依赖树无 `subxt` | `cargo tree -p did-sdk \| grep subxt` | 无输出 |
| `did-sdk` Cargo.toml 无 `subxt` | 人工检查 `[dependencies]` | 不存在 |
| `DidSdk` trait 无 `get_anchor` | 编译期检查 | 调用 `sdk.get_anchor(...)` 编译失败 |
| `did-sdk` 配置无 `[did_sdk.chain]` | 配置样例检查 | 不存在 |
| 两后端模式切换 | 启动参数 `mode=mock` / `mode=centralized` | 行为一致，需重启 |
| `chain-sdk` `get_anchor` 可用 | 集成测试 | Verifier 角色可查锚定 |
| 网关端到端 | `aimail-gateway` 集成测试 | 完整性验证 + 锚定核对通过 |
| 路径三端到端 | 委托锚定集成测试 | A 签发 → 链主代锚 → 验证方查到 |

## 8. 风险与遗留

| 项 | 说明 | 处置 |
|---|---|---|
| 客户端锚定预览需求 | 若 UI 需要显示“此绑定尚未撤销” | 走 `Centralized` 的 HTTP 只读接口，或由上层应用调用验证方接口；**不得**为预览引入 `subxt` |
| 断网场景 | 客户端无网络 | `did:key`/`did:peer` 签名与本地 VC 管理完全可用；锚定预览不可用，但不影响签名闭环 |
| `did:web` 解析 | 需 HTTPS | 属 DID 解析，不是链上查询；不受本修订影响 |
| 未来若确实需要客户端链查询 | 重新评估 | 优先考虑轻量 RPC 客户端（如 `Sube`）或 HTTP 网关代理，而非直接引入 `subxt`；任何引入需走架构评审 |

## 9. 一句话总结

**`did-sdk` 移除 `get_anchor` 与 `subxt` 依赖，后端收敛为 `Mock` / `Centralized`；锚定查询职责归属验证方的 `chain-sdk`（Verifier）。客户端只做签名与 VC 钱包，验证方只做锚定核对与验证决策，职责边界与依赖负担同时得到修正。**
