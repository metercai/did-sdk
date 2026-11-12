# did-sdk

[![ci](https://github.com/metercai/did-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/metercai/did-sdk/actions/workflows/ci.yml)
[![rust-musl](https://github.com/metercai/did-sdk/actions/workflows/rust-musl.yml/badge.svg)](https://github.com/metercai/did-sdk/actions/workflows/rust-musl.yml)
[![python](https://github.com/metercai/did-sdk/actions/workflows/python.yml/badge.svg)](https://github.com/metercai/did-sdk/actions/workflows/python.yml)
[![node](https://github.com/metercai/did-sdk/actions/workflows/node.yml/badge.svg)](https://github.com/metercai/did-sdk/actions/workflows/node.yml)
[![cross-lang](https://github.com/metercai/did-sdk/actions/workflows/cross-lang.yml/badge.svg)](https://github.com/metercai/did-sdk/actions/workflows/cross-lang.yml)

DID 方法与 VC 钱包统一能力层：**`DidSdk<Client>` / `DidSdk<Server>` 两种运行模式**
× **Mock / Centralized / Chain 三种后端** × **did:key / did:peer / did:web 三种 DID 方法**。

> **当前状态：已按更新版规格重构，本地与 GitHub Actions 验证通过。**
> - 规格：`01-DidSdk接口契约与实现规格书1.md` / `04-keyvault-core_crate规格书1.md`（上游输入）
> - 实施/迁移说明：[`docs/implementation-report.md`](docs/implementation-report.md)
> - 验收清单：[`docs/acceptance-checklist.md`](docs/acceptance-checklist.md)
> - CI 维护：[`docs/ci-setup.md`](docs/ci-setup.md)

---

## 1. 两种运行模式

| 模式 | 使用者 | DID 方法 | 私钥 | VC 能力 |
|---|---|---|---|---|
| `DidSdk<Client>` | 客户端应用、`aimail-sdk` | `did:key` / `did:peer` | `KeyVault`（设备安全区） | 签发 + 持有 + 呈现 |
| `DidSdk<Server>` | `chain-sdk` / `chain-owner-sdk` 服务端 | 固定 `did:web` | **不持有**（外部 `Signer` 注入 `Proof`） | 持有侧、组装、校验他人 VC |

两种模式通过类型参数在**编译期隔离**：

- `DidSdk<Client>` 没有 `resolve_did_web` / `assemble_vc_with_proof` / `verify_vc`；
- `DidSdk<Server>` 没有 `generate_did_key` / `generate_did_peer` / `sign_with_did_key` / `issue_self_asserted_vc`。

三种后端（Mock / Centralized / Chain）与两种运行模式正交，只影响 `resolve_did` / `get_anchor`。

---

## 2. 三套产物与安装

| 产物 | 目录 | 构建 | 目标 |
|---|---|---|---|
| Rust crate | `./` + `./keyvault-core` | cargo / cargo-zigbuild | Linux musl x64/arm64、macOS arm64、Windows x64 |
| Python wheel | `./bindings/python` | maturin | manylinux / musllinux / macosx / win_amd64 |
| Node addon | `./bindings/node` | napi-rs | Linux x64/arm64 gnu+musl、macOS arm64、Windows x64 |

```bash
# Rust（未发布到 crates.io 前使用 path）
cargo add did-sdk

# Python
pip install did-sdk
cd bindings/python && maturin build --release && pip install dist/*.whl

# Node
npm install @did-sdk/node
cd bindings/node && npm ci && npx napi build --platform --release
```

**本项目不提供浏览器 WASM 版本。**

---

## 3. 快速开始

### Rust Client

```rust
use did_sdk::{build_client_sdk, config::resolve_config, SigningContext};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = resolve_config(Default::default())?;
    let sdk = build_client_sdk(&config)?;

    let did = sdk.generate_did_key()?;
    let signature = sdk
        .sign_with_did_key(
            b"hello did-sdk",
            SigningContext {
                purpose: "smoke".into(),
                payload_summary: "quickstart".into(),
                requestor: None,
            },
        )
        .await?;

    let vc = sdk.issue_self_asserted_vc(serde_json::json!({"name": "Alice"}))?;
    sdk.store_vc(vc.clone()).await?;
    let vp = sdk.build_vp(vec![vc], "challenge-1", "example.com").await?;

    println!("did={did}, sig_len={}, vp={}", signature.0.len(), vp.proof.is_some());
    Ok(())
}
```

### Rust Server

```rust
use did_sdk::{build_server_sdk, Proof, ServerConfig};

let config = ServerConfig {
    participant_did: "did:web:issuer.example.com".into(),
    ..Default::default()
};
let sdk = build_server_sdk(&config)?;

// proof 由外部 Signer（chain-sdk / chain-owner-sdk）产生
let proof = Proof {
    type_: "Ed25519Signature2020".into(),
    created: 1_700_000_000,
    verification_method: "did:web:issuer.example.com#key-1".into(),
    jws: "<base58 signature>".into(),
};
let vc = sdk.assemble_vc_with_proof(claims, "did:key:zSubject", proof)?;
let result = sdk.verify_vc(&vc).await?;
println!("verified={}", result.verified);
```

### Python

```python
import asyncio
from did_sdk import DidSdk

async def main():
    sdk = DidSdk()  # 全部参数可省略
    did = await sdk.generate_did_key()
    peer = await sdk.generate_did_peer("0")
    sig = await sdk.sign_with_did_key(b"hello did-sdk", purpose="smoke")
    vc = await sdk.issue_self_asserted_vc({"name": "Alice"})
    await sdk.store_vc(vc)
    print(did, peer, len(sig), vc["proof"]["jws"])

asyncio.run(main())
```

### Node / TypeScript

```ts
import { DidSdk } from "@did-sdk/node";

const sdk = new DidSdk();
const did = await sdk.generateDidKey();
const peer = await sdk.generateDidPeer("0");
const sig = await sdk.signWithDidKey(Buffer.from("hello did-sdk"), { purpose: "smoke" });
const vc = await sdk.issueSelfAssertedVc({ name: "Alice" });
await sdk.storeVc(vc);
console.log(did, peer, sig.length, vc.proof.jws);
```

---

## 4. DID 方法

| 方法 | 模式 | 解析 | 离线验签 | 轮换 |
|---|---|---|---|---|
| `did:key` | Client | 从字符串解码 Ed25519 公钥 | 是 | 换 DID |
| `did:peer:0/2` | Client | 公钥内嵌 | 是 | 静态 |
| `did:peer:1` | Client | 文档哈希 + 本地文档 | 是 | 静态 |
| `did:web` | Server | HTTPS `did.json` | 否（需网络） | 文档内轮换 |

> `did:peer` 的 POC 编码为简化实现：`0` / `2` 使用 `did:peer:<numalgo>z<multibase(0xED01||key)>`；
> `1` 使用文档哈希并在本地保存文档。生产接入其他实现时需对齐编码。

---

## 5. VC 钱包

| 能力 | Client | Server |
|---|---|---|
| `store_vc` / `get_vc` / `list_vcs` / `remove_vc` | 是 | 是 |
| `build_vp` | 是（本地签名） | 是（无签名私钥，返回无 proof 的 VP） |
| `issue_self_asserted_vc` | 是 | 否 |
| `assemble_vc_with_proof` | — | 是（外部 `Proof` 注入） |
| `verify_vc` | — | 是（issuer 解析 + 签名 + 有效期 + 锚定） |

VC 的 `proof` 结构：

```json
{
  "type": "Ed25519Signature2020",
  "created": 1700000000,
  "verificationMethod": "did:key:z...#key-1",
  "jws": "<base58 signature>"
}
```

---

## 6. 配置

优先级：**显式 overrides > 环境变量 > 可选 TOML > 内置默认值**。
密码链：`DID_SDK_KEYVAULT_PASSWORD` → `password_file` → 自动生成（可关闭）→ 交互输入（可选）→ 报错。

```toml
[did_sdk]
mode = "mock"                 # mock / centralized / chain
subject_kind = "client"       # client / server（构造工厂决定类型）
vc_storage_path = "./vc_store"
cache_ttl_secs = 600

[did_sdk.key_vault]           # 仅 Client
scheme = "file-keystore"      # file-keystore / memory-keystore
path = "./identity-keys"
password_env = "DID_SDK_KEYVAULT_PASSWORD"

[did_sdk.centralized]
endpoint = "http://127.0.0.1:8080"

[did_sdk.chain]
endpoint = "ws://127.0.0.1:9944"

# Server（由 chain-sdk / chain-owner-sdk 装配）
# [did_sdk]
# mode = "chain"
# subject_kind = "server"
# participant_did = "did:web:issuer.example.com:mail"
# vc_storage_path = "./participant-vc-store"
```

### 环境变量

| 变量 | 覆盖项 |
|---|---|
| `DID_SDK_HOME` | 根目录 |
| `DID_SDK_MODE` | 后端模式 |
| `DID_SDK_CONFIG_FILE` | TOML 路径 |
| `DID_SDK_VC_STORAGE_PATH` | VC 目录 |
| `DID_SDK_KEYVAULT_SCHEME` | file / memory |
| `DID_SDK_KEYVAULT_PATH` | 密钥目录 |
| `DID_SDK_KEYVAULT_PASSWORD` | 密码（最高优先） |
| `DID_SDK_KEYVAULT_PASSWORD_FILE` | 密码文件 |
| `DID_SDK_CENTRALIZED_ENDPOINT` | Centralized 端点 |
| `DID_SDK_CHAIN_ENDPOINT` | Chain 端点 |
| `DID_SDK_CACHE_TTL_SECS` | TTL |

---

## 7. `UserRejected`

| 语言 | 观察方式 |
|---|---|
| Rust | `DidSdkError::UserRejected` |
| Python | `except did_sdk.UserRejectedError` |
| Node | `err.code === "UserRejected"` |

来源：`ServerRequestHandler` 拒绝、`MockBackend::with_auto_reject`、未来 `KeyVaultError::UserRejected`。

---

## 8. 安全与静态链接

- `KeyVault` 无导出私钥接口；`Keypair` 不实现 `Serialize` / `Clone` / `Debug`。
- 三类 namespace 物理隔离：`chain-account/`（sr25519）、`participant-did/`（ed25519）、`client-did/`（ed25519）；跨 namespace 签名返回 `NamespaceViolation`。
- `FileKeystore`：Argon2id + ChaCha20-Poly1305，按 namespace 子目录 + `index.json`，原子写。
- Client 签名前用户确认；Server 不持签名私钥。
- 链访问只读；不注入链账户私钥。
- HTTP 仅 rustls，不引入 OpenSSL/native-tls。

| 目标 | Rust 核心 | Python wheel | Node addon |
|---|---|---|---|
| Linux musl x64/arm64 | **完全静态（CI `file` 断言）** | musllinux | musl `.node` |
| Linux gnu | — | manylinux | gnu `.node` |
| macOS arm64 | 原生 | macosx | macOS `.node` |
| Windows x64 | 原生 | win_amd64 | Windows `.node` |

---

## 9. 开发与测试

```bash
export RUSTUP_HOME="$PWD/.rustup"       # 仅本沙箱
export RUSTUP_TOOLCHAIN=1.88.0
export CARGO_HOME="$PWD/.cargo-home"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --exclude did-sdk-python --exclude did-sdk-node

# 三套产物
bash scripts/build-rust-musl.sh
bash scripts/build-python.sh
bash scripts/build-node.sh
bash scripts/cross-lang-vectors.sh
```

---

## 10. 兼容性说明（相对旧版）

本次按更新版规格做了**破坏性重构**：

1. `did-sdk` 不再是 `dyn DidSdk` trait，而是 `DidSdk<Client>` / `DidSdk<Server>` 类型；
2. `DidRecord` 字段改为 `method/doc_hash/owner/block_number`；
3. `VerifyResult` 改为 `verified/integrity/address/reason`；
4. `IssueAuthorizationSignature` 改为裸签名字节；
5. VC proof 改为 `Proof { type_, created, verificationMethod, jws }`；
6. `keyvault-core` `KeyId` 带 namespace 前缀，`FileKeystore` 文件格式升级到 v2（`.enc`），旧 v1 keystore 不兼容，需要重新生成密钥（POC）。

---

## 11. 许可证

Apache-2.0，见 [`LICENSE`](LICENSE)。
