# did-sdk

DID SDK：一个 Rust 核心（Linux musl 完全静态）+ Python wheel + Node 原生模块，
提供 **Mock / Centralized / Chain** 三种运行模式，业务代码只依赖统一的 `DidSdk` 接口。

> **当前状态：Rust 核心、keyvault-core、Python/Node 绑定已实现并通过本地测试。**
> 实施计划与评审结论见 [`docs/implementation-plan.md`](docs/implementation-plan.md)，
> 验收证据见 [`docs/acceptance-checklist.md`](docs/acceptance-checklist.md)，
> 阶段报告见 [`docs/implementation-report.md`](docs/implementation-report.md)，
> CI 接入步骤见 [`docs/ci-setup.md`](docs/ci-setup.md)。
> 跨平台（Linux musl / Windows）构建统一由 GitHub Actions runner 完成，本地只做
> macOS arm64 验证；首次推送后以 CI 结果为准。

---

## 1. 三套产物

| 产物 | 目录 | 构建工具 | 目标平台 | 静态链接 |
|---|---|---|---|---|
| Rust crate | `./` + `./keyvault-core` | `cargo` / `cargo-zigbuild` | Linux musl x64/arm64、macOS arm64、Windows x64 | **Linux musl 完全静态、零运行时依赖** |
| Python wheel | `./bindings/python` | `maturin` | manylinux / musllinux / macosx / win_amd64 | 由 Python 生态处理 |
| Node addon | `./bindings/node` | `napi-rs` | Linux x64/arm64（gnu + musl）、macOS arm64、Windows x64 | 由 Node 生态处理 |

**本项目不提供浏览器 WASM 版本。**

---

## 2. 安装

### Rust

```bash
cargo add did-sdk
```

发布前从仓库本地引用：

```toml
[dependencies]
did-sdk = { path = "path/to/did-sdk" }
```

### Python

```bash
pip install did-sdk
```

> 尚未发布到 PyPI；当前请使用本地构建。

本地构建：

```bash
cd bindings/python
maturin build --release
pip install dist/*.whl
```

### Node

```bash
npm install @did-sdk/node
```

> 尚未发布到 npm；当前请使用本地构建。

本地构建：

```bash
cd bindings/node
npm install
npx napi build --platform --release
```

---

## 3. 免配置快速开始

全部配置项都有内置默认值：默认 `mode = mock`，默认使用 `file-keystore`，
密码缺失时自动生成随机密码并写入权限为 `0600` 的文件。

### Rust

```rust
use did_sdk::{build_did_sdk, config::resolve_config, SigningContext};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = resolve_config(Default::default())?;
    let sdk = build_did_sdk(&cfg)?;

    let did = sdk.generate_did_key().await?;
    let sig = sdk
        .sign_with_did_key(
            b"hello did-sdk",
            SigningContext {
                purpose: "smoke".into(),
                payload_summary: "quickstart".into(),
                requestor: None,
            },
        )
        .await?;

    println!("did={did}, sig_len={}", sig.0.len());
    Ok(())
}
```

### Python

```python
import asyncio
from did_sdk import DidSdk

async def main():
    sdk = DidSdk()  # 全部参数可省略
    did = await sdk.generate_did_key()
    sig = await sdk.sign_with_did_key(b"hello did-sdk", purpose="smoke")
    print(did, len(sig))

asyncio.run(main())
```

### Node / TypeScript

```ts
import { DidSdk } from "@did-sdk/node";

const sdk = new DidSdk(); // 全部参数可省略
const did = await sdk.generateDidKey();
const sig = await sdk.signWithDidKey(Buffer.from("hello did-sdk"), {
  purpose: "smoke",
});
console.log(did, sig.length);
```

---

## 4. 配置

### 4.1 内置默认值

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `mode` | `mock` | 零外部依赖，进程内可用 |
| `vc_storage_path` | `{DID_SDK_HOME}/vc_store` | `DID_SDK_HOME` 默认 `dirs::data_dir()/did-sdk` |
| `key_vault.scheme` | `file-keystore` | POC 唯一持久化实现 |
| `key_vault.path` | `{DID_SDK_HOME}/identity-keys` | |
| `key_vault.password_env` | `DID_SDK_KEYVAULT_PASSWORD` | 密码优先从此环境变量读取 |
| `key_vault.password_file` | `{DID_SDK_HOME}/keyvault.password` | 环境变量缺失时的回退 |
| `key_vault.allow_auto_generate_password` | `true` | 自动生成随机密码并 `warn` |
| `centralized_endpoint` | `http://127.0.0.1:8080` | |
| `chain_endpoint` | `ws://127.0.0.1:9944` | |
| `cache_ttl_secs` | `600` | `get_anchor` 本地 TTL |

### 4.2 环境变量

| 环境变量 | 覆盖项 |
|---|---|
| `DID_SDK_HOME` | 根目录 |
| `DID_SDK_MODE` | `mock` / `centralized` / `chain` |
| `DID_SDK_CONFIG_FILE` | TOML 配置文件路径 |
| `DID_SDK_VC_STORAGE_PATH` | `vc_storage_path` |
| `DID_SDK_KEYVAULT_SCHEME` | `file-keystore` / `memory-keystore` |
| `DID_SDK_KEYVAULT_PATH` | `key_vault.path` |
| `DID_SDK_KEYVAULT_PASSWORD` | 密码（最高优先） |
| `DID_SDK_KEYVAULT_PASSWORD_FILE` | 密码文件路径 |
| `DID_SDK_CENTRALIZED_ENDPOINT` | Centralized 端点 |
| `DID_SDK_CHAIN_ENDPOINT` | Chain 端点 |
| `DID_SDK_CACHE_TTL_SECS` | TTL |

### 4.3 优先级

**显式 overrides > 环境变量 > 可选 TOML 文件 > 内置默认值。**

密码单独一条链：

`DID_SDK_KEYVAULT_PASSWORD` → `password_file` → 自动生成（仅当
`allow_auto_generate_password = true`）→ 报错。

### 4.4 可选 TOML

见 [`configs/did-sdk.toml.example`](configs/did-sdk.toml.example)。所有字段可省略，
省略时保持默认值；只有设置了 `DID_SDK_CONFIG_FILE` 或默认路径存在时才读取。

---

## 5. 模式切换

```bash
DID_SDK_MODE=centralized DID_SDK_CENTRALIZED_ENDPOINT=http://127.0.0.1:8080 ./app
```

或在构造函数 / `resolve_config` 中显式覆盖。三种模式共享同一套 `DidSdk` 接口与
VC / 签名对象格式，切换模式不需要改业务代码。

| 模式 | 链上依赖 | 写操作 | 说明 |
|---|---|---|---|
| `mock` | 无 | 进程内 / 本地 | 支持 `with_preloaded_anchors`、`with_auto_confirm`、`with_auto_reject`、`with_signing_delay` |
| `centralized` | HTTP 只读 | 本地 | 只调用 `GET /anchors/{id}`、`GET /dids/{did}`，带 TTL 缓存 |
| `chain` | Substrate 只读 | 本地 | 不注入任何链账户签名者；只读 storage |

---

## 6. `UserRejected` 语义

| 语言 | 观察方式 |
|---|---|
| Rust | `DidSdkError::UserRejected` |
| Python | `except did_sdk.UserRejectedError`（`RuntimeError` 子类） |
| Node | `err.code === "UserRejected"` |

拒绝不通过字符串比较判断；三端都由 Rust 核心的同一错误透传路径产生：

`KeyVaultError::UserRejected`（未来设备安全区）或 `MockDidSdk::AutoReject`
→ `DidSdkError::UserRejected` → 绑定层异常。

---

## 7. 安全模型

- 私钥只存在于 `KeyVault` 内部；`Keypair` 不实现 `Serialize` / `Clone`，trait 无导出方法。
- `FileKeystore` 使用 **Argon2id** 派生密钥、**ChaCha20-Poly1305** 加密；
  每个密钥文件独立 salt/nonce。
- 密钥文件、`index.json` 均为原子写（同目录临时文件 + rename）。
- 自动生成的密码文件在 Unix 上权限为 `0600`；Windows 上仅创建文件。
- 三语言绑定共享同一套 Rust 核心配置解析，密码 / 文件权限 / 环境变量语义一致。
- `Chain` 模式只读，**不注入链账户私钥**。
- HTTP 仅使用 `rustls`，不引入 OpenSSL / native-tls。

---

## 8. 平台与静态链接

| 目标 | Rust 核心 | Python wheel | Node addon |
|---|---|---|---|
| `x86_64-unknown-linux-musl` | 完全静态（`file` 断言） | musllinux | Linux x64 musl |
| `aarch64-unknown-linux-musl` | 完全静态（`file` 断言） | musllinux | Linux arm64 musl |
| `x86_64-unknown-linux-gnu` | — | manylinux | Linux x64 gnu |
| `aarch64-apple-darwin` | 原生 | macosx arm64 | macOS arm64 |
| `x86_64-pc-windows-msvc` | 原生 | win_amd64 | Windows x64 |

Rust 侧 Linux musl 产物要求 `ldd` 报 `not a dynamic executable`；
Python / Node 产物不追求静态链接，libc 依赖由目标平台生态处理。

---

## 9. 未来扩展：`keyvault-device` / `keyvault-server`

未来接入 Keychain / Keystore / TPM / KMS/HSM 时：

1. 新增 crate 实现 `keyvault_core::KeyVault`；
2. 在 `did-sdk/src/config.rs` 的 `build_vault()` 增加 feature 门控分支；
3. 业务代码、`DidSdk` trait、Python/Node 绑定 **不需要修改**。

`KeyVaultError::UserRejected` 与 `DidSdkError::UserRejected` 已为此预留。

---

## 10. 开发

### 10.1 工具链

- Rust **1.88.0**（`rust-toolchain.toml` 已固定；edition 2024）
- Python ≥ 3.9 + `maturin`
- Node ≥ 18 + npm

本机初始化环境为 macOS arm64；为在沙箱内验证，1.88.0 安装到了仓库本地
`.rustup/`（已 gitignore），cargo 缓存放在 `.cargo-home/`。本地执行时可用：

```bash
export RUSTUP_HOME="$PWD/.rustup"
export RUSTUP_TOOLCHAIN=1.88.0
export CARGO_HOME="$PWD/.cargo-home"
```

普通开发机直接 `rustup toolchain install 1.88.0` 即可，不需要上述变量。
CI 使用 `dtolnay/rust-toolchain@1.88.0`。

### 10.2 常用命令

```bash
cargo fmt --all -- --check
cargo clippy --workspace --exclude did-sdk-python --exclude did-sdk-node -- -D warnings
cargo test --workspace --exclude did-sdk-python --exclude did-sdk-node

# 三套产物
bash scripts/build-rust-musl.sh
bash scripts/build-python.sh
bash scripts/build-node.sh

# 三语言 golden vector
bash scripts/cross-lang-vectors.sh
```

### 10.3 仓库结构

```text
did-sdk/
├── src/                    # Rust 核心：config / types / error / mock / centralized / chain / vc / ...
├── keyvault-core/          # KeyVault trait + FileKeystore + MemoryKeystore + crypto
├── bindings/python/        # PyO3 + maturin
├── bindings/node/          # napi-rs
├── tests/                  # 集成测试 + 三语言 golden vector
├── examples/mini_cli.rs    # musl 静态链接验证
├── scripts/                # 构建与向量校验
├── configs/                # TOML 示例
├── docs/                   # 实施计划、验收清单
└── .github/workflows/      # CI / 四平台构建 / 三语言向量
```

---

## 11. 许可证

Apache-2.0，详见 [`LICENSE`](LICENSE)。
