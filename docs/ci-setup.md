# GitHub Actions 接入说明

本文档说明如何把本地 `did-sdk` 仓库接入 `metercai/did-sdk`，以及如何验证
S1（Linux musl 静态）与 S3（四平台构建）。

## 1. 前置条件

- GitHub 账户/组织：`metercai`
- 仓库名：`did-sdk`
- 本地已提交 `main` 分支（当前 HEAD 见 `git log --oneline`）
- GitHub 账户有创建仓库权限

## 2. 创建仓库并推送

### 方案 A：网页创建（推荐）

1. 在 GitHub 创建空仓库 `metercai/did-sdk`（**不要**勾选 README / .gitignore / license）；
2. 在本地执行：

```bash
cd /Users/metercai/Desktop/chains/did-sdk
git remote set-url origin git@github.com:metercai/did-sdk.git   # 若尚未配置
git push -u origin main
```

若使用 HTTPS：

```bash
git remote set-url origin https://github.com/metercai/did-sdk.git
git push -u origin main
# 用户名填 metercai；密码填 Personal Access Token（repo scope），不是账户密码
```

### 方案 B：GitHub CLI

```bash
gh auth login
gh repo create metercai/did-sdk --private --source=. --remote=origin --push
```

## 3. 推送后自动运行的 workflow

| workflow | 触发 | 验证内容 |
|---|---|---|
| `ci.yml` | push / PR / 手动 | fmt、clippy -D warnings、Rust 测试 |
| `rust-musl.yml` | push / PR / 手动 | 四平台构建；Linux musl `file` 静态断言 |
| `python.yml` | push / PR / 手动 | 5 平台 wheel |
| `node.yml` | push / PR / 手动 | 5 平台 `.node` |
| `cross-lang.yml` | push / PR / 手动 | Rust/Python/Node 读取同一 golden vector |

所有 workflow 都支持 `workflow_dispatch`，可在 Actions 页面手动触发。

## 4. 验收 S1 / S3

1. 打开 Actions → `rust-musl`；
2. 四个 matrix job 全绿：
   - `x86_64-unknown-linux-musl`
   - `aarch64-unknown-linux-musl`
   - `aarch64-apple-darwin`
   - `x86_64-pc-windows-msvc`
3. 查看 musl job 的 `Verify static (musl only)` 日志：
   - `file` 输出包含 `statically linked` 或 `static-pie linked`；
   - `ldd` 输出 `not a dynamic executable`；
4. 在 `python` / `node` workflow 的 Artifacts 下载对应 wheel / `.node`。

> musl 交叉构建使用 `cargo-zigbuild` + `zig`（workflow 已安装）；
> Node musl 构建使用 `napi build --zig`。本地不安装这些工具。

## 5. 真实 Chain 集成（可选）

拿到 identity-chain 节点与 pallet 元数据后：

```bash
export DID_SDK_CHAIN_ENDPOINT=ws://127.0.0.1:9944
export DID_SDK_CHAIN_PALLET=Identity
export DID_SDK_CHAIN_ANCHOR_STORAGE=Anchors
export DID_SDK_CHAIN_DID_STORAGE=Dids
export DID_SDK_CHAIN_ANCHOR_ID=<anchor id>

cargo test --test consistency chain_anchor_integration -- --ignored --nocapture
```

## 6. 常见失败

| 现象 | 原因 | 处理 |
|---|---|---|
| musl job `file` 不含 static | 静态断言只接受 `statically linked` | 脚本已同时接受 `static-pie linked`；检查是否误用动态目标 |
| Python job 找不到 pyproject | maturin 工作目录不对 | workflow 已设置 `working-directory: bindings/python` |
| Node musl 链接失败 | 缺少 zig | workflow 已用 `setup-zig` 并在 musl 目标加 `--zig` |
| `cargo install cargo-zigbuild` 失败 | MSRV/网络 | 固定 cargo-zigbuild 版本或使用预装镜像 |
| Windows 文件权限测试失败 | Unix 权限断言 | 测试只在 `#[cfg(unix)]` 下运行 |
| `actionlint` 报 `on` 语法 | YAML 1.1 把 `on` 解析为布尔 | 使用 actionlint 校验，不要用旧 YAML 1.1 解析器 |
