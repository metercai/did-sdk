# Chain 元数据说明

`docs/implementation-plan.md`（决策 D-14）约定：POC 阶段 **不把某个具体链的
`identity_chain.scale` 元数据提交进仓库**。

原因：

1. 仓库内没有该链的 pallet 名称、存储项名称与 SCALE 类型定义；
2. 提交错误或过期的元数据会让 `ChainModeDidSdk` 在编译期通过、运行时全部失败；
3. `subxt` 支持连接节点后在线获取 metadata，Chain 模式按运行时元数据做动态查询。

P6 验收时若拿到真实链的元数据，再：

```bash
# 例：从本地节点导出元数据（具体命令由链维护方提供）
subxt metadata --url ws://127.0.0.1:9944 -o metadata/identity_chain.scale
```

并把文件提交到本目录，同时在 `chain.rs` 中启用静态元数据路径。
