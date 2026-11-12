# did-sdk (Python)

`did-sdk` 的 Python 绑定，基于 PyO3 + maturin，与 Rust 核心共享同一套签名对象、
配置解析与错误映射。

## 构建

```bash
maturin build --release
pip install dist/*.whl
```

## 免配置示例

```python
import asyncio
from did_sdk import DidSdk

async def main():
    sdk = DidSdk()
    did = await sdk.generate_did_key()
    print(did)

asyncio.run(main())
```

完整文档见仓库根目录 [`README.md`](../../README.md)。
