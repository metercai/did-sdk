# did-sdk-server (Python)

Server 模式绑定：固定 `did:web` participant、外部 `Proof` 组装 VC、`verify_vc`、
VC 钱包；开发/测试/试运行可配置 `FileKeystore` 本地签名器。

```python
from did_sdk_server import ServerDidSdk

sdk = ServerDidSdk(
    "did:web:issuer.example.com",
    mode="mock",
    key_vault_scheme="file-keystore",
    key_vault_password="dev-password",
    vc_storage_path="./participant-vc",
)
```

生产环境可传 `key_vault_scheme="none"` 关闭本地签名器，此时 VC 加密密钥使用
`DID_SDK_VC_STORAGE_PASSWORD` 或自动生成的 `.vc_password`。
