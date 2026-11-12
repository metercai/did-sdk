"""did-sdk Python 绑定。

与 Rust 核心共享同一套签名对象、配置解析与错误映射。
"""

from ._did_sdk import (
    DidSdk,
    DidSdkError,
    InvalidArgumentError,
    NotFoundError,
    UserRejectedError,
)

__version__ = "0.1.0"

__all__ = [
    "DidSdk",
    "DidSdkError",
    "InvalidArgumentError",
    "NotFoundError",
    "UserRejectedError",
]
