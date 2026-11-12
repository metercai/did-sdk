"use strict";

// 原生错误只有 napi Status（如 GenericFailure）；这里按 reason 前缀补上稳定的
// `err.code`，与 Rust/Python 的 UserRejected / NotFound / InvalidArgument 对齐。
const native = require("./index.js");

function normalize(error) {
  if (!error || typeof error !== "object") return error;
  const message = String(error.message || "");
  const prefixes = ["UserRejected", "NotFound", "InvalidArgument", "DidSdkError"];
  for (const prefix of prefixes) {
    if (message.startsWith(`${prefix}:`)) {
      error.code = prefix;
      break;
    }
  }
  return error;
}

function wrap(fn) {
  return function wrapped(...args) {
    try {
      const result = fn.apply(this, args);
      if (result && typeof result.then === "function") {
        return result.catch((error) => {
          throw normalize(error);
        });
      }
      return result;
    } catch (error) {
      throw normalize(error);
    }
  };
}

for (const name of Object.getOwnPropertyNames(native.DidSdk.prototype)) {
  if (name === "constructor") continue;
  const descriptor = Object.getOwnPropertyDescriptor(native.DidSdk.prototype, name);
  if (descriptor && typeof descriptor.value === "function") {
    native.DidSdk.prototype[name] = wrap(descriptor.value);
  }
}

module.exports = { ...native, DidSdk: native.DidSdk };
