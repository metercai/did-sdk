//! 签名对象构造：纯函数，不涉及存储。
//!
//! 三语言共享 `tests/vectors/signing_vectors.json` 作为唯一事实源；
//! 行序、分隔符与是否带尾随换行都必须逐字节一致。

/// 构造 `DID-Signature-v1` 的待签名字节。
///
/// 格式：
/// ```text
/// DID-Signature-v1
/// {did}
/// {from}
/// {timestamp}
/// {anchor_ref}
/// {body_hash}
/// {rcpt_hash}
/// ```
/// 行之间用 `\n` 分隔，**末尾不带换行**。
pub fn did_signature_v1(
    did: &str,
    from: &str,
    timestamp: u64,
    anchor_ref: &str,
    body_hash: &str,
    rcpt_hash: &str,
) -> Vec<u8> {
    format!("DID-Signature-v1\n{did}\n{from}\n{timestamp}\n{anchor_ref}\n{body_hash}\n{rcpt_hash}")
        .into_bytes()
}

/// 构造 `IssuedVc-v1` 的待签名字节。
///
/// 格式：
/// ```text
/// IssuedVc-v1
/// {issuer_did}
/// {subject_did}
/// {vc_type}
/// {vc_hash}
/// ```
pub fn issued_vc_v1(issuer_did: &str, subject_did: &str, vc_type: &str, vc_hash: &str) -> Vec<u8> {
    format!("IssuedVc-v1\n{issuer_did}\n{subject_did}\n{vc_type}\n{vc_hash}").into_bytes()
}

/// 构造 `GatewayAccess-v1` 的待签名字节。
///
/// 格式：
/// ```text
/// GatewayAccess-v1
/// {did}
/// {agent_email}
/// {challenge}
/// ```
pub fn gateway_access_v1(did: &str, agent_email: &str, challenge: &str) -> Vec<u8> {
    format!("GatewayAccess-v1\n{did}\n{agent_email}\n{challenge}").into_bytes()
}

/// 构造 `VP-v1` 的待签名字节（规格未定义，评审决策 D-06 新增）。
///
/// 格式：
/// ```text
/// VP-v1
/// {holder}
/// {challenge}
/// {domain}
/// {vc_hash_1}
/// ...
/// {vc_hash_n}
/// ```
/// `vc_hashes` 为空时保留前三行；每个 hash 单独一行，末尾不带换行。
pub fn vp_v1(holder: &str, challenge: &str, domain: &str, vc_hashes: &[String]) -> Vec<u8> {
    let mut out = format!("VP-v1\n{holder}\n{challenge}\n{domain}");
    for hash in vc_hashes {
        out.push('\n');
        out.push_str(hash);
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn no_trailing_newline() {
        let bytes = did_signature_v1("d", "f", 1, "a", "b", "c");
        assert!(!bytes.ends_with(b"\n"));
        assert_eq!(String::from_utf8(bytes).unwrap().lines().count(), 7);
    }

    #[test]
    fn vp_hashes_are_one_per_line() {
        let bytes = vp_v1("d", "c", "x", &["h1".into(), "h2".into()]);
        assert_eq!(String::from_utf8(bytes).unwrap(), "VP-v1\nd\nc\nx\nh1\nh2");
    }
}
