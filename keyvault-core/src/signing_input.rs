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

/// 选择性披露 VP 的签名对象（selective disclosure 扩展）。
///
/// 格式：
/// ```text
/// VP-SD-v1
/// {holder}
/// {challenge}
/// {domain}
/// {disclosures_hash}
/// {vc_hash_1}
/// {vc_hash_2}
/// ...
/// ```
///
/// `vc_hash` 是完整 VC JSON 的 SHA-256（hex）；`disclosures_hash` 是
/// Disclosures 数组 canonical JSON 的 SHA-256（hex）。
pub fn vp_sd_v1(
    holder: &str,
    challenge: &str,
    domain: &str,
    disclosures_hash: &str,
    vc_hashes: &[String],
) -> Vec<u8> {
    let mut out = format!("VP-SD-v1\n{holder}\n{challenge}\n{domain}\n{disclosures_hash}");
    for hash in vc_hashes {
        out.push('\n');
        out.push_str(hash);
    }
    out.into_bytes()
}

/// 参与方注册绑定声明（服务端 ChainOwner 治理）。
///
/// 格式（POC 约定；字段顺序与 `ParticipantRecord` 一致）：
/// ```text
/// ParticipantRegistration-v1
/// {participant_id}
/// {controller_did}
/// {operator}
/// {chain_role}
/// {business_types joined by ","}
/// {authorized_domains joined by ","}
/// ```
pub fn participant_registration_v1(
    participant_id: u32,
    controller_did: &str,
    operator: &str,
    chain_role: &str,
    business_types: &[String],
    authorized_domains: &[String],
) -> Vec<u8> {
    format!(
        "ParticipantRegistration-v1\n{participant_id}\n{controller_did}\n{operator}\n{chain_role}\n{}\n{}",
        business_types.join(","),
        authorized_domains.join(",")
    )
    .into_bytes()
}

/// operator 轮换声明。
///
/// 格式：
/// ```text
/// OperatorRotation-v1
/// {participant_id}
/// {new_operator}
/// {timestamp}
/// ```
pub fn operator_rotation_v1(participant_id: u32, new_operator: &str, timestamp: u64) -> Vec<u8> {
    format!("OperatorRotation-v1\n{participant_id}\n{new_operator}\n{timestamp}").into_bytes()
}

/// controller_did 轮换声明。
///
/// 格式：
/// ```text
/// ControllerDidRotation-v1
/// {participant_id}
/// {new_controller_did}
/// {timestamp}
/// ```
pub fn controller_did_rotation_v1(
    participant_id: u32,
    new_controller_did: &str,
    timestamp: u64,
) -> Vec<u8> {
    format!("ControllerDidRotation-v1\n{participant_id}\n{new_controller_did}\n{timestamp}")
        .into_bytes()
}

/// 委托锚定授权声明（路径三，用户 A 签）。
///
/// 格式：
/// ```text
/// DelegationAuthorization-v1
/// {vc_hash}
/// {delegate_did}
/// {delegate_operator}
/// {timestamp}
/// ```
pub fn delegation_authorization_v1(
    vc_hash: &str,
    delegate_did: &str,
    delegate_operator: &str,
    timestamp: u64,
) -> Vec<u8> {
    format!(
        "DelegationAuthorization-v1\n{vc_hash}\n{delegate_did}\n{delegate_operator}\n{timestamp}"
    )
    .into_bytes()
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
    fn governance_inputs_have_stable_layout() {
        let registration = participant_registration_v1(
            7,
            "did:web:issuer.example.com",
            "5GrwvaEF5zXb26Fz9rcQpDWSZ",
            "Issuer",
            &["EmailGateway".into(), "Warrant".into()],
            &["example.com".into()],
        );
        assert_eq!(
            String::from_utf8(registration).unwrap(),
            "ParticipantRegistration-v1\n7\ndid:web:issuer.example.com\n5GrwvaEF5zXb26Fz9rcQpDWSZ\nIssuer\nEmailGateway,Warrant\nexample.com"
        );
        assert_eq!(
            String::from_utf8(operator_rotation_v1(7, "5New", 9)).unwrap(),
            "OperatorRotation-v1\n7\n5New\n9"
        );
        assert_eq!(
            String::from_utf8(controller_did_rotation_v1(7, "did:web:new", 9)).unwrap(),
            "ControllerDidRotation-v1\n7\ndid:web:new\n9"
        );
        assert_eq!(
            String::from_utf8(delegation_authorization_v1("h", "did:key:z", "op", 9)).unwrap(),
            "DelegationAuthorization-v1\nh\ndid:key:z\nop\n9"
        );
    }

    #[test]
    fn vp_sd_layout() {
        let bytes = vp_sd_v1("d", "c", "x", "dh", &["h1".into(), "h2".into()]);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "VP-SD-v1\nd\nc\nx\ndh\nh1\nh2"
        );
    }

    #[test]
    fn vp_hashes_are_one_per_line() {
        let bytes = vp_v1("d", "c", "x", &["h1".into(), "h2".into()]);
        assert_eq!(String::from_utf8(bytes).unwrap(), "VP-v1\nd\nc\nx\nh1\nh2");
    }
}
