//! SS58 地址编解码（Substrate AccountId32）。
//!
//! 布局：prefix(1 或 2 字节) | account_id(32) | checksum(2)
//! checksum = BLAKE2b-512(b"SS58PRE" || prefix || account_id)[0..2]

use crate::KeyVaultError;
use crate::crypto::blake2::blake2b512;

const SS58_PREFIX: &[u8] = b"SS58PRE";
const ACCOUNT_ID_LEN: usize = 32;

/// 从 SS58 地址解析 32 字节 AccountId。
pub fn ss58_to_account_id(ss58: &str) -> Result<[u8; 32], KeyVaultError> {
    let data = bs58::decode(ss58).into_vec().map_err(|error| {
        KeyVaultError::InvalidKeyFormat(format!("invalid SS58 base58: {error}"))
    })?;
    let (prefix_len, _prefix) = decode_prefix(&data)?;
    if data.len() != prefix_len + ACCOUNT_ID_LEN + 2 {
        return Err(KeyVaultError::InvalidKeyFormat(format!(
            "invalid SS58 length: {}",
            data.len()
        )));
    }
    let account_start = prefix_len;
    let account_end = account_start + ACCOUNT_ID_LEN;
    let mut account = [0u8; 32];
    account.copy_from_slice(&data[account_start..account_end]);
    let checksum = &data[account_end..];
    let expected = ss58_checksum(&data[..account_end]);
    if checksum != &expected[..2] {
        return Err(KeyVaultError::InvalidKeyFormat(
            "SS58 checksum mismatch".into(),
        ));
    }
    Ok(account)
}

/// 从 32 字节 AccountId 生成 SS58 地址。
pub fn account_id_to_ss58(account_id: &[u8; 32], prefix: u16) -> String {
    let mut data = encode_prefix(prefix);
    data.extend_from_slice(account_id);
    let checksum = ss58_checksum(&data);
    data.extend_from_slice(&checksum[..2]);
    bs58::encode(data).into_string()
}

fn encode_prefix(prefix: u16) -> Vec<u8> {
    if prefix < 64 {
        vec![prefix as u8]
    } else {
        let first = (((prefix & 0b0000_0000_1111_1100) >> 2) as u8) | 0b0100_0000;
        let second = ((prefix >> 8) as u8) | (((prefix & 0b0000_0000_0000_0011) << 6) as u8);
        vec![first, second]
    }
}

fn decode_prefix(data: &[u8]) -> Result<(usize, u16), KeyVaultError> {
    let Some(first) = data.first().copied() else {
        return Err(KeyVaultError::InvalidKeyFormat("empty SS58".into()));
    };
    if first & 0b0100_0000 == 0 {
        Ok((1, u16::from(first)))
    } else {
        let Some(second) = data.get(1).copied() else {
            return Err(KeyVaultError::InvalidKeyFormat(
                "truncated SS58 prefix".into(),
            ));
        };
        let prefix = (u16::from(first & 0b0011_1111) << 2) | (u16::from(second) >> 6);
        Ok((2, prefix))
    }
}

fn ss58_checksum(data: &[u8]) -> [u8; 64] {
    let mut input = Vec::with_capacity(SS58_PREFIX.len() + data.len());
    input.extend_from_slice(SS58_PREFIX);
    input.extend_from_slice(data);
    blake2b512(&input)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn roundtrip_prefixes() {
        for prefix in [0u16, 2, 42, 64, 1000, 16383] {
            let account = [7u8; 32];
            let ss58 = account_id_to_ss58(&account, prefix);
            assert_eq!(
                ss58_to_account_id(&ss58).unwrap(),
                account,
                "prefix {prefix}"
            );
        }
    }

    #[test]
    fn rejects_bad_checksum() {
        let account = [1u8; 32];
        let mut ss58 = account_id_to_ss58(&account, 42);
        ss58.pop();
        ss58.push('x');
        assert!(ss58_to_account_id(&ss58).is_err());
    }
}
