// Author: 金书记 | Author: Jin Shuji
//! OS CSPRNG helpers for token material.
//! 操作系统 CSPRNG，用于生成 token 材料。

use crate::error::{SaTokenError, SaTokenResult};

/// Fill `buf` from the OS CSPRNG.
/// 用操作系统 CSPRNG 填满 `buf`。
pub(super) fn fill_bytes(buf: &mut [u8]) -> SaTokenResult<()> {
    getrandom::getrandom(buf)
        .map_err(|e| SaTokenError::InternalError(format!("CSPRNG unavailable: {e}")))
}

/// `length` hex characters (each byte → 2 hex chars). Odd length truncates the last nibble display.
/// `length` 个 hex 字符（每字节 2 个 hex）。奇数长度截断最后半字节的显示。
pub(crate) fn random_hex(length: usize) -> SaTokenResult<String> {
    if length == 0 {
        return Err(SaTokenError::ConfigError(
            "random token length must be > 0".into(),
        ));
    }
    let byte_len = length.div_ceil(2);
    let mut buf = vec![0u8; byte_len];
    fill_bytes(&mut buf)?;
    let hex = hex::encode(&buf);
    // hex.len() == byte_len * 2 >= length
    Ok(hex[..length].to_string())
}

const ALNUM_CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `len` characters from `[A-Za-z0-9]`, unbiased (reject samples >= 248).
/// `len` 位 `[A-Za-z0-9]`，拒绝采样避免取模偏差（丢弃 >= 248 的字节）。
pub(crate) fn random_alnum(len: usize) -> SaTokenResult<String> {
    if len == 0 {
        return Err(SaTokenError::ConfigError(
            "random alphanumeric length must be > 0".into(),
        ));
    }
    let mut out = String::with_capacity(len);
    let max_unbiased = (256 / ALNUM_CHARSET.len()) * ALNUM_CHARSET.len(); // 248
    let mut buf = [0u8; 32];
    while out.len() < len {
        fill_bytes(&mut buf)?;
        for b in buf {
            if out.len() >= len {
                break;
            }
            if (b as usize) < max_unbiased {
                out.push(
                    ALNUM_CHARSET
                        .get((b as usize) % ALNUM_CHARSET.len())
                        .copied()
                        .unwrap_or(b'0') as char,
                );
            }
        }
    }
    Ok(out)
}

/// 8-char alphanumeric token without modulo bias (reject samples >= 248).
/// 8 位字母数字 token，拒绝采样避免取模偏差（丢弃 >= 248 的字节）。
pub(super) fn random_tik(len: usize) -> SaTokenResult<String> {
    random_alnum(len)
}
