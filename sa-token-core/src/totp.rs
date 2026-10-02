// Author: 金书记 | Author: Jin Shuji
//
//! TOTP (Java `SaTotpTemplate` / `SaTotpUtil`).
//! TOTP 动态口令，对齐 Java `SaTotpTemplate`。

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::error::{SaTokenError, SaTokenResult};
use crate::http_basic::ct_eq;

/// Default time-step in seconds (RFC 6238).
/// 默认时间窗口步长（秒）。
pub const DEFAULT_TIME_STEP: u64 = 30;
/// Default OTP width.
/// 默认验证码位数。
pub const DEFAULT_CODE_DIGITS: u32 = 6;
/// Default HMAC algorithm name (Java `HmacSHA1`).
/// 默认 HMAC 算法名。
pub const DEFAULT_HMAC_ALGORITHM: &str = "HmacSHA1";
/// Default secret length in bytes.
/// 默认密钥字节数。
pub const DEFAULT_SECRET_KEY_LENGTH: usize = 16;

/// TOTP generator / verifier (Java `SaTotpTemplate`).
/// TOTP 生成与校验（对齐 Java `SaTotpTemplate`）。
#[derive(Debug, Clone)]
pub struct SaTotpTemplate {
    /// Time-step in seconds.
    /// 时间窗口步长（秒）。
    pub time_step: u64,
    /// Number of OTP digits.
    /// 验证码位数。
    pub code_digits: u32,
    /// HMAC algorithm name (`HmacSHA1`).
    /// HMAC 算法名。
    pub hmac_algorithm: String,
    /// Secret key length in bytes.
    /// 密钥字节数。
    pub secret_key_length: usize,
}

impl Default for SaTotpTemplate {
    fn default() -> Self {
        Self {
            time_step: DEFAULT_TIME_STEP,
            code_digits: DEFAULT_CODE_DIGITS,
            hmac_algorithm: DEFAULT_HMAC_ALGORITHM.to_string(),
            secret_key_length: DEFAULT_SECRET_KEY_LENGTH,
        }
    }
}

impl SaTotpTemplate {
    /// Construct with Java-style parameters.
    /// 使用与 Java 构造函数对应的参数创建。
    pub fn new(
        time_step: u64,
        code_digits: u32,
        hmac_algorithm: impl Into<String>,
        secret_key_length: usize,
    ) -> Self {
        Self {
            time_step,
            code_digits,
            hmac_algorithm: hmac_algorithm.into(),
            secret_key_length,
        }
    }

    /// Generate a random Base32 secret (no padding).
    /// 生成随机 Base32 密钥（无 padding）。
    pub fn generate_secret_key(&self) -> String {
        let mut bytes = vec![0u8; self.secret_key_length];
        if bytes.is_empty() || getrandom::getrandom(&mut bytes).is_err() {
            return String::new();
        }
        data_encoding::BASE32_NOPAD.encode(&bytes)
    }

    /// Generate the current-window TOTP code.
    /// 生成当前时间窗口的 TOTP 验证码。
    pub fn generate_totp(&self, secret: &str) -> String {
        self.generate_totp_at(secret, unix_now())
    }

    /// Validate `code` against the current window ± `time_window_offset`.
    /// 在当前窗口 ± `time_window_offset` 内校验验证码。
    pub fn validate_totp(&self, secret: &str, code: &str, time_window_offset: i32) -> bool {
        let width = self.code_digits as usize;
        if code.len() != width {
            return false;
        }
        let step = self.time_step.max(1);
        let current_window = unix_now() / step;
        for i in -time_window_offset..=time_window_offset {
            let window = current_window.saturating_add_signed(i64::from(i));
            let calculated = self.generate_totp_at(secret, window.saturating_mul(step));
            if ct_eq(calculated.as_bytes(), code.as_bytes()) {
                return true;
            }
        }
        false
    }

    /// Check TOTP; fail with `TotpAuthFailed`.
    /// 校验 TOTP，失败返回 `TotpAuthFailed`。
    pub fn check_totp(
        &self,
        secret: &str,
        code: &str,
        time_window_offset: i32,
    ) -> SaTokenResult<()> {
        if self.validate_totp(secret, code, time_window_offset) {
            Ok(())
        } else {
            Err(SaTokenError::TotpAuthFailed)
        }
    }

    /// `otpauth://totp/{account}?secret={secret}` with a fresh secret.
    /// 生成带新密钥的 Google Authenticator URI。
    pub fn generate_google_secret_key(&self, account: &str) -> String {
        self.generate_google_secret_key_with_secret(account, &self.generate_secret_key())
    }

    /// `otpauth://totp/{account}?secret={secret}`.
    pub fn generate_google_secret_key_with_secret(&self, account: &str, secret: &str) -> String {
        format!("otpauth://totp/{account}?secret={secret}")
    }

    /// `otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}`.
    pub fn generate_google_secret_key_with_issuer(
        &self,
        account: &str,
        issuer: &str,
        secret: &str,
    ) -> String {
        format!("otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}")
    }

    fn generate_totp_at(&self, secret: &str, time: u64) -> String {
        let key = match decode_base32(secret) {
            Some(bytes) if !bytes.is_empty() => bytes,
            _ => return String::new(),
        };
        let step = self.time_step.max(1);
        let counter = time / step;
        let mut mac = match Hmac::<Sha1>::new_from_slice(&key) {
            Ok(mac) => mac,
            Err(_) => return String::new(),
        };
        mac.update(&counter.to_be_bytes());
        let hash = mac.finalize().into_bytes();
        dynamic_truncate(hash.as_slice(), self.code_digits)
    }
}

/// Generate a random Base32 secret (no padding).
/// 生成随机 Base32 密钥（无 padding）。
pub fn generate_secret_key() -> String {
    SaTotpTemplate::default().generate_secret_key()
}

/// Generate the current-window TOTP code.
/// 生成当前时间窗口的 TOTP 验证码。
pub fn generate_totp(secret: &str) -> String {
    SaTotpTemplate::default().generate_totp(secret)
}

/// Validate `code` against the current window ± `time_window_offset`.
/// 在当前窗口 ± `time_window_offset` 内校验验证码。
pub fn validate_totp(secret: &str, code: &str, time_window_offset: i32) -> bool {
    SaTotpTemplate::default().validate_totp(secret, code, time_window_offset)
}

/// Check TOTP; fail with `TotpAuthFailed`.
/// 校验 TOTP，失败返回 `TotpAuthFailed`。
pub fn check_totp(secret: &str, code: &str, time_window_offset: i32) -> SaTokenResult<()> {
    SaTotpTemplate::default().check_totp(secret, code, time_window_offset)
}

/// `otpauth://totp/{account}?secret={secret}` with a fresh secret.
pub fn generate_google_secret_key(account: &str) -> String {
    SaTotpTemplate::default().generate_google_secret_key(account)
}

/// `otpauth://totp/{account}?secret={secret}`.
pub fn generate_google_secret_key_with_secret(account: &str, secret: &str) -> String {
    SaTotpTemplate::default().generate_google_secret_key_with_secret(account, secret)
}

/// `otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}`.
pub fn generate_google_secret_key_with_issuer(account: &str, issuer: &str, secret: &str) -> String {
    SaTotpTemplate::default().generate_google_secret_key_with_issuer(account, issuer, secret)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn decode_base32(secret: &str) -> Option<Vec<u8>> {
    let mut cleaned: String = secret
        .chars()
        .filter(|c| *c != '=' && !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return None;
    }
    while cleaned.len() % 8 != 0 {
        cleaned.push('=');
    }
    data_encoding::BASE32.decode(cleaned.as_bytes()).ok()
}

fn dynamic_truncate(hash: &[u8], code_digits: u32) -> String {
    let offset = usize::from(hash.last().copied().unwrap_or(0) & 0x0f);
    let chunk = hash
        .get(offset..offset.saturating_add(4))
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .unwrap_or([0; 4]);
    let [b0, b1, b2, b3] = chunk;
    let binary =
        (u32::from(b0 & 0x7f) << 24) | (u32::from(b1) << 16) | (u32::from(b2) << 8) | u32::from(b3);
    let digits = code_digits.max(1);
    let modulo = 10u32.saturating_pow(digits);
    let otp = if modulo == 0 { 0 } else { binary % modulo };
    let width = digits as usize;
    format!("{otp:0width$}")
}
