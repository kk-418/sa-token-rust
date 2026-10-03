// Author: 金书记 | Author: Jin Shuji
//! Request signing (HMAC-SHA256 or Java `SaSignTemplate` MD5).
//! 请求签名（HMAC-SHA256 或 Java `SaSignTemplate` MD5）。
//!
//! Shared by SSO HTTP and any open API that wants the same canonical query.
//! SSO HTTP 与需要同一套规范查询串的开放 API 共用本类型。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use sha2::Sha256;

use crate::compat::{SignAlgorithm, SignNonceFormat};
use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::http_basic::ct_eq;

type HmacSha256 = Hmac<Sha256>;

/// Query/body signing helper.
/// 查询串/表单体签名。
#[derive(Clone)]
pub struct RequestSign {
    secret: String,
    window_secs: i64,
    dao: Option<Arc<SaTokenDao>>,
    algorithm: Option<SignAlgorithm>,
}

impl std::fmt::Debug for RequestSign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RequestSign { .. }")
    }
}

impl RequestSign {
    /// Create a signer with secret and timestamp window (seconds).
    /// 使用密钥与时间窗（秒）创建签名器。
    pub fn new(secret: impl Into<String>, window_secs: i64) -> Self {
        Self {
            secret: secret.into(),
            window_secs: if window_secs > 0 { window_secs } else { 300 },
            dao: None,
            algorithm: None,
        }
    }

    /// Attach Dao so nonce values can be consumed once.
    /// 挂载 Dao，使 nonce 只能使用一次。
    pub fn with_dao(mut self, dao: Arc<SaTokenDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// Override the sign algorithm. Default: Dao `wire.sign_algorithm`, else HMAC-SHA256.
    /// 覆盖签名算法。默认取 Dao `wire.sign_algorithm`，否则 HMAC-SHA256。
    pub fn with_algorithm(mut self, algorithm: SignAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    fn algorithm(&self) -> SignAlgorithm {
        if let Some(alg) = self.algorithm {
            return alg;
        }
        self.dao
            .as_ref()
            .map(|d| d.config().wire.sign_algorithm)
            .unwrap_or(SignAlgorithm::HmacSha256)
    }

    fn canonical_hmac(params: &BTreeMap<String, String>) -> String {
        params
            .iter()
            .filter(|(k, _)| k.as_str() != "sign")
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// Java `SaSignTemplate.joinParamsDictSort` + `&key={secret}`. Empty values skipped.
    /// Java `SaSignTemplate.joinParamsDictSort` 再拼 `&key={secret}`；空值跳过。
    fn canonical_md5(&self, params: &BTreeMap<String, String>) -> String {
        let body = params
            .iter()
            .filter(|(k, v)| k.as_str() != "sign" && !v.is_empty())
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        format!("{body}&key={}", self.secret)
    }

    /// Sign the canonical query (excludes the `sign` field).
    /// 对规范查询串签名（排除 `sign` 字段）。
    pub fn sign_params(&self, params: &BTreeMap<String, String>) -> SaTokenResult<String> {
        if self.secret.is_empty() {
            return Err(SaTokenError::ConfigError(
                "request sign secret is empty".into(),
            ));
        }
        match self.algorithm() {
            SignAlgorithm::HmacSha256 => {
                let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes()).map_err(|e| {
                    SaTokenError::ConfigError(format!("invalid request sign secret: {e}"))
                })?;
                mac.update(Self::canonical_hmac(params).as_bytes());
                Ok(hex::encode(mac.finalize().into_bytes()))
            }
            SignAlgorithm::Md5 => {
                let full = self.canonical_md5(params);
                Ok(hex::encode(Md5::digest(full.as_bytes())))
            }
        }
    }

    /// Insert `timestamp` + `nonce` then compute `sign`. Caller sends the whole map.
    /// 写入 `timestamp` 与 `nonce` 再计算 `sign`。调用方发送完整 map。
    pub fn create_signed(
        &self,
        mut params: BTreeMap<String, String>,
    ) -> SaTokenResult<BTreeMap<String, String>> {
        let now = match self.algorithm() {
            SignAlgorithm::HmacSha256 => chrono::Utc::now().timestamp().to_string(),
            SignAlgorithm::Md5 => chrono::Utc::now().timestamp_millis().to_string(),
        };
        let nonce = crate::token::random_hex(32)?;
        params.insert("timestamp".into(), now);
        params.insert("nonce".into(), nonce);
        let sign = self.sign_params(&params)?;
        params.insert("sign".into(), sign);
        Ok(params)
    }

    fn nonce_write(&self, nonce: &str) -> (String, u64) {
        match self
            .dao
            .as_ref()
            .map(|d| d.config().wire.sign_nonce)
            .unwrap_or(SignNonceFormat::Rust)
        {
            SignNonceFormat::Rust => ("1".into(), self.window_secs as u64),
            SignNonceFormat::Java => (nonce.to_string(), (self.window_secs * 2 + 2) as u64),
        }
    }

    fn timestamp_expired(&self, ts: i64) -> bool {
        match self.algorithm() {
            SignAlgorithm::HmacSha256 => {
                let now = chrono::Utc::now().timestamp();
                (now - ts).abs() > self.window_secs
            }
            SignAlgorithm::Md5 => {
                let now = chrono::Utc::now().timestamp_millis();
                (now - ts).abs() > self.window_secs.saturating_mul(1000)
            }
        }
    }

    /// Verify signature, timestamp window, and optional nonce uniqueness.
    /// 校验签名、时间窗与可选 nonce 唯一性。
    pub async fn verify_params(
        &self,
        params: &BTreeMap<String, String>,
        provided_sign: &str,
    ) -> SaTokenResult<()> {
        if self.secret.is_empty() {
            return Err(SaTokenError::ConfigError(
                "request sign secret is empty".into(),
            ));
        }
        let ts = params
            .get("timestamp")
            .and_then(|s| s.parse::<i64>().ok())
            .ok_or(SaTokenError::SignTimestampExpired)?;
        if self.timestamp_expired(ts) {
            return Err(SaTokenError::SignTimestampExpired);
        }
        if let (Some(nonce), Some(dao)) = (params.get("nonce"), self.dao.as_ref()) {
            // Dedicated key space so login nonces and request-sign nonces never collide.
            // 独立键空间，避免登录 nonce 与请求签名 nonce 互相占位。
            let nkey = dao.keys().sign_nonce(nonce);
            let (value, ttl_secs) = self.nonce_write(nonce);
            let inserted = dao
                .set_if_absent(&nkey, &value, Some(Duration::from_secs(ttl_secs)))
                .await?;
            if !inserted {
                return Err(SaTokenError::NonceAlreadyUsed);
            }
        }
        let expected = self.sign_params(params)?;
        if !ct_eq(expected.as_bytes(), provided_sign.as_bytes()) {
            return Err(SaTokenError::SignInvalid);
        }
        Ok(())
    }
}

/// Map generic sign errors onto SSO-facing variants used by existing match arms.
/// 把通用签名错误映射为 SSO 现有匹配臂使用的变体。
pub fn map_sign_err_to_sso(err: SaTokenError) -> SaTokenError {
    match err {
        SaTokenError::SignInvalid => SaTokenError::SsoSignInvalid,
        SaTokenError::SignTimestampExpired => SaTokenError::TicketExpired,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaTokenConfig;
    use sa_token_storage_memory::MemoryStorage;
    use std::sync::Arc;

    #[test]
    fn md5_matches_java_sa_sign_template() {
        let sign = RequestSign::new("secret", 300).with_algorithm(SignAlgorithm::Md5);
        let mut params = BTreeMap::new();
        params.insert("loginId".into(), "10001".into());
        params.insert("nonce".into(), "abc".into());
        params.insert("timestamp".into(), "1700000000000".into());
        assert_eq!(
            sign.sign_params(&params).unwrap(),
            "943f8792b48ba07bbe6ad696565e41be"
        );
    }

    #[test]
    fn md5_skips_empty_and_appends_key() {
        let sign = RequestSign::new("secret", 300).with_algorithm(SignAlgorithm::Md5);
        let mut params = BTreeMap::new();
        params.insert("a".into(), "1".into());
        params.insert("empty".into(), String::new());
        params.insert("sign".into(), "ignored".into());
        assert_eq!(
            sign.sign_params(&params).unwrap(),
            "8dbb43445edb78bd6a55900584213e82"
        );
    }

    #[test]
    fn hmac_create_signed_uses_second_timestamp() {
        let sign = RequestSign::new("secret", 300);
        let signed = sign.create_signed(BTreeMap::new()).unwrap();
        let ts = signed.get("timestamp").unwrap();
        assert!(ts.len() <= 10, "HMAC timestamp must be seconds, got {ts}");
        assert_eq!(
            signed.get("sign").unwrap().as_str(),
            sign.sign_params(&signed).unwrap()
        );
    }

    #[test]
    fn md5_create_signed_uses_millis_timestamp() {
        let sign = RequestSign::new("secret", 300).with_algorithm(SignAlgorithm::Md5);
        let signed = sign.create_signed(BTreeMap::new()).unwrap();
        let ts = signed.get("timestamp").unwrap();
        assert!(
            ts.len() >= 13,
            "MD5 timestamp must be milliseconds, got {ts}"
        );
    }

    #[tokio::test]
    async fn java_nonce_value_is_nonce_and_ttl_is_window_times_two_plus_two() {
        let mut cfg = SaTokenConfig::java_compatible();
        cfg.sign_window_secs = 300;
        cfg.sign_secret_key = Some("secret".into());
        let mgr = crate::SaTokenManager::new(Arc::new(MemoryStorage::new()), cfg);
        let sign = RequestSign::new("secret", 300).with_dao(mgr.dao().clone());
        let mut params = BTreeMap::new();
        params.insert(
            "timestamp".into(),
            chrono::Utc::now().timestamp_millis().to_string(),
        );
        params.insert("nonce".into(), "interop-nonce-001".into());
        let sig = sign.sign_params(&params).unwrap();
        sign.verify_params(&params, &sig).await.unwrap();

        let key = mgr.keys().sign_nonce("interop-nonce-001");
        assert_eq!(key, "satoken:sign:nonce:interop-nonce-001");
        assert_eq!(
            mgr.dao().get_string(&key).await.unwrap().as_deref(),
            Some("interop-nonce-001")
        );
        let ttl = mgr.dao().ttl(&key).await.unwrap().expect("ttl");
        assert!(
            ttl.as_secs() <= 602 && ttl.as_secs() > 590,
            "Java nonce ttl = window*2+2 (602), got {}",
            ttl.as_secs()
        );
        let err = sign.verify_params(&params, &sig).await.unwrap_err();
        assert!(matches!(err, SaTokenError::NonceAlreadyUsed));
    }

    #[tokio::test]
    async fn rust_nonce_value_is_one() {
        let cfg = SaTokenConfig::default();
        let mgr = crate::SaTokenManager::new(Arc::new(MemoryStorage::new()), cfg);
        let sign = RequestSign::new("secret", 300).with_dao(mgr.dao().clone());
        let mut params = BTreeMap::new();
        params.insert(
            "timestamp".into(),
            chrono::Utc::now().timestamp().to_string(),
        );
        params.insert("nonce".into(), "n1".into());
        let sig = sign.sign_params(&params).unwrap();
        sign.verify_params(&params, &sig).await.unwrap();
        assert_eq!(
            mgr.dao()
                .get_string(&mgr.keys().sign_nonce("n1"))
                .await
                .unwrap()
                .as_deref(),
            Some("1")
        );
    }
}
