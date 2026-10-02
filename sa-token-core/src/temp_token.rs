// Author: 金书记 | Author: Jin Shuji
//! Short-lived tokens that carry a business value (share links, one-shot actions).
//! 携带业务值的短时令牌（分享链接、一次性操作授权）。

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::token::random_hex;
use crate::util::StpUtil;

/// Default namespace used in storage keys.
/// 存储键使用的默认命名空间。
pub const DEFAULT_NAMESPACE: &str = "default";

/// Persisted temp-token body.
/// 持久化的临时令牌体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempTokenRecord {
    /// Business payload (string or JSON).
    /// 业务载荷（字符串或 JSON）。
    pub value: serde_json::Value,
    /// Namespace for isolation between product lines.
    /// 产品线隔离用的命名空间。
    pub namespace: String,
    /// Absolute expiry; used when the store has not yet evicted the key.
    /// 绝对过期时间；存储尚未逐出键时仍用它判定。
    pub expire_at: Option<DateTime<Utc>>,
}

/// Temp-token operations bound to a Dao.
/// 绑定 Dao 的临时令牌操作。
#[derive(Clone)]
pub struct TempTokenManager {
    dao: Arc<SaTokenDao>,
}

impl std::fmt::Debug for TempTokenManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TempTokenManager { .. }")
    }
}

impl TempTokenManager {
    /// Construct from an existing Dao.
    /// 用已有 Dao 构造。
    pub fn new(dao: Arc<SaTokenDao>) -> Self {
        Self { dao }
    }

    fn ttl(timeout_secs: i64) -> SaTokenResult<Option<Duration>> {
        if timeout_secs == 0 {
            return Err(SaTokenError::ConfigError(
                "temp token timeout must not be 0".into(),
            ));
        }
        if timeout_secs < 0 {
            Ok(None)
        } else {
            Ok(Some(Duration::from_secs(timeout_secs as u64)))
        }
    }

    fn expire_at(timeout_secs: i64) -> Option<DateTime<Utc>> {
        if timeout_secs < 0 {
            None
        } else {
            Some(Utc::now() + chrono::Duration::seconds(timeout_secs))
        }
    }

    fn index_digest(value: &str) -> String {
        let mut h = Sha256::new();
        h.update(value.as_bytes());
        hex::encode(h.finalize())
    }

    /// Create a token. `timeout_secs < 0` means no TTL.
    /// `record_index` stores a value→token lookup (one value keeps the latest token).
    ///
    /// 创建令牌。`timeout_secs < 0` 表示不设 TTL。
    /// `record_index` 为 true 时写入 value→token 反查（同一 value 只保留最新 token）。
    pub async fn create(
        &self,
        namespace: &str,
        value: serde_json::Value,
        timeout_secs: i64,
        record_index: bool,
    ) -> SaTokenResult<String> {
        if namespace.is_empty() {
            return Err(SaTokenError::ConfigError(
                "temp token namespace must not be empty".into(),
            ));
        }
        let ttl = Self::ttl(timeout_secs)?;
        let record = TempTokenRecord {
            value: value.clone(),
            namespace: namespace.to_string(),
            expire_at: Self::expire_at(timeout_secs),
        };
        // Retry until the random key is free; 12 is the same default as login uniqueness.
        // 随机键冲突时重试；次数与登录唯一重试默认值一致。
        let mut token = String::new();
        for _ in 0..12 {
            let candidate = random_hex(32)?;
            let key = self.dao.keys().temp_token(namespace, &candidate);
            let raw = self.dao.encode(&record)?;
            if self.dao.set_if_absent(&key, &raw, ttl).await? {
                token = candidate;
                break;
            }
        }
        if token.is_empty() {
            return Err(SaTokenError::ConfigError(
                "failed to allocate a unique temp token".into(),
            ));
        }
        if record_index {
            if let Some(s) = value.as_str() {
                let ik = self
                    .dao
                    .keys()
                    .temp_index(namespace, &Self::index_digest(s));
                self.dao.set_string(&ik, &token, ttl).await?;
            }
        }
        Ok(token)
    }

    /// Parse and return the record. Missing → NotFound; clock past expire_at → Expired.
    /// 解析记录。缺失为 NotFound；已过 `expire_at` 为 Expired。
    pub async fn parse(&self, namespace: &str, token: &str) -> SaTokenResult<TempTokenRecord> {
        if token.is_empty() {
            return Err(SaTokenError::TempTokenNotFound);
        }
        let key = self.dao.keys().temp_token(namespace, token);
        let rec: TempTokenRecord = self
            .dao
            .get_object(&key)
            .await?
            .ok_or(SaTokenError::TempTokenNotFound)?;
        if let Some(exp) = rec.expire_at {
            if Utc::now() > exp {
                let _ = self.dao.delete(&key).await;
                return Err(SaTokenError::TempTokenExpired);
            }
        }
        Ok(rec)
    }

    /// Lookup the latest token for a string value (requires `record_index` at create).
    /// 按字符串业务值反查最新 token（创建时需打开 `record_index`）。
    pub async fn find_token(&self, namespace: &str, value: &str) -> SaTokenResult<String> {
        let ik = self
            .dao
            .keys()
            .temp_index(namespace, &Self::index_digest(value));
        self.dao
            .get_string(&ik)
            .await?
            .ok_or(SaTokenError::TempTokenNotFound)
    }

    /// Delete token and its string-value index when present.
    /// 删除令牌；若有字符串反查索引则一并删。
    pub async fn delete(&self, namespace: &str, token: &str) -> SaTokenResult<()> {
        let key = self.dao.keys().temp_token(namespace, token);
        if let Ok(Some(rec)) = self.dao.get_object::<TempTokenRecord>(&key).await {
            if let Some(s) = rec.value.as_str() {
                let ik = self
                    .dao
                    .keys()
                    .temp_index(namespace, &Self::index_digest(s));
                let _ = self.dao.delete(&ik).await;
            }
        }
        self.dao.delete(&key).await
    }

    /// Remaining TTL in seconds (Java `SaTempUtil.getTimeout`).
    ///
    /// Missing key → `-2`; exists with no TTL → `-1`; otherwise remaining seconds.
    /// 剩余有效期（秒）：键不存在 `-2`；存在且无 TTL `-1`；否则为剩余秒数。
    pub async fn get_timeout(&self, namespace: &str, token: &str) -> SaTokenResult<i64> {
        let key = self.dao.keys().temp_token(namespace, token);
        if !self.dao.exists(&key).await? {
            return Ok(-2);
        }
        match self.dao.ttl(&key).await? {
            None => Ok(-1),
            Some(d) => Ok(d.as_secs() as i64),
        }
    }

    /// Persist a caller-chosen token (Java `SaTempUtil.saveToken`); does not randomize.
    /// 用调用方给定的 token 写入，不随机生成。
    pub async fn save(
        &self,
        namespace: &str,
        token: &str,
        value: serde_json::Value,
        timeout_secs: i64,
    ) -> SaTokenResult<()> {
        if namespace.is_empty() {
            return Err(SaTokenError::ConfigError(
                "temp token namespace must not be empty".into(),
            ));
        }
        if token.is_empty() {
            return Err(SaTokenError::ConfigError(
                "temp token must not be empty".into(),
            ));
        }
        let ttl = Self::ttl(timeout_secs)?;
        let record = TempTokenRecord {
            value,
            namespace: namespace.to_string(),
            expire_at: Self::expire_at(timeout_secs),
        };
        let key = self.dao.keys().temp_token(namespace, token);
        self.dao.set_object(&key, &record, ttl).await
    }
}

/// StpUtil helpers using the process-global manager.
/// 使用进程内全局 Manager 的 StpUtil 辅助函数。
pub async fn create_default(value: impl Into<String>, timeout_secs: i64) -> SaTokenResult<String> {
    let manager = StpUtil::try_get_manager()?;
    TempTokenManager::new(manager.dao().clone())
        .create(
            DEFAULT_NAMESPACE,
            serde_json::Value::String(value.into()),
            timeout_secs,
            false,
        )
        .await
}

/// Parse a temp token in the default namespace | 解析默认命名空间下的临时令牌
pub async fn parse_default(token: &str) -> SaTokenResult<TempTokenRecord> {
    let manager = StpUtil::try_get_manager()?;
    TempTokenManager::new(manager.dao().clone())
        .parse(DEFAULT_NAMESPACE, token)
        .await
}

/// Delete a temp token in the default namespace | 删除默认命名空间下的临时令牌
pub async fn delete_default(token: &str) -> SaTokenResult<()> {
    let manager = StpUtil::try_get_manager()?;
    TempTokenManager::new(manager.dao().clone())
        .delete(DEFAULT_NAMESPACE, token)
        .await
}

/// Remaining TTL of a temp token in the default namespace.
/// 默认命名空间下临时令牌的剩余 TTL。
pub async fn get_timeout_default(token: &str) -> SaTokenResult<i64> {
    let manager = StpUtil::try_get_manager()?;
    TempTokenManager::new(manager.dao().clone())
        .get_timeout(DEFAULT_NAMESPACE, token)
        .await
}

/// Save a caller-chosen temp token in the default namespace.
/// 在默认命名空间写入调用方指定的临时令牌。
pub async fn save_default(
    token: &str,
    value: serde_json::Value,
    timeout_secs: i64,
) -> SaTokenResult<()> {
    let manager = StpUtil::try_get_manager()?;
    TempTokenManager::new(manager.dao().clone())
        .save(DEFAULT_NAMESPACE, token, value, timeout_secs)
        .await
}
