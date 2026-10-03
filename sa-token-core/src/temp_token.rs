// Author: 金书记 | Author: Jin Shuji
//! Short-lived tokens that carry a business value (share links, one-shot actions).
//! 携带业务值的短时令牌（分享链接、一次性操作授权）。

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::compat::TempTokenFormat;
use crate::compat::jackson::{CLASS_LINKED_HASH_MAP, CLASS_LONG};
use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::session::SaSession;
use crate::token::random_hex;
use crate::util::StpUtil;

/// Default namespace used in storage keys.
/// 存储键使用的默认命名空间。
pub const DEFAULT_NAMESPACE: &str = "default";

/// Java raw-session dataMap key for the value→token index.
/// Java raw-session dataMap 中 value→token 索引的键。
const TEMP_TOKEN_MAP: &str = "__HD_TEMP_TOKEN_MAP";

/// Java `SaTokenDao.NEVER_EXPIRE`.
const NEVER_EXPIRE: i64 = -1;
/// Java `SaTokenDao.NOT_VALUE_EXPIRE`.
const NOT_VALUE_EXPIRE: i64 = -2;

/// Persisted temp-token body.
/// 持久化的临时令牌体。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempTokenRecord {
    /// Business payload (string or JSON).
    /// 业务载荷（字符串或 JSON）。
    pub value: Value,
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

    fn is_java_raw(&self) -> bool {
        self.dao.config().wire.temp_token_format == TempTokenFormat::JavaRaw
    }

    /// Wire default namespace (`default` native, `temp-token` Java).
    /// 配置默认命名空间（原生 `default`，Java `temp-token`）。
    fn wire_namespace(&self) -> &str {
        self.dao.config().wire.temp_token_namespace.as_str()
    }

    /// Create a token. `timeout_secs < 0` means no TTL.
    /// `record_index` stores a value→token lookup (one value keeps the latest token).
    ///
    /// 创建令牌。`timeout_secs < 0` 表示不设 TTL。
    /// `record_index` 为 true 时写入 value→token 反查（同一 value 只保留最新 token）。
    pub async fn create(
        &self,
        namespace: &str,
        value: Value,
        timeout_secs: i64,
        record_index: bool,
    ) -> SaTokenResult<String> {
        if namespace.is_empty() {
            return Err(SaTokenError::ConfigError(
                "temp token namespace must not be empty".into(),
            ));
        }
        let ttl = Self::ttl(timeout_secs)?;
        let raw = if self.is_java_raw() {
            self.dao.wire().encode_root(&value)?
        } else {
            let record = TempTokenRecord {
                value: value.clone(),
                namespace: namespace.to_string(),
                expire_at: Self::expire_at(timeout_secs),
            };
            self.dao.encode(&record)?
        };
        // Retry until the random key is free; 12 is the same default as login uniqueness.
        // 随机键冲突时重试；次数与登录唯一重试默认值一致。
        let mut token = String::new();
        for _ in 0..12 {
            let candidate = random_hex(32)?;
            let key = self.dao.keys().temp_token(namespace, &candidate);
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
            if self.is_java_raw() {
                self.add_java_index(namespace, &value, &token, timeout_secs)
                    .await?;
            } else if let Some(s) = value.as_str() {
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
        if self.is_java_raw() {
            let raw = self
                .dao
                .get_string(&key)
                .await?
                .ok_or(SaTokenError::TempTokenNotFound)?;
            let value = self.dao.wire().decode_root(&raw)?;
            return Ok(TempTokenRecord {
                value,
                namespace: namespace.to_string(),
                expire_at: None,
            });
        }
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
        if self.is_java_raw() {
            return self
                .find_java_token(namespace, &Value::String(value.to_string()))
                .await;
        }
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
        if self.is_java_raw() {
            let value = match self.dao.get_string(&key).await? {
                Some(raw) => self.dao.wire().decode_root(&raw).ok(),
                None => None,
            };
            self.dao.delete(&key).await?;
            if let Some(v) = value {
                self.remove_java_index(namespace, &v, token).await?;
            }
            return Ok(());
        }
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
        value: Value,
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
        let key = self.dao.keys().temp_token(namespace, token);
        if self.is_java_raw() {
            let raw = self.dao.wire().encode_root(&value)?;
            return self.dao.set_string(&key, &raw, ttl).await;
        }
        let record = TempTokenRecord {
            value,
            namespace: namespace.to_string(),
            expire_at: Self::expire_at(timeout_secs),
        };
        self.dao.set_object(&key, &record, ttl).await
    }

    async fn add_java_index(
        &self,
        namespace: &str,
        value: &Value,
        token: &str,
        timeout_secs: i64,
    ) -> SaTokenResult<()> {
        let value_id = java_value_id(value);
        let session_key = self.dao.keys().raw_session(namespace, &value_id);
        let mut session = match self.dao.get_session(&session_key).await? {
            Some(s) => s,
            None => SaSession::new(&session_key).with_type(namespace),
        };
        let mut map = read_temp_index(&session);
        if !map.iter().any(|(t, _)| t == token) {
            map.push((token.to_string(), ttl_to_expire_ms(timeout_secs)));
        }
        self.write_java_index(&session_key, &mut session, map).await
    }

    async fn remove_java_index(
        &self,
        namespace: &str,
        value: &Value,
        token: &str,
    ) -> SaTokenResult<()> {
        let value_id = java_value_id(value);
        let session_key = self.dao.keys().raw_session(namespace, &value_id);
        let Some(mut session) = self.dao.get_session(&session_key).await? else {
            return Ok(());
        };
        let mut map = read_temp_index(&session);
        map.retain(|(t, _)| t != token);
        self.write_java_index(&session_key, &mut session, map).await
    }

    async fn find_java_token(&self, namespace: &str, value: &Value) -> SaTokenResult<String> {
        let value_id = java_value_id(value);
        let session_key = self.dao.keys().raw_session(namespace, &value_id);
        let Some(session) = self.dao.get_session(&session_key).await? else {
            return Err(SaTokenError::TempTokenNotFound);
        };
        let map = self.adjust_java_index(&session_key, session).await?;
        map.last()
            .map(|(t, _)| t.clone())
            .ok_or(SaTokenError::TempTokenNotFound)
    }

    async fn write_java_index(
        &self,
        session_key: &str,
        session: &mut SaSession,
        map: Vec<(String, i64)>,
    ) -> SaTokenResult<()> {
        let kept = prune_temp_index(map);
        if kept.is_empty() {
            return self.dao.delete(session_key).await;
        }
        session.set_java_typed(TEMP_TOKEN_MAP, typed_long_map(&kept));
        let ttl = max_ttl_duration(&kept);
        self.dao.set_session(session_key, session, ttl).await
    }

    async fn adjust_java_index(
        &self,
        session_key: &str,
        mut session: SaSession,
    ) -> SaTokenResult<Vec<(String, i64)>> {
        let map = read_temp_index(&session);
        let kept = prune_temp_index(map);
        if kept.is_empty() {
            self.dao.delete(session_key).await?;
            return Ok(kept);
        }
        session.set_java_typed(TEMP_TOKEN_MAP, typed_long_map(&kept));
        let ttl = max_ttl_duration(&kept);
        self.dao.set_session(session_key, &session, ttl).await?;
        Ok(kept)
    }
}

fn now_millis() -> i64 {
    Utc::now().timestamp_millis()
}

fn ttl_to_expire_ms(timeout_secs: i64) -> i64 {
    if timeout_secs < 0 {
        NEVER_EXPIRE
    } else {
        timeout_secs
            .saturating_mul(1000)
            .saturating_add(now_millis())
    }
}

fn expire_ms_to_ttl(expire_ms: i64) -> i64 {
    if expire_ms == NEVER_EXPIRE {
        return NEVER_EXPIRE;
    }
    if expire_ms < 0 {
        return NOT_VALUE_EXPIRE;
    }
    let now = now_millis();
    if expire_ms < now {
        NOT_VALUE_EXPIRE
    } else {
        (expire_ms - now) / 1000
    }
}

fn read_temp_index(session: &SaSession) -> Vec<(String, i64)> {
    match session.data.get(TEMP_TOKEN_MAP) {
        Some(Value::Object(m)) => m
            .iter()
            .filter_map(|(k, v)| v.as_i64().map(|n| (k.clone(), n)))
            .collect(),
        _ => Vec::new(),
    }
}

fn prune_temp_index(map: Vec<(String, i64)>) -> Vec<(String, i64)> {
    map.into_iter()
        .filter(|(_, exp)| expire_ms_to_ttl(*exp) != NOT_VALUE_EXPIRE)
        .collect()
}

fn max_ttl_duration(map: &[(String, i64)]) -> Option<Duration> {
    let mut max = 0i64;
    for (_, exp) in map {
        let ttl = expire_ms_to_ttl(*exp);
        if ttl == NEVER_EXPIRE {
            return None;
        }
        if ttl > max {
            max = ttl;
        }
    }
    if max > 0 {
        Some(Duration::from_secs(max as u64))
    } else {
        Some(Duration::from_secs(1))
    }
}

fn typed_long_map(entries: &[(String, i64)]) -> Value {
    let mut obj = Map::new();
    obj.insert("@class".into(), json!(CLASS_LINKED_HASH_MAP));
    for (token, expire_ms) in entries {
        obj.insert(token.clone(), json!([CLASS_LONG, expire_ms]));
    }
    Value::Object(obj)
}

/// Java `String.valueOf` / `Map.toString` used as raw-session id.
/// Java `String.valueOf` / `Map.toString`，用作 raw-session id。
fn java_value_id(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        Value::Object(_) | Value::Array(_) => java_collection_to_string(v),
    }
}

fn java_collection_to_string(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let inner: Vec<String> = map
                .iter()
                .map(|(k, val)| format!("{k}={}", java_map_value(val)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
        Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(java_map_value).collect();
            format!("[{}]", inner.join(", "))
        }
        other => java_map_value(other),
    }
}

fn java_map_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        Value::Object(_) | Value::Array(_) => java_collection_to_string(v),
    }
}

/// StpUtil helpers using the process-global manager.
/// 使用进程内全局 Manager 的 StpUtil 辅助函数。
pub async fn create_default(value: impl Into<String>, timeout_secs: i64) -> SaTokenResult<String> {
    let manager = StpUtil::try_get_manager()?;
    let temp = TempTokenManager::new(manager.dao().clone());
    let ns = temp.wire_namespace().to_string();
    temp.create(&ns, Value::String(value.into()), timeout_secs, false)
        .await
}

/// Parse a temp token in the default namespace | 解析默认命名空间下的临时令牌
pub async fn parse_default(token: &str) -> SaTokenResult<TempTokenRecord> {
    let manager = StpUtil::try_get_manager()?;
    let temp = TempTokenManager::new(manager.dao().clone());
    let ns = temp.wire_namespace().to_string();
    temp.parse(&ns, token).await
}

/// Delete a temp token in the default namespace | 删除默认命名空间下的临时令牌
pub async fn delete_default(token: &str) -> SaTokenResult<()> {
    let manager = StpUtil::try_get_manager()?;
    let temp = TempTokenManager::new(manager.dao().clone());
    let ns = temp.wire_namespace().to_string();
    temp.delete(&ns, token).await
}

/// Remaining TTL of a temp token in the default namespace.
/// 默认命名空间下临时令牌的剩余 TTL。
pub async fn get_timeout_default(token: &str) -> SaTokenResult<i64> {
    let manager = StpUtil::try_get_manager()?;
    let temp = TempTokenManager::new(manager.dao().clone());
    let ns = temp.wire_namespace().to_string();
    temp.get_timeout(&ns, token).await
}

/// Save a caller-chosen temp token in the default namespace.
/// 在默认命名空间写入调用方指定的临时令牌。
pub async fn save_default(token: &str, value: Value, timeout_secs: i64) -> SaTokenResult<()> {
    let manager = StpUtil::try_get_manager()?;
    let temp = TempTokenManager::new(manager.dao().clone());
    let ns = temp.wire_namespace().to_string();
    temp.save(&ns, token, value, timeout_secs).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaTokenConfig;
    use crate::manager::SaTokenManager;
    use sa_token_storage_memory::MemoryStorage;

    fn native_mgr() -> (SaTokenManager, TempTokenManager) {
        let storage = Arc::new(MemoryStorage::new());
        let mgr = SaTokenManager::new(storage, SaTokenConfig::default());
        let temp = TempTokenManager::new(mgr.dao().clone());
        (mgr, temp)
    }

    fn java_mgr() -> (SaTokenManager, TempTokenManager) {
        let storage = Arc::new(MemoryStorage::new());
        let mgr = SaTokenManager::new(storage, SaTokenConfig::java_compatible());
        let temp = TempTokenManager::new(mgr.dao().clone());
        (mgr, temp)
    }

    #[test]
    fn java_value_id_string_long_map() {
        assert_eq!(java_value_id(&json!("hello")), "hello");
        assert_eq!(java_value_id(&json!(10001)), "10001");
        let id = java_value_id(&json!({"name": "alice", "id": 10001}));
        assert!(id.starts_with('{') && id.ends_with('}'));
        assert!(id.contains("name=alice"));
        assert!(id.contains("id=10001"));
    }

    #[tokio::test]
    async fn native_wrapped_keeps_record_and_digest_index() {
        let (mgr, temp) = native_mgr();
        let token = temp
            .create("ns", json!("payload"), 120, true)
            .await
            .expect("create");
        let rec = temp.parse("ns", &token).await.expect("parse");
        assert_eq!(rec.value, json!("payload"));
        assert_eq!(rec.namespace, "ns");
        assert!(rec.expire_at.is_some());
        assert_eq!(
            temp.find_token("ns", "payload").await.expect("index"),
            token
        );

        let key = mgr.keys().temp_token("ns", &token);
        let stored: TempTokenRecord = mgr
            .dao()
            .get_object(&key)
            .await
            .expect("get")
            .expect("some");
        assert_eq!(stored.value, json!("payload"));
        assert!(stored.expire_at.is_some());

        let java_idx = mgr.keys().raw_session("ns", "payload");
        assert!(
            mgr.dao()
                .get_string(&java_idx)
                .await
                .expect("raw")
                .is_none(),
            "native Wrapped must not write Java raw-session index"
        );
    }

    #[tokio::test]
    async fn java_raw_string_key_and_index() {
        let (mgr, temp) = java_mgr();
        let ns = mgr.config.wire.temp_token_namespace.clone();
        let token = temp
            .create(&ns, json!("hello"), -1, true)
            .await
            .expect("create");

        let body_key = mgr.keys().temp_token(&ns, &token);
        assert_eq!(body_key, format!("satoken:temp-token:{token}"));
        let body = mgr
            .dao()
            .get_string(&body_key)
            .await
            .expect("get")
            .expect("body");
        assert_eq!(body, r#""hello""#);

        let rec = temp.parse(&ns, &token).await.expect("parse");
        assert_eq!(rec.value, json!("hello"));
        assert!(rec.expire_at.is_none());
        assert_eq!(temp.find_token(&ns, "hello").await.expect("find"), token);
        assert_eq!(temp.get_timeout(&ns, &token).await.expect("ttl"), -1);

        let session_key = mgr.keys().raw_session(&ns, "hello");
        assert_eq!(session_key, "satoken:raw-session:temp-token:hello");
        let raw = mgr
            .dao()
            .get_string(&session_key)
            .await
            .expect("session")
            .expect("raw");
        let v: Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(v["@class"], "cn.dev33.satoken.session.SaSession");
        assert_eq!(v["type"], "temp-token");
        assert_eq!(v["id"], session_key);
        let idx = &v["dataMap"][TEMP_TOKEN_MAP];
        assert_eq!(idx["@class"], CLASS_LINKED_HASH_MAP);
        assert_eq!(idx[&token], json!([CLASS_LONG, -1]));
    }

    #[tokio::test]
    async fn java_raw_long_is_bare_number() {
        let (mgr, temp) = java_mgr();
        let ns = mgr.config.wire.temp_token_namespace.clone();
        let token = temp
            .create(&ns, json!(10001), -1, true)
            .await
            .expect("create");
        let body = mgr
            .dao()
            .get_string(&mgr.keys().temp_token(&ns, &token))
            .await
            .expect("get")
            .expect("body");
        assert_eq!(body, "10001");
        let session_key = mgr.keys().raw_session(&ns, "10001");
        assert_eq!(session_key, "satoken:raw-session:temp-token:10001");
        assert!(
            mgr.dao()
                .get_string(&session_key)
                .await
                .expect("session")
                .is_some()
        );
        assert_eq!(
            temp.parse(&ns, &token).await.expect("parse").value,
            json!(10001)
        );
    }

    #[tokio::test]
    async fn java_raw_map_has_no_class() {
        let (mgr, temp) = java_mgr();
        let ns = mgr.config.wire.temp_token_namespace.clone();
        let value = json!({"name": "alice", "id": 10001});
        let token = temp
            .create(&ns, value.clone(), -1, true)
            .await
            .expect("create");
        let body = mgr
            .dao()
            .get_string(&mgr.keys().temp_token(&ns, &token))
            .await
            .expect("get")
            .expect("body");
        assert!(!body.contains("@class"), "root map must not carry @class");
        let parsed: Value = serde_json::from_str(&body).expect("json");
        assert_eq!(parsed["name"], "alice");
        assert_eq!(parsed["id"], 10001);

        let value_id = java_value_id(&value);
        let session_key = mgr.keys().raw_session(&ns, &value_id);
        assert!(session_key.starts_with("satoken:raw-session:temp-token:"));
        assert!(session_key.contains("name=alice"));
        assert!(session_key.contains("id=10001"));
        let raw = mgr
            .dao()
            .get_string(&session_key)
            .await
            .expect("session")
            .expect("raw");
        let v: Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(v["type"], "temp-token");
        assert_eq!(
            v["dataMap"][TEMP_TOKEN_MAP][&token],
            json!([CLASS_LONG, -1])
        );
    }

    #[tokio::test]
    async fn java_raw_without_index_skips_raw_session() {
        let (mgr, temp) = java_mgr();
        let ns = mgr.config.wire.temp_token_namespace.clone();
        let token = temp
            .create(&ns, json!("hello"), -1, false)
            .await
            .expect("create");
        let session_key = mgr.keys().raw_session(&ns, "hello");
        assert!(
            mgr.dao()
                .get_string(&session_key)
                .await
                .expect("session")
                .is_none()
        );
        temp.delete(&ns, &token).await.expect("delete");
        assert!(
            temp.parse(&ns, &token)
                .await
                .is_err_and(|e| matches!(e, SaTokenError::TempTokenNotFound))
        );
    }
}
