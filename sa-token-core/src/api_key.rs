//! API Key (Java `SaApiKeyTemplate`).
//!
//! Aligns with sa-token-apikey 1.46.0: model fields, check order
//! (invalid → expired → disabled), AND/OR scopes, and request-side read
//! (`params` → `headers` → HTTP Basic).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sa_token_adapter::storage::SaStorage;
use serde::{Deserialize, Serialize};

use crate::config::SaTokenConfig;
use crate::context::{RequestAuthMeta, SaTokenContext};
use crate::error::{SaTokenError, SaTokenResult};
use crate::manager::SaTokenManager;

/// Default namespace (Java `SaApiKeyTemplate.DEFAULT_NAMESPACE`).
/// 默认命名空间。
pub const DEFAULT_NAMESPACE: &str = "apikey";

/// Default API Key prefix (Java `SaApiKeyConfig.prefix`).
/// 默认 API Key 前缀。
pub const DEFAULT_PREFIX: &str = "AK-";

/// Default TTL in seconds: 30 days (Java `SaApiKeyConfig.timeout`).
/// 默认有效期（秒）：30 天。
pub const DEFAULT_TIMEOUT: i64 = 2_592_000;

/// Never-expire sentinel (Java `SaTokenDao.NEVER_EXPIRE`).
/// 永不过期标记。
const NEVER_EXPIRE: i64 = -1;

/// Already-expired sentinel returned by `expires_in` (Java `-2`).
/// `expires_in` 在已过期时返回的标记。
const VALUE_EXPIRED: i64 = -2;

/// Random suffix length after `prefix` (Java `SaFoxUtil.getRandomString(36)`).
/// 前缀之后的随机段长度。
const RANDOM_SUFFIX_LEN: usize = 36;

/// Current wall-clock time in epoch milliseconds.
/// 当前墙钟时间（纪元毫秒）。
fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// 36 hex chars from CSPRNG; UUID concatenation if the OS RNG is unavailable.
/// 36 位 hex（CSPRNG）；操作系统 RNG 不可用时回退 UUID 拼接。
fn random_suffix() -> String {
    match crate::token::random_hex(RANDOM_SUFFIX_LEN) {
        Ok(s) => s,
        Err(_) => {
            let a = uuid::Uuid::new_v4().simple().to_string();
            let b = uuid::Uuid::new_v4().simple().to_string();
            a.chars().chain(b.chars()).take(RANDOM_SUFFIX_LEN).collect()
        }
    }
}

fn storage_err(err: impl std::fmt::Display) -> SaTokenError {
    SaTokenError::StorageError(err.to_string())
}

/// API Key model (Java `ApiKeyModel`).
/// API Key 模型。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyModel {
    /// Display title | 名称
    #[serde(default)]
    pub title: String,
    /// Description | 介绍
    #[serde(default)]
    pub intro: String,
    /// Secret value | ApiKey 值
    #[serde(default)]
    pub api_key: String,
    /// Owner login id | 账号 id
    #[serde(default)]
    pub login_id: String,
    /// Created at, epoch milliseconds | 创建时间（13 位毫秒）
    #[serde(default)]
    pub create_time: i64,
    /// Expires at, epoch milliseconds (`-1` = never) | 到期时间（`-1` 永不过期）
    #[serde(default)]
    pub expires_time: i64,
    /// Whether the key is enabled | 是否有效
    #[serde(default = "default_is_valid")]
    pub is_valid: bool,
    /// Granted scopes | 授权范围
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Optional extra map | 扩展数据
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_data: Option<HashMap<String, serde_json::Value>>,
}

fn default_is_valid() -> bool {
    true
}

impl Default for ApiKeyModel {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiKeyModel {
    /// Empty model with `create_time = now` and `is_valid = true` (Java ctor).
    /// 空模型：创建时间为现在，`is_valid = true`。
    pub fn new() -> Self {
        Self {
            title: String::new(),
            intro: String::new(),
            api_key: String::new(),
            login_id: String::new(),
            create_time: now_millis(),
            expires_time: 0,
            is_valid: true,
            scopes: Vec::new(),
            extra_data: None,
        }
    }

    /// Whether wall clock is past `expires_time` (never-expire is `-1`).
    /// 是否已过期（`-1` 永不过期）。
    pub fn time_expired(&self) -> bool {
        if self.expires_time == NEVER_EXPIRE {
            return false;
        }
        now_millis() > self.expires_time
    }

    /// Remaining TTL in seconds: `-1` never, `-2` already expired.
    /// 剩余有效期（秒）：`-1` 永不过期，`-2` 已过期。
    pub fn expires_in(&self) -> i64 {
        if self.expires_time == NEVER_EXPIRE {
            return NEVER_EXPIRE;
        }
        let secs = (self.expires_time - now_millis()) / 1000;
        if secs < 1 { VALUE_EXPIRED } else { secs }
    }

    /// Append a scope (Java `addScope`).
    /// 追加一个 scope。
    pub fn add_scope(&mut self, scope: impl Into<String>) -> &mut Self {
        self.scopes.push(scope.into());
        self
    }

    /// Insert extra data (Java `addExtra`).
    /// 写入一条扩展数据。
    pub fn add_extra(&mut self, key: impl Into<String>, value: serde_json::Value) -> &mut Self {
        self.extra_data
            .get_or_insert_with(HashMap::new)
            .insert(key.into(), value);
        self
    }

    fn check_can_save(&self) -> SaTokenResult<()> {
        if self.api_key.is_empty() {
            return Err(SaTokenError::ApiKeyInvalid);
        }
        if self.login_id.is_empty() {
            return Err(SaTokenError::ApiKeyInvalid);
        }
        if self.create_time == 0 {
            return Err(SaTokenError::ApiKeyInvalid);
        }
        if self.expires_time == 0 {
            return Err(SaTokenError::ApiKeyInvalid);
        }
        Ok(())
    }
}

/// API Key operations bound to a manager's storage + config.
/// 绑定 Manager 存储与配置的 API Key 操作。
#[derive(Clone)]
pub struct ApiKeyManager {
    storage: Arc<dyn SaStorage>,
    config: Arc<SaTokenConfig>,
    namespace: String,
    prefix: String,
    timeout: i64,
}

impl std::fmt::Debug for ApiKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyManager")
            .field("namespace", &self.namespace)
            .field("prefix", &self.prefix)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl ApiKeyManager {
    /// Bind to an existing `SaTokenManager` (default namespace / prefix / timeout).
    /// 绑定已有 Manager，命名空间 / 前缀 / 超时使用默认值。
    pub fn new(manager: &SaTokenManager) -> Self {
        Self {
            storage: Arc::clone(manager.storage()),
            config: Arc::clone(&manager.config),
            namespace: DEFAULT_NAMESPACE.to_string(),
            prefix: DEFAULT_PREFIX.to_string(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Storage key for a model: `{token_name}:{namespace}:{apiKey}`.
    /// 模型存储键。
    pub fn save_key(&self, api_key: &str) -> String {
        format!("{}:{}:{}", self.config.token_name, self.namespace, api_key)
    }

    /// Storage key for the login-id index: `{token_name}:{namespace}:index:{loginId}`.
    /// loginId 索引存储键。
    pub fn index_key(&self, login_id: &str) -> String {
        format!(
            "{}:{}:index:{}",
            self.config.token_name, self.namespace, login_id
        )
    }

    /// Build a model; does **not** persist (Java `createApiKeyModel(loginId)`).
    /// 创建模型，**不**自动写入存储。
    pub fn create(&self, login_id: impl Into<String>) -> ApiKeyModel {
        let now = now_millis();
        let expires_time = if self.timeout < 0 {
            NEVER_EXPIRE
        } else {
            now.saturating_add(self.timeout.saturating_mul(1000))
        };
        ApiKeyModel {
            title: String::new(),
            intro: String::new(),
            api_key: format!("{}{}", self.prefix, random_suffix()),
            login_id: login_id.into(),
            create_time: now,
            expires_time,
            is_valid: true,
            scopes: Vec::new(),
            extra_data: None,
        }
    }

    /// Persist a model and maintain the login-id index (Java `saveApiKey`).
    ///
    /// Expired models are deleted from storage (not treated as a successful check).
    /// 持久化模型并维护 loginId 索引；已过期则删除存储。
    pub async fn save(&self, model: &ApiKeyModel) -> SaTokenResult<()> {
        model.check_can_save()?;
        let key = self.save_key(&model.api_key);
        if model.time_expired() {
            self.storage.delete(&key).await.map_err(storage_err)?;
            let list = self.load_index(&model.login_id).await?;
            return self.persist_index(&model.login_id, list).await;
        }
        let ttl = match model.expires_in() {
            NEVER_EXPIRE => None,
            secs if secs > 0 => Some(Duration::from_secs(secs as u64)),
            _ => None,
        };
        let raw = self.config.encode(model)?;
        self.storage
            .set(&key, &raw, ttl)
            .await
            .map_err(storage_err)?;
        let mut list = self.load_index(&model.login_id).await?;
        if !list.iter().any(|k| k == &model.api_key) {
            list.push(model.api_key.clone());
        }
        self.persist_index(&model.login_id, list).await
    }

    /// Load from cache with **no** expiry check (Java `getApiKeyModelFromCache`).
    /// 从缓存读取，**不做**过期检查（便于灰盒拨钟）。
    pub async fn get(&self, api_key: &str) -> SaTokenResult<Option<ApiKeyModel>> {
        if api_key.is_empty() {
            return Ok(None);
        }
        let key = self.save_key(api_key);
        match self.storage.get(&key).await.map_err(storage_err)? {
            Some(raw) if !raw.is_empty() => Ok(Some(self.config.decode(&raw)?)),
            _ => Ok(None),
        }
    }

    /// Validate: missing → invalid; expired → expired; `!is_valid` → disabled.
    /// 校验：缺失无效、已过期、已禁用。
    pub async fn check(&self, api_key: &str) -> SaTokenResult<ApiKeyModel> {
        let Some(ak) = self.get(api_key).await? else {
            return Err(SaTokenError::ApiKeyInvalid);
        };
        if ak.time_expired() {
            return Err(SaTokenError::ApiKeyExpired);
        }
        if !ak.is_valid {
            return Err(SaTokenError::ApiKeyDisabled);
        }
        Ok(ak)
    }

    /// Delete one key and drop it from the login-id index (Java `deleteApiKey`).
    /// 删除一把 key 并从索引移除。
    pub async fn delete(&self, api_key: &str) -> SaTokenResult<()> {
        let Some(ak) = self.get(api_key).await? else {
            return Ok(());
        };
        self.storage
            .delete(&self.save_key(api_key))
            .await
            .map_err(storage_err)?;
        let list = self.load_index(&ak.login_id).await?;
        self.persist_index(&ak.login_id, list).await
    }

    /// Delete every key owned by `login_id` (Java `deleteApiKeyByLoginId`).
    /// 删除该 loginId 下全部 API Key。
    pub async fn delete_by_login_id(&self, login_id: &str) -> SaTokenResult<()> {
        let list = self.load_index(login_id).await?;
        for api_key in &list {
            self.storage
                .delete(&self.save_key(api_key))
                .await
                .map_err(storage_err)?;
        }
        self.storage
            .delete(&self.index_key(login_id))
            .await
            .map_err(storage_err)?;
        Ok(())
    }

    /// List non-expired keys for a login id (Java `getApiKeyList`).
    /// 列出该 loginId 下未过期的 API Key。
    pub async fn list_by_login_id(&self, login_id: &str) -> SaTokenResult<Vec<ApiKeyModel>> {
        let list = self.load_index(login_id).await?;
        let mut out = Vec::new();
        for api_key in list {
            if let Some(ak) = self.get(&api_key).await?
                && !ak.time_expired()
            {
                out.push(ak);
            }
        }
        Ok(out)
    }

    /// AND: the key must hold every given scope (Java `checkApiKeyScope`).
    /// AND 模式：必须具备全部 scope。
    pub async fn check_scope(&self, api_key: &str, scopes: &[&str]) -> SaTokenResult<()> {
        let ak = self.check(api_key).await?;
        if scopes.is_empty() {
            return Ok(());
        }
        for scope in scopes {
            if !ak.scopes.iter().any(|s| s == scope) {
                return Err(SaTokenError::ApiKeyScopeDenied((*scope).to_string()));
            }
        }
        Ok(())
    }

    /// OR: the key must hold at least one given scope (Java `checkApiKeyScopeOr`).
    /// OR 模式：具备其一即可。
    pub async fn check_scope_or(&self, api_key: &str, scopes: &[&str]) -> SaTokenResult<()> {
        let ak = self.check(api_key).await?;
        if scopes.is_empty() {
            return Ok(());
        }
        for scope in scopes {
            if ak.scopes.iter().any(|s| s == scope) {
                return Ok(());
            }
        }
        let denied = scopes.first().copied().unwrap_or_default();
        Err(SaTokenError::ApiKeyScopeDenied(denied.to_string()))
    }

    /// AND scope check as bool (Java `hasApiKeyScope`).
    /// AND 模式，返回是否具备。
    pub async fn has_scope(&self, api_key: &str, scopes: &[&str]) -> bool {
        self.check_scope(api_key, scopes).await.is_ok()
    }

    /// OR scope check as bool (Java `hasApiKeyScopeOr`).
    /// OR 模式，返回是否具备其一。
    pub async fn has_scope_or(&self, api_key: &str, scopes: &[&str]) -> bool {
        self.check_scope_or(api_key, scopes).await.is_ok()
    }

    /// `check` then return `login_id` (Java `getLoginIdByApiKey`).
    /// 校验后取 login_id。
    pub async fn get_login_id(&self, api_key: &str) -> SaTokenResult<String> {
        Ok(self.check(api_key).await?.login_id)
    }

    /// `check` then require the key to belong to `login_id` (Java `checkApiKeyLoginId`).
    /// 先走现有校验，再核对归属 login_id。
    pub async fn check_login_id(
        &self,
        api_key: &str,
        login_id: &str,
    ) -> SaTokenResult<ApiKeyModel> {
        let model = self.check(api_key).await?;
        if model.login_id != login_id {
            return Err(SaTokenError::PermissionDeniedDetail(login_id.to_string()));
        }
        Ok(model)
    }

    /// Read the raw key from request meta (Java `readApiKeyValue`).
    ///
    /// Order: `params[namespace]` → headers (case-insensitive) → Basic `Authorization`
    /// (trailing `:` stripped).
    /// 读取顺序：参数 → 请求头 → HTTP Basic（去掉末尾 `:`）。
    pub fn read_api_key_value(&self, meta: &RequestAuthMeta) -> Option<String> {
        if let Some(v) = meta.params.get(&self.namespace)
            && !v.is_empty()
        {
            return Some(v.clone());
        }
        if let Some(v) = meta
            .headers
            .iter()
            .find(|(k, v)| k.eq_ignore_ascii_case(&self.namespace) && !v.is_empty())
            .map(|(_, v)| v.clone())
        {
            return Some(v);
        }
        let auth = meta.authorization.as_deref()?;
        let mut decoded = crate::http_basic::decode_basic_authorization(auth)?;
        if decoded.ends_with(':') {
            decoded.pop();
        }
        if decoded.is_empty() {
            None
        } else {
            Some(decoded)
        }
    }

    /// Check the API Key carried by the current request context (Java `currentApiKey`).
    /// 校验当前请求上下文中的 API Key。
    pub async fn current_api_key(&self) -> SaTokenResult<ApiKeyModel> {
        let key = SaTokenContext::try_current()
            .and_then(|ctx| self.read_api_key_value(&ctx.auth_meta()))
            .unwrap_or_default();
        self.check(&key).await
    }

    /// `current_api_key` then `login_id`.
    /// 从当前请求取出 login_id。
    pub async fn current_login_id(&self) -> SaTokenResult<String> {
        Ok(self.current_api_key().await?.login_id)
    }

    async fn load_index(&self, login_id: &str) -> SaTokenResult<Vec<String>> {
        let key = self.index_key(login_id);
        match self.storage.get(&key).await.map_err(storage_err)? {
            Some(raw) if !raw.is_empty() => self.config.decode(&raw),
            _ => Ok(Vec::new()),
        }
    }

    /// Drop missing/expired keys, then rewrite the index with max remaining TTL.
    /// 去掉缺失/过期项，再按最大剩余 TTL 写回索引。
    async fn persist_index(&self, login_id: &str, list: Vec<String>) -> SaTokenResult<()> {
        let mut kept = Vec::new();
        let mut never = false;
        let mut max_ttl: i64 = 0;
        for api_key in list {
            let Some(ak) = self.get(&api_key).await? else {
                continue;
            };
            if ak.time_expired() {
                continue;
            }
            match ak.expires_in() {
                NEVER_EXPIRE => never = true,
                secs if secs > max_ttl => max_ttl = secs,
                _ => {}
            }
            kept.push(api_key);
        }
        let key = self.index_key(login_id);
        if kept.is_empty() {
            return self.storage.delete(&key).await.map_err(storage_err);
        }
        let ttl = if never {
            None
        } else if max_ttl > 0 {
            Some(Duration::from_secs(max_ttl as u64))
        } else {
            None
        };
        let raw = self.config.encode(&kept)?;
        self.storage.set(&key, &raw, ttl).await.map_err(storage_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_storage_memory::MemoryStorage;

    fn test_manager() -> (SaTokenManager, ApiKeyManager) {
        let storage = Arc::new(MemoryStorage::new());
        let mgr = SaTokenManager::new(storage, SaTokenConfig::default());
        let api = ApiKeyManager::new(&mgr);
        (mgr, api)
    }

    #[test]
    fn expires_in_never_and_expired() {
        let mut model = ApiKeyModel::new();
        model.expires_time = NEVER_EXPIRE;
        assert!(!model.time_expired());
        assert_eq!(model.expires_in(), NEVER_EXPIRE);

        model.expires_time = now_millis() - 5_000;
        assert!(model.time_expired());
        assert_eq!(model.expires_in(), VALUE_EXPIRED);

        model.expires_time = now_millis() + 30_000;
        assert!(!model.time_expired());
        let left = model.expires_in();
        assert!((20..=30).contains(&left), "expires_in={left}");
    }

    #[test]
    fn create_uses_prefix_and_timeout() {
        let (_mgr, api) = test_manager();
        let model = api.create("user-1");
        assert!(model.api_key.starts_with(DEFAULT_PREFIX));
        let suffix = model.api_key.trim_start_matches(DEFAULT_PREFIX);
        assert_eq!(suffix.len(), RANDOM_SUFFIX_LEN);
        assert_eq!(model.login_id, "user-1");
        assert!(model.is_valid);
        assert!(!model.time_expired());
        assert!(model.create_time > 0);
        assert!(model.expires_time > model.create_time);
    }

    #[test]
    fn read_api_key_value_params_headers_basic() {
        let (_mgr, api) = test_manager();

        let mut meta = RequestAuthMeta::default();
        meta.params
            .insert(DEFAULT_NAMESPACE.to_string(), "from-param".into());
        assert_eq!(api.read_api_key_value(&meta).as_deref(), Some("from-param"));

        let mut meta = RequestAuthMeta::default();
        meta.headers.insert("APIKEY".into(), "from-header".into());
        assert_eq!(
            api.read_api_key_value(&meta).as_deref(),
            Some("from-header")
        );

        // base64("AK-demo:") = QUstZGVtbzo=
        let meta = RequestAuthMeta {
            authorization: Some("Basic QUstZGVtbzo=".into()),
            ..Default::default()
        };
        assert_eq!(api.read_api_key_value(&meta).as_deref(), Some("AK-demo"));
    }

    #[tokio::test]
    async fn create_save_check_roundtrip() {
        let (_mgr, api) = test_manager();
        let model = api.create("u-round");
        api.save(&model).await.expect("save");
        let checked = api.check(&model.api_key).await.expect("check");
        assert_eq!(checked.login_id, "u-round");
        assert_eq!(checked.api_key, model.api_key);
    }

    #[test]
    fn save_rejects_empty_fields() {
        let model = ApiKeyModel::new();
        assert!(matches!(
            model.check_can_save(),
            Err(SaTokenError::ApiKeyInvalid)
        ));
    }
}
