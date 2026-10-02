//! 存储访问唯一收口：storage × serializer × keys。
//!
//! Storage funnel: Repository and Service layers **must not** hold
//! `SaStorage`，所有键构造、序列化、TTL 计算都在本层完成，从而保证
//! 「键 schema 唯一来源（A3）」与「序列化器可插拔（A2）」两个约束不被绕过。
//!
//! Single funnel for storage access: storage × serializer × keys.
//! Application services talk to Dao, not raw `SaStorage`:
//! must never touch `SaStorage` directly, so that the single-source key schema
//! (A3) and the pluggable serializer (A2) can never be bypassed.

use std::sync::Arc;
use std::time::Duration;

use sa_token_adapter::serializer::SharedSerializer;
use sa_token_adapter::storage::{SaStorage, ScanPage, scan_all_keys_dedup};
use serde::{Serialize, de::DeserializeOwned};

use crate::codec::{decode_value, encode_value};
use crate::config::SaTokenConfig;
use crate::error::{SaTokenError, SaTokenResult};
use crate::keys::SaKeys;

/// 存储访问层：封装键构造、序列化与底层原子原语。
/// Storage access layer wrapping key building, serialization and atomic primitives.
#[derive(Clone)]
pub struct SaTokenDao {
    /// 底层存储适配器 | Underlying storage adapter
    storage: Arc<dyn SaStorage>,
    /// 配置共享引用：避免逐层克隆 SaTokenConfig（B1-20）
    /// Shared config reference, avoids cloning `SaTokenConfig` per layer
    config: Arc<SaTokenConfig>,
    /// 键构造器（A3：唯一 schema 来源）| Key builder (A3: single schema source)
    keys: SaKeys,
    /// 默认 TTL 快照（config.timeout；-1 永久时为 None）
    /// Cached default TTL derived from `config.timeout` (`None` when permanent)
    default_ttl: Option<Duration>,
}

impl std::fmt::Debug for SaTokenDao {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SaTokenDao { .. }")
    }
}

impl SaTokenDao {
    /// 从共享配置与存储实例构造。
    ///
    /// 注意入参是 `Arc<SaTokenConfig>`：manager 构造链中 config 只克隆一次，
    /// 其余各层共享同一份，避免 `SharedSerializer` 与十余个 `String` 被反复复制。
    ///
    /// Build from a shared config and a storage instance. Taking
    /// `Arc<SaTokenConfig>` keeps the config cloned exactly once per manager.
    pub fn new(storage: Arc<dyn SaStorage>, config: Arc<SaTokenConfig>) -> Self {
        let keys = SaKeys::from_config(&config);
        let default_ttl = config.timeout_duration();
        Self {
            storage,
            config,
            keys,
            default_ttl,
        }
    }

    /// 底层存储引用 | Underlying storage reference
    pub fn storage(&self) -> &Arc<dyn SaStorage> {
        &self.storage
    }

    /// 共享配置引用 | Shared config reference
    pub fn config(&self) -> &Arc<SaTokenConfig> {
        &self.config
    }

    /// 当前序列化器 | Current serializer
    pub fn serializer(&self) -> &SharedSerializer {
        &self.config.serializer
    }

    /// 键构造器（A3 契约：返回引用，不克隆）| Key builder (A3: returns a reference)
    pub fn keys(&self) -> &SaKeys {
        &self.keys
    }

    /// 默认 token TTL（config.timeout 秒；-1 永久为 None）
    /// Default token TTL from `config.timeout` (`None` when permanent).
    pub fn default_ttl(&self) -> Option<Duration> {
        self.default_ttl
    }

    /// 续签秒数**唯一算式**（修 B1-23）：优先 `active_timeout`，回退 `timeout`。
    ///
    /// 返回 `<= 0` 表示"永久/不限制"，调用方应据此把 TTL 置为 `None`。
    /// 此前 `renew_ttl` 与 `apply_auto_renew` 各写一份同样的三元判断，
    /// 一旦语义调整必然漂移，故收敛为单一函数。
    ///
    /// Single source of truth for the renewal window in seconds: prefers
    /// `active_timeout`, falls back to `timeout`. A non-positive result means
    /// "permanent", i.e. the caller should use a `None` TTL.
    pub fn renew_secs(&self) -> i64 {
        if self.config.active_timeout > 0 {
            self.config.active_timeout
        } else {
            self.config.timeout
        }
    }

    /// 由 `renew_secs` 派生的续签 TTL | Renewal TTL derived from `renew_secs`
    pub fn renew_ttl(&self) -> Option<Duration> {
        let secs = self.renew_secs();
        if secs > 0 {
            Some(Duration::from_secs(secs as u64))
        } else {
            None
        }
    }

    /// 序列化（走配置注入的序列化器，A2 契约）| Encode via the configured serializer
    pub fn encode<T: Serialize + ?Sized>(&self, value: &T) -> SaTokenResult<String> {
        encode_value(&self.config.serializer, value)
    }

    /// 反序列化 | Decode via the configured serializer
    pub fn decode<T: DeserializeOwned>(&self, raw: &str) -> SaTokenResult<T> {
        decode_value(&self.config.serializer, raw)
    }

    // ---------- 标量键读写 | Scalar key operations ----------

    /// 读取字符串 | Read a raw string value
    pub async fn get_string(&self, key: &str) -> SaTokenResult<Option<String>> {
        self.storage
            .get(key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 写入字符串 | Write a raw string value
    pub async fn set_string(
        &self,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> SaTokenResult<()> {
        self.storage
            .set(key, value, ttl)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 删除键 | Delete a key
    pub async fn delete(&self, key: &str) -> SaTokenResult<()> {
        self.storage
            .delete(key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 查询剩余 TTL；键不存在或永不过期时返回 `None`。
    /// Remaining TTL; `None` when the key is missing or never expires.
    pub async fn ttl(&self, key: &str) -> SaTokenResult<Option<Duration>> {
        self.storage
            .ttl(key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 原子读取并删除（nonce 一次性消费依赖此原语，A1 `get_del`）。
    /// Atomically read-and-delete; the one-shot nonce consumption relies on it.
    pub async fn take_string(&self, key: &str) -> SaTokenResult<Option<String>> {
        self.storage
            .get_del(key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 键不存在时才写入（A1 `set_if_absent`）。用于分布式互斥占位。
    /// Write only when the key is absent; useful as a distributed placeholder.
    pub async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl: Option<Duration>,
    ) -> SaTokenResult<bool> {
        self.storage
            .set_if_absent(key, value, ttl)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 比较并交换（A1 `compare_and_swap`）——登录提交点的原子保护（B1-14）。
    ///
    /// `expected == None` 表示"要求键当前不存在"。返回 `false` 说明有并发写入抢先，
    /// 调用方应视为「登录竞态」并回滚本次全部写入。
    ///
    /// Compare-and-swap, guarding the login commit point. `expected == None`
    /// requires the key to be absent. `false` means a concurrent writer won the
    /// race, so the caller must roll back this login attempt.
    pub async fn cas(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl: Option<Duration>,
    ) -> SaTokenResult<bool> {
        self.storage
            .compare_and_swap(key, expected, new_value, ttl)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 比较并删除（A1 `compare_and_delete`）。
    ///
    /// logout 清理 `login:token` 映射时使用：仅当映射仍指向本 token 才删除，
    /// 避免并发登录写入新 token 后被旧 token 的 logout 误删。
    ///
    /// Compare-and-delete: used when clearing the `login:token` mapping so that
    /// a stale logout cannot erase a mapping already pointing at a newer token.
    pub async fn cas_delete(&self, key: &str, expected: &str) -> SaTokenResult<bool> {
        self.storage
            .compare_and_delete(key, expected)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    // ---------- 对象读写 | Object operations ----------

    /// 读取并反序列化对象 | Read and deserialize an object
    pub async fn get_object<T: DeserializeOwned>(&self, key: &str) -> SaTokenResult<Option<T>> {
        match self.get_string(key).await? {
            Some(raw) => Ok(Some(self.decode(&raw)?)),
            None => Ok(None),
        }
    }

    /// 序列化并写入对象 | Serialize and write an object
    pub async fn set_object<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<Duration>,
    ) -> SaTokenResult<()> {
        let raw = self.encode(value)?;
        self.set_string(key, &raw, ttl).await
    }

    /// Serialize and overwrite an object while keeping the existing key TTL.
    /// Missing keys are a successful no-op.
    /// 序列化后 KEEPTTL 覆盖写入；键不存在时成功空操作。
    pub async fn set_object_keep_ttl<T: Serialize>(
        &self,
        key: &str,
        value: &T,
    ) -> SaTokenResult<()> {
        let raw = self.encode(value)?;
        self.storage
            .set_keep_ttl(key, &raw)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 读取字符串列表（键缺失视为空列表）| Read a string list (absent = empty)
    pub async fn get_string_list(&self, key: &str) -> SaTokenResult<Vec<String>> {
        match self.get_string(key).await? {
            Some(raw) => self.decode(&raw),
            None => Ok(Vec::new()),
        }
    }

    /// 覆盖写入字符串列表 | Overwrite a string list
    pub async fn set_string_list(
        &self,
        key: &str,
        list: &[String],
        ttl: Option<Duration>,
    ) -> SaTokenResult<()> {
        let raw = self.encode(list)?;
        self.set_string(key, &raw, ttl).await
    }

    // ---------- 列表原语 | List primitives ----------

    /// 去重追加成员（A1 `list_push` with unique=true）。
    /// Append a member with de-duplication.
    pub async fn list_push_unique(
        &self,
        key: &str,
        member: &str,
        ttl: Option<Duration>,
    ) -> SaTokenResult<usize> {
        self.storage
            .list_push(key, member, true, ttl)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 移除成员 | Remove a member
    pub async fn list_remove(&self, key: &str, member: &str) -> SaTokenResult<bool> {
        self.storage
            .list_remove(key, member)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 分片读取列表 | Read a slice of the list
    pub async fn list_range(
        &self,
        key: &str,
        start: usize,
        limit: Option<usize>,
    ) -> SaTokenResult<Vec<String>> {
        self.storage
            .list_range(key, start, limit)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    /// 列表长度 | List length
    pub async fn list_len(&self, key: &str) -> SaTokenResult<usize> {
        self.storage
            .list_len(key)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    // ---------- 扫描 | Scan ----------

    /// 游标扫描（A1 `scan`）。仅用于索引缺失时的兜底回退路径。
    ///
    /// 注意 A1 契约：`limit` 是**建议值**而非上界，返回条数可能多于或少于它，
    /// 因此调用方必须以 `next_cursor == 0` 作为终止条件，不能靠计数。
    ///
    /// Cursor-based scan, used only as a fallback when the index is missing.
    /// Per the A1 contract `limit` is advisory, so callers must terminate on
    /// `next_cursor == 0` rather than by counting keys.
    pub async fn scan(&self, pattern: &str, cursor: u64, limit: usize) -> SaTokenResult<ScanPage> {
        self.storage
            .scan(pattern, cursor, limit)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    // ---------- 会话检索 | Session search (Java StpUtil.search*) ----------

    /// 扫描页大小：`limit` 仅为建议值，以 `next_cursor == 0` 结束。
    /// Advisory scan page size; terminate on `next_cursor == 0`.
    const SEARCH_SCAN_PAGE: usize = 256;

    /// 按条件检索全部 token 值（对齐 Java `StpUtil.searchTokenValue`）。
    ///
    /// 返回剥离存储键前缀后的 token 字符串，可直接交给 `get_login_id`。
    /// Search token values (Java `StpUtil.searchTokenValue`). Returns stripped
    /// token strings, not full storage keys.
    pub async fn search_token_value(
        &self,
        login_type: Option<&str>,
        keyword: &str,
        start: i64,
        size: i64,
        sort_asc: bool,
    ) -> SaTokenResult<Vec<String>> {
        let pattern = self.keys.token_scan_pattern(login_type);
        self.search_stripped_ids(&pattern, keyword, start, size, sort_asc, |key| {
            self.keys.parse_token_from_key(key, login_type)
        })
        .await
    }

    /// 按条件检索全部 Account-Session id（对齐 Java `StpUtil.searchSessionId`）。
    /// Search account-session ids (Java `StpUtil.searchSessionId`).
    pub async fn search_session_id(
        &self,
        login_type: Option<&str>,
        keyword: &str,
        start: i64,
        size: i64,
        sort_asc: bool,
    ) -> SaTokenResult<Vec<String>> {
        let pattern = self.keys.scan_pattern("session", login_type);
        self.search_stripped_ids(&pattern, keyword, start, size, sort_asc, |key| {
            self.keys.parse_id_from_key(key, "session", login_type)
        })
        .await
    }

    /// 按条件检索全部 Token-Session id（对齐 Java `StpUtil.searchTokenSessionId`）。
    /// Search token-session ids (Java `StpUtil.searchTokenSessionId`).
    pub async fn search_token_session_id(
        &self,
        login_type: Option<&str>,
        keyword: &str,
        start: i64,
        size: i64,
        sort_asc: bool,
    ) -> SaTokenResult<Vec<String>> {
        let pattern = self.keys.scan_pattern("token-session", login_type);
        self.search_stripped_ids(&pattern, keyword, start, size, sort_asc, |key| {
            self.keys
                .parse_id_from_key(key, "token-session", login_type)
        })
        .await
    }

    /// 扫描 → 剥离 id → keyword 过滤 → 排序 → 分页。
    /// Scan, strip ids, filter by keyword, sort, then paginate.
    async fn search_stripped_ids(
        &self,
        pattern: &str,
        keyword: &str,
        start: i64,
        size: i64,
        sort_asc: bool,
        parse: impl Fn(&str) -> Option<&str>,
    ) -> SaTokenResult<Vec<String>> {
        let keys = scan_all_keys_dedup(self.storage.as_ref(), pattern, Self::SEARCH_SCAN_PAGE)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))?;

        let mut ids: Vec<String> = keys
            .iter()
            .filter_map(|key| parse(key))
            .filter(|id| keyword.is_empty() || id.contains(keyword))
            .map(str::to_string)
            .collect();

        ids.sort();
        if !sort_asc {
            ids.reverse();
        }

        let start = start.max(0) as usize;
        if start >= ids.len() {
            return Ok(Vec::new());
        }
        let end = if size == -1 {
            ids.len()
        } else if size <= 0 {
            start
        } else {
            start.saturating_add(size as usize).min(ids.len())
        };
        Ok(ids
            .get(start..end)
            .map(<[String]>::to_vec)
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_storage_memory::MemoryStorage;

    fn test_dao() -> SaTokenDao {
        SaTokenDao::new(
            Arc::new(MemoryStorage::new()),
            Arc::new(SaTokenConfig::default()),
        )
    }

    async fn seed_search_keys(dao: &SaTokenDao) {
        let keys = dao.keys();
        dao.set_string(&keys.token_info("tok-aaa"), "u1", None)
            .await
            .unwrap();
        dao.set_string(&keys.token_info("tok-bbb"), "u2", None)
            .await
            .unwrap();
        dao.set_string(&keys.token_info("tok-ccc"), "u3", None)
            .await
            .unwrap();
        dao.set_string(&keys.token_info("other-ddd"), "u4", None)
            .await
            .unwrap();
        dao.set_string(&keys.account_session("default", "sess-aaa"), "{}", None)
            .await
            .unwrap();
        dao.set_string(&keys.account_session("default", "sess-bbb"), "{}", None)
            .await
            .unwrap();
        dao.set_string(&keys.account_session("default", "sess-ccc"), "{}", None)
            .await
            .unwrap();
        dao.set_string(&keys.token_session("ts-aaa"), "{}", None)
            .await
            .unwrap();
        dao.set_string(&keys.token_session("ts-bbb"), "{}", None)
            .await
            .unwrap();
        dao.set_string(&keys.token_session("ts-ccc"), "{}", None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn search_token_value_strips_pages_and_filters() {
        let dao = test_dao();
        seed_search_keys(&dao).await;

        let all = dao.search_token_value(None, "", 0, -1, true).await.unwrap();
        assert_eq!(all, vec!["other-ddd", "tok-aaa", "tok-bbb", "tok-ccc"]);
        assert!(all.iter().all(|id| !id.contains("token:")));

        let filtered = dao
            .search_token_value(None, "tok-", 0, -1, true)
            .await
            .unwrap();
        assert_eq!(filtered, vec!["tok-aaa", "tok-bbb", "tok-ccc"]);

        let page = dao.search_token_value(None, "", 1, 2, true).await.unwrap();
        assert_eq!(page, vec!["tok-aaa", "tok-bbb"]);

        let desc = dao
            .search_token_value(None, "", 0, -1, false)
            .await
            .unwrap();
        assert_eq!(desc, vec!["tok-ccc", "tok-bbb", "tok-aaa", "other-ddd"]);

        let from_neg = dao.search_token_value(None, "", -5, 1, true).await.unwrap();
        assert_eq!(from_neg, vec!["other-ddd"]);

        let oob = dao.search_token_value(None, "", 10, 5, true).await.unwrap();
        assert!(oob.is_empty());
    }

    #[tokio::test]
    async fn search_session_id_strips_pages_and_filters() {
        let dao = test_dao();
        seed_search_keys(&dao).await;

        let all = dao.search_session_id(None, "", 0, -1, true).await.unwrap();
        assert_eq!(all, vec!["sess-aaa", "sess-bbb", "sess-ccc"]);
        assert!(all.iter().all(|id| !id.contains("session:")));

        let filtered = dao
            .search_session_id(None, "bbb", 0, -1, true)
            .await
            .unwrap();
        assert_eq!(filtered, vec!["sess-bbb"]);

        let page = dao.search_session_id(None, "", 0, 2, true).await.unwrap();
        assert_eq!(page, vec!["sess-aaa", "sess-bbb"]);

        let desc = dao.search_session_id(None, "", 1, 2, false).await.unwrap();
        assert_eq!(desc, vec!["sess-bbb", "sess-aaa"]);
    }

    #[tokio::test]
    async fn search_token_session_id_strips_pages_and_filters() {
        let dao = test_dao();
        seed_search_keys(&dao).await;

        let all = dao
            .search_token_session_id(None, "", 0, -1, true)
            .await
            .unwrap();
        assert_eq!(all, vec!["ts-aaa", "ts-bbb", "ts-ccc"]);
        assert!(all.iter().all(|id| !id.contains("token-session:")));

        let filtered = dao
            .search_token_session_id(None, "ts-a", 0, -1, true)
            .await
            .unwrap();
        assert_eq!(filtered, vec!["ts-aaa"]);

        let page = dao
            .search_token_session_id(None, "", 2, 10, true)
            .await
            .unwrap();
        assert_eq!(page, vec!["ts-ccc"]);

        let empty_kw_miss = dao
            .search_token_session_id(None, "no-such", 0, -1, true)
            .await
            .unwrap();
        assert!(empty_kw_miss.is_empty());
    }
}
