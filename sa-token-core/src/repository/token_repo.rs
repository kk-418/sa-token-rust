//! Token 仓储：token 体、双向映射、多设备索引、续签策略。
//!
//! Token repository: token bodies, bidirectional mappings, the multi-device
//! index and the renewal policy.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};

use crate::compat::{AccountIndex, LastActiveStore, TokenValueFormat};
use crate::config::{LogoutMode, SaTokenConfig};
use crate::context::SaTokenContext;
use crate::dao::SaTokenDao;
use crate::error::{SaTokenError, SaTokenResult};
use crate::keys::LOGIN_TYPE_DEFAULT;
use crate::token::map::{
    TOKEN_MAP_BE_REPLACED, TOKEN_MAP_KICK_OUT, is_kick_out_marker, is_replaced_marker,
};
use crate::token::{TokenInfo, TokenValue, intern_login_type};

/// `token-id` 复合映射值的分隔符（修 B1-11）。
///
/// 选用 `\u{1}`（SOH 控制字符）而非 `:`：`login_id` 允许包含冒号，
/// 用冒号会与 A3 的键分段规则冲突并产生解析歧义；SOH 不会出现在
/// 合法的 `login_type` / `login_id` 中，因此可安全作为分隔符。
///
/// Separator for the composite `token-id` mapping value. `\u{1}` (SOH) is used
/// instead of `:` because a login id may legitimately contain colons, which
/// would clash with the A3 key segmentation rules.
const TOKEN_ID_SEP: char = '\u{1}';

/// `token-id` 映射解析结果 | Parsed `token-id` mapping value
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenIdMapping {
    /// 正常身份映射 | A normal identity mapping
    Identity {
        /// 登录类型 | Login type
        login_type: String,
        /// 账号 ID | Login id
        login_id: String,
    },
    /// 已被踢下线（标记值 -5）| Kicked out (marker `-5`)
    KickedOut,
    /// 已被顶下线（标记值 -4）| Replaced (marker `-4`)
    Replaced,
}

/// Token 读写与索引维护 | Token persistence and index maintenance
pub struct TokenRepo {
    dao: Arc<SaTokenDao>,
    config: Arc<SaTokenConfig>,
}

impl std::fmt::Debug for TokenRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenRepo { .. }")
    }
}

impl TokenRepo {
    /// 构造仓储 | Construct the repository
    pub fn new(dao: Arc<SaTokenDao>, config: Arc<SaTokenConfig>) -> Self {
        Self { dao, config }
    }

    /// 底层 Dao | Underlying dao
    pub fn dao(&self) -> &Arc<SaTokenDao> {
        &self.dao
    }

    /// 默认 TTL | Default TTL
    fn ttl(&self) -> Option<Duration> {
        self.dao.default_ttl()
    }

    fn uses_rust_index(&self) -> bool {
        self.config.wire.account_index == AccountIndex::RustIndexKeys
    }

    fn is_login_id_value(&self) -> bool {
        self.config.wire.token_value == TokenValueFormat::LoginId
    }

    fn last_active_enabled(&self) -> bool {
        self.config.wire.last_active == LastActiveStore::SeparateKey
            && (self.config.active_timeout != -1 || self.config.dynamic_active_timeout)
    }

    fn token_key(&self, login_type: &str, token: &str) -> String {
        self.dao.keys().token_info_with_type(login_type, token)
    }

    fn last_active_key(&self, login_type: &str, token: &str) -> String {
        self.dao.keys().last_active_with_type(login_type, token)
    }

    async fn set_keep_ttl_raw(&self, key: &str, value: &str) -> SaTokenResult<()> {
        self.dao
            .storage()
            .set_keep_ttl(key, value)
            .await
            .map_err(|e| SaTokenError::StorageError(e.to_string()))
    }

    fn encode_last_active(&self, info: &TokenInfo) -> String {
        let ms = info.last_active_time.timestamp_millis();
        if self.config.dynamic_active_timeout {
            let secs = info
                .active_timeout_override
                .unwrap_or(self.config.active_timeout);
            format!("{ms},{secs}")
        } else {
            ms.to_string()
        }
    }

    fn parse_last_active(raw: &str) -> Option<(DateTime<Utc>, Option<i64>)> {
        let (ms_raw, dyn_secs) = match raw.split_once(',') {
            Some((ms, secs)) => (ms, secs.parse::<i64>().ok()),
            None => (raw, None),
        };
        let ms = ms_raw.parse::<i64>().ok()?;
        let at = DateTime::from_timestamp_millis(ms)?;
        Some((at, dyn_secs))
    }

    async fn write_last_active(
        &self,
        login_type: &str,
        token: &str,
        info: &TokenInfo,
        ttl: Option<Duration>,
        keep_ttl: bool,
    ) -> SaTokenResult<()> {
        if !self.last_active_enabled() {
            return Ok(());
        }
        let key = self.last_active_key(login_type, token);
        let value = self.encode_last_active(info);
        if keep_ttl {
            self.set_keep_ttl_raw(&key, &value).await
        } else {
            self.dao.set_string(&key, &value, ttl).await
        }
    }

    async fn overlay_last_active(
        &self,
        login_type: &str,
        token: &str,
        info: &mut TokenInfo,
    ) -> SaTokenResult<bool> {
        if self.config.wire.last_active != LastActiveStore::SeparateKey {
            return Ok(true);
        }
        let key = self.last_active_key(login_type, token);
        match self.dao.get_string(&key).await? {
            Some(raw) => {
                if let Some((at, dyn_secs)) = Self::parse_last_active(&raw) {
                    info.last_active_time = at;
                    if let Some(secs) = dyn_secs {
                        info.active_timeout_override = Some(secs);
                    }
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn persist_token_body(
        &self,
        login_type: &str,
        info: &TokenInfo,
        ttl: Option<Duration>,
        keep_ttl: bool,
    ) -> SaTokenResult<()> {
        let key = self.token_key(login_type, info.token.as_str());
        if self.is_login_id_value() {
            if keep_ttl {
                self.set_keep_ttl_raw(&key, info.login_id.as_ref()).await?;
            } else {
                self.dao
                    .set_string(&key, info.login_id.as_ref(), ttl)
                    .await?;
            }
        } else if keep_ttl {
            self.dao.set_object_keep_ttl(&key, info).await?;
        } else {
            self.dao.set_object(&key, info, ttl).await?;
        }
        self.write_last_active(login_type, info.token.as_str(), info, ttl, keep_ttl)
            .await
    }

    fn expire_from_ttl(ttl: Option<Duration>) -> Option<DateTime<Utc>> {
        ttl.map(|d| Utc::now() + ChronoDuration::seconds(d.as_secs() as i64))
    }

    async fn synthesize_login_id_info(
        &self,
        login_type: &str,
        token: &str,
        login_id: &str,
    ) -> SaTokenResult<TokenInfo> {
        let key = self.token_key(login_type, token);
        let ttl = self.dao.ttl(&key).await?;
        let mut info = TokenInfo::new(TokenValue::new(token), login_id);
        info.login_type = intern_login_type(login_type);
        info.expire_time = Self::expire_from_ttl(ttl);
        let _ = self
            .overlay_last_active(login_type, token, &mut info)
            .await?;
        Ok(info)
    }

    /// Remaining storage TTL from `expire_time` (`None` = never expires).
    /// 由 `expire_time` 推剩余寿命；`None` 表示永久。
    pub fn ttl_for(&self, info: &TokenInfo) -> Option<Duration> {
        let expire = info.expire_time?;
        let remaining = expire
            .signed_duration_since(Utc::now())
            .num_seconds()
            .max(0);
        Some(Duration::from_secs(remaining as u64))
    }

    /// `max(existing TTL, new TTL)` for shared keys (index / login mapping).
    ///
    /// - new `None` (permanent) → permanent
    /// - key missing → new TTL
    /// - key exists and remaining is `None` → already permanent, do not shorten
    /// - both finite → the larger Duration
    async fn max_ttl(
        &self,
        key: &str,
        new_ttl: Option<Duration>,
    ) -> SaTokenResult<Option<Duration>> {
        let Some(new) = new_ttl else {
            return Ok(None);
        };
        if !self.dao.exists(key).await? {
            return Ok(Some(new));
        }
        Ok(self.dao.ttl(key).await?.map(|existing| existing.max(new)))
    }

    /// Set remaining TTL; `None` rewrites the scalar as permanent.
    /// 写入剩余 TTL；`None` 把标量键改写为永久。
    async fn write_ttl(&self, key: &str, ttl: Option<Duration>) -> SaTokenResult<()> {
        match ttl {
            Some(d) => self.dao.expire(key, d).await,
            None => {
                let Some(raw) = self.dao.get_string(key).await? else {
                    return Ok(());
                };
                self.dao.set_string(key, &raw, None).await
            }
        }
    }

    // ==================== token 体 | Token body ====================

    /// 写入 token 体 | Persist a token body
    pub async fn save_token_info(&self, info: &TokenInfo) -> SaTokenResult<()> {
        self.save_token_info_typed(LOGIN_TYPE_DEFAULT, info).await
    }

    /// Persist a token body under an explicit login type.
    /// 按指定 login_type 写入 token 体。
    pub async fn save_token_info_typed(
        &self,
        login_type: &str,
        info: &TokenInfo,
    ) -> SaTokenResult<()> {
        self.persist_token_body(login_type, info, self.ttl_for(info), false)
            .await
    }

    /// 读取 token 体（不做任何校验）| Read a token body without validation
    pub async fn get_token_info(&self, token: &str) -> SaTokenResult<Option<TokenInfo>> {
        self.get_token_info_typed(LOGIN_TYPE_DEFAULT, token).await
    }

    /// Read a token body under an explicit login type.
    /// 按指定 login_type 读取 token 体。
    pub async fn get_token_info_typed(
        &self,
        login_type: &str,
        token: &str,
    ) -> SaTokenResult<Option<TokenInfo>> {
        let key = self.token_key(login_type, token);
        if self.is_login_id_value() {
            let Some(raw) = self.dao.get_string(&key).await? else {
                return Ok(None);
            };
            if is_kick_out_marker(&raw) || is_replaced_marker(&raw) {
                return Ok(None);
            }
            return Ok(Some(
                self.synthesize_login_id_info(login_type, token, &raw)
                    .await?,
            ));
        }
        let Some(mut info) = self.dao.get_object::<TokenInfo>(&key).await? else {
            return Ok(None);
        };
        let _ = self
            .overlay_last_active(login_type, token, &mut info)
            .await?;
        Ok(Some(info))
    }

    /// 删除 token 体 | Delete a token body
    pub async fn delete_token_info(&self, token: &str) -> SaTokenResult<()> {
        self.delete_token_info_typed(LOGIN_TYPE_DEFAULT, token)
            .await
    }

    /// Delete a token body under an explicit login type.
    /// 按指定 login_type 删除 token 体。
    pub async fn delete_token_info_typed(
        &self,
        login_type: &str,
        token: &str,
    ) -> SaTokenResult<()> {
        self.dao.delete(&self.token_key(login_type, token)).await?;
        if self.last_active_enabled() {
            let _ = self
                .dao
                .delete(&self.last_active_key(login_type, token))
                .await;
        }
        Ok(())
    }

    // ==================== login:token 提交点映射 | Commit-point mapping ====================

    /// 读取 `login:token` 映射 | Read the `login:token` mapping
    pub async fn get_login_mapping(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Option<String>> {
        if !self.uses_rust_index() {
            return Ok(None);
        }
        let key = self.dao.keys().login_token(login_type, login_id);
        self.dao.get_string(&key).await
    }

    /// 无条件写入 `login:token` 映射（并发模式使用）。
    /// Unconditionally write the mapping (used in concurrent mode).
    pub async fn save_login_mapping(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<()> {
        self.save_login_mapping_with_ttl(login_type, login_id, token, self.ttl())
            .await
    }

    /// Write `login:token` with an explicit TTL, taking `max(existing, new)`.
    /// 写入 `login:token`，TTL 取 `max(现有, 新)`。
    pub async fn save_login_mapping_with_ttl(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
        ttl: Option<Duration>,
    ) -> SaTokenResult<()> {
        if !self.uses_rust_index() {
            return Ok(());
        }
        let key = self.dao.keys().login_token(login_type, login_id);
        let ttl = self.max_ttl(&key, ttl).await?;
        self.dao.set_string(&key, token, ttl).await
    }

    /// CAS 写入 `login:token` 映射 —— 登录事务的提交点（修 B1-14）。
    pub async fn cas_login_mapping(
        &self,
        login_type: &str,
        login_id: &str,
        expected: Option<&str>,
        new_token: &str,
    ) -> SaTokenResult<bool> {
        self.cas_login_mapping_with_ttl(login_type, login_id, expected, new_token, self.ttl())
            .await
    }

    /// CAS-write `login:token` with an explicit TTL (`max(existing, new)`).
    /// CAS 写入 `login:token`，TTL 取 `max(现有, 新)`。
    pub async fn cas_login_mapping_with_ttl(
        &self,
        login_type: &str,
        login_id: &str,
        expected: Option<&str>,
        new_token: &str,
        ttl: Option<Duration>,
    ) -> SaTokenResult<bool> {
        if !self.uses_rust_index() {
            return Ok(true);
        }
        let key = self.dao.keys().login_token(login_type, login_id);
        let ttl = self.max_ttl(&key, ttl).await?;
        self.dao.cas(&key, expected, new_token, ttl).await
    }

    /// 删除 `login:token` 映射 | Delete the mapping
    pub async fn delete_login_mapping(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<()> {
        if !self.uses_rust_index() {
            return Ok(());
        }
        self.dao
            .delete(&self.dao.keys().login_token(login_type, login_id))
            .await
    }

    /// 仅当映射仍指向指定 token 时才删除（原子，修 B1-14 的对偶场景）。
    pub async fn cas_delete_login_mapping(
        &self,
        login_type: &str,
        login_id: &str,
        expected_token: &str,
    ) -> SaTokenResult<bool> {
        if !self.uses_rust_index() {
            return Ok(true);
        }
        let key = self.dao.keys().login_token(login_type, login_id);
        self.dao.cas_delete(&key, expected_token).await
    }

    // ==================== token-id 反向映射 | Reverse mapping ====================

    /// 编码复合映射值：`{login_type}\u{1}{login_id}`（修 B1-11）。
    fn encode_token_id_value(login_type: &str, login_id: &str) -> String {
        let mut s = String::with_capacity(login_type.len() + 1 + login_id.len());
        s.push_str(login_type);
        s.push(TOKEN_ID_SEP);
        s.push_str(login_id);
        s
    }

    /// 解析映射值，兼容旧格式与下线标记。
    fn parse_token_id_value(raw: &str) -> TokenIdMapping {
        if is_kick_out_marker(raw) {
            return TokenIdMapping::KickedOut;
        }
        if is_replaced_marker(raw) {
            return TokenIdMapping::Replaced;
        }
        match raw.split_once(TOKEN_ID_SEP) {
            Some((lt, lid)) => TokenIdMapping::Identity {
                login_type: if lt.is_empty() {
                    LOGIN_TYPE_DEFAULT.to_string()
                } else {
                    lt.to_string()
                },
                login_id: lid.to_string(),
            },
            None => TokenIdMapping::Identity {
                login_type: LOGIN_TYPE_DEFAULT.to_string(),
                login_id: raw.to_string(),
            },
        }
    }

    /// 写入 token → 身份 的反向映射。
    pub async fn save_token_id_mapping(
        &self,
        token: &str,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<()> {
        self.save_token_id_mapping_with_ttl(token, login_type, login_id, self.ttl())
            .await
    }

    /// Write token → identity mapping with an explicit TTL.
    /// 写入 token → 身份 映射，使用本次 TTL。
    pub async fn save_token_id_mapping_with_ttl(
        &self,
        token: &str,
        login_type: &str,
        login_id: &str,
        ttl: Option<Duration>,
    ) -> SaTokenResult<()> {
        if !self.uses_rust_index() {
            return Ok(());
        }
        let key = self.dao.keys().token_id_mapping(token);
        let value = Self::encode_token_id_value(login_type, login_id);
        self.dao.set_string(&key, &value, ttl).await
    }

    /// 写入下线标记（`-4` / `-5`），同样带 TTL。
    pub async fn mark_token_id(&self, token: &str, marker: &str) -> SaTokenResult<()> {
        if !self.uses_rust_index() {
            return Ok(());
        }
        let key = self.dao.keys().token_id_mapping(token);
        self.dao.set_string(&key, marker, self.ttl()).await
    }

    /// 删除反向映射 | Delete the reverse mapping
    pub async fn delete_token_id_mapping(&self, token: &str) -> SaTokenResult<()> {
        if !self.uses_rust_index() {
            return Ok(());
        }
        self.dao
            .delete(&self.dao.keys().token_id_mapping(token))
            .await
    }

    /// 读取并解析反向映射 | Read and parse the reverse mapping
    pub async fn get_token_id_mapping(&self, token: &str) -> SaTokenResult<Option<TokenIdMapping>> {
        if !self.uses_rust_index() {
            return Ok(None);
        }
        let raw = self
            .dao
            .get_string(&self.dao.keys().token_id_mapping(token))
            .await?;
        Ok(raw.as_deref().map(Self::parse_token_id_value))
    }

    /// 校验下线标记：被踢/被顶时返回对应错误。
    pub async fn check_mapping_marker(&self, token: &str) -> SaTokenResult<()> {
        match self.get_token_id_mapping(token).await? {
            Some(TokenIdMapping::KickedOut) => Err(SaTokenError::AccountKickedOut),
            Some(TokenIdMapping::Replaced) => Err(SaTokenError::AccountReplaced),
            _ => Ok(()),
        }
    }

    // ==================== 多设备索引 | Multi-device index ====================

    /// 索引键 | Index key
    fn index_key(&self, login_type: &str, login_id: &str) -> String {
        self.dao.keys().login_token_index(login_type, login_id)
    }

    /// 追加 token 到索引（去重，原子 `list_push`）。
    pub async fn append_index(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<()> {
        self.append_index_with_ttl(login_type, login_id, token, self.ttl())
            .await
    }

    /// Append to the index with `max(existing TTL, new TTL)`.
    /// 追加索引，TTL 取 `max(现有, 新)`。
    pub async fn append_index_with_ttl(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
        ttl: Option<Duration>,
    ) -> SaTokenResult<()> {
        if !self.uses_rust_index() {
            return Ok(());
        }
        let key = self.index_key(login_type, login_id);
        let ttl = self.max_ttl(&key, ttl).await?;
        self.push_index(&key, token, ttl).await
    }

    /// Push a member; when targeting permanent, rewrite the list if it still has a TTL.
    /// 追加成员；目标为永久且现有仍带 TTL 时，重写列表以去掉过期。
    async fn push_index(&self, key: &str, token: &str, ttl: Option<Duration>) -> SaTokenResult<()> {
        if ttl.is_none() && self.dao.exists(key).await? && self.dao.ttl(key).await?.is_some() {
            let mut members = self.dao.list_range(key, 0, None).await?;
            if !members.iter().any(|m| m == token) {
                members.push(token.to_string());
            }
            self.dao.delete(key).await?;
            for m in members {
                self.dao.list_push_unique(key, &m, None).await?;
            }
            return Ok(());
        }
        self.dao.list_push_unique(key, token, ttl).await?;
        Ok(())
    }

    /// 从索引移除 token（原子 `list_remove`，幂等）。
    pub async fn remove_index(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
    ) -> SaTokenResult<bool> {
        if !self.uses_rust_index() {
            return Ok(true);
        }
        let key = self.index_key(login_type, login_id);
        self.dao.list_remove(&key, token).await
    }

    /// 刷新时把多设备索引中的旧 token 换成新 token。
    /// Replace the old token with the new one in the multi-device index on refresh.
    pub async fn replace_index(
        &self,
        login_type: &str,
        login_id: &str,
        old_token: &str,
        new_token: &str,
    ) -> SaTokenResult<()> {
        if old_token == new_token {
            return Ok(());
        }
        let _ = self.remove_index(login_type, login_id, old_token).await?;
        self.append_index(login_type, login_id, new_token).await
    }

    /// 列出索引中的全部 token（按写入顺序，最旧在前）。
    pub async fn list_tokens(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        if !self.uses_rust_index() {
            return Ok(Vec::new());
        }
        let key = self.index_key(login_type, login_id);
        self.dao.list_range(&key, 0, None).await
    }

    /// 剔除索引中的孤儿 token，返回 (存活列表, 剔除数量)。
    pub async fn prune_index(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<(Vec<String>, usize)> {
        if !self.uses_rust_index() {
            return Ok((Vec::new(), 0));
        }
        let key = self.index_key(login_type, login_id);
        let tokens = self.dao.list_range(&key, 0, None).await?;

        let mut alive = Vec::with_capacity(tokens.len());
        let mut pruned = 0usize;

        for t in tokens {
            match self.get_token_info_typed(login_type, &t).await {
                Ok(Some(_)) => alive.push(t),
                Ok(None) => {
                    let _ = self.dao.list_remove(&key, &t).await;
                    pruned += 1;
                    tracing::debug!(token = %t, "pruned orphan token from login index");
                }
                Err(e) => {
                    tracing::warn!(token = %t, error = %e, "index prune probe failed, keeping entry");
                    alive.push(t);
                }
            }
        }

        Ok((alive, pruned))
    }

    // ==================== 续签策略 | Renewal policy ====================

    /// 是否需要执行自动续签 —— `auto_renew` + `renew_threshold` 的**唯一**判定处。
    pub fn should_auto_renew(&self, info: &TokenInfo) -> bool {
        if !self.config.auto_renew {
            return false;
        }

        if self.config.renew_threshold < 0 {
            return true;
        }

        match info.expire_time {
            Some(expire) => {
                let remaining = expire.signed_duration_since(Utc::now()).num_seconds();
                remaining <= self.config.renew_threshold
            }
            None => self.config.active_timeout > 0,
        }
    }

    /// 执行续签写入并返回更新后的 TokenInfo。
    pub async fn apply_auto_renew(&self, token: &str, info: TokenInfo) -> SaTokenResult<TokenInfo> {
        self.apply_auto_renew_typed(LOGIN_TYPE_DEFAULT, token, info)
            .await
    }

    /// Auto-renew under an explicit login type.
    /// 按指定 login_type 执行续签写入。
    pub async fn apply_auto_renew_typed(
        &self,
        login_type: &str,
        token: &str,
        mut info: TokenInfo,
    ) -> SaTokenResult<TokenInfo> {
        info.update_active_time();

        let secs = self.dao.renew_secs();
        let ttl = if secs > 0 {
            info.expire_time = Some(Utc::now() + ChronoDuration::seconds(secs));
            Some(Duration::from_secs(secs as u64))
        } else {
            info.expire_time = None;
            None
        };

        self.persist_token_body(login_type, &info, ttl, false)
            .await?;
        if self.uses_rust_index() {
            let map_key = self.dao.keys().token_id_mapping(token);
            self.write_ttl(&map_key, ttl).await?;
        }
        Ok(info)
    }

    /// Update `last_active_time` with KEEPTTL. Does not change `expire_time`.
    /// Same `SaTokenContext` request refreshes once; no context refreshes every call.
    /// 只更新 last-active 并 KEEPTTL 写回，不改 `expire_time`。
    /// 同一请求只刷新一次；无上下文则每次都刷。
    pub async fn apply_active_refresh(
        &self,
        token: &str,
        info: TokenInfo,
    ) -> SaTokenResult<TokenInfo> {
        self.apply_active_refresh_typed(LOGIN_TYPE_DEFAULT, token, info)
            .await
    }

    /// Refresh last-active under an explicit login type.
    /// 按指定 login_type 刷新 last-active。
    pub async fn apply_active_refresh_typed(
        &self,
        login_type: &str,
        token: &str,
        mut info: TokenInfo,
    ) -> SaTokenResult<TokenInfo> {
        if SaTokenContext::try_current().is_some_and(|c| c.active_refreshed()) {
            return Ok(info);
        }

        info.update_active_time();
        match self.config.wire.last_active {
            LastActiveStore::SeparateKey => {
                self.write_last_active(login_type, token, &info, None, true)
                    .await?;
            }
            LastActiveStore::InTokenInfo => {
                let key = self.token_key(login_type, token);
                if self.is_login_id_value() {
                    self.set_keep_ttl_raw(&key, info.login_id.as_ref()).await?;
                } else {
                    self.dao.set_object_keep_ttl(&key, &info).await?;
                }
            }
        }

        if SaTokenContext::try_current().is_some() {
            let _ = SaTokenContext::with_current_mut(|inner| {
                inner.active_refreshed = true;
            });
        }
        Ok(info)
    }

    // ==================== 组合读取 | Composite reads ====================

    /// 读取并校验 token（标记 → 存在性 → 过期 → 冻结），**不触发**续签。
    pub async fn load_token_info_no_renew(&self, token: &TokenValue) -> SaTokenResult<TokenInfo> {
        self.load_token_info_no_renew_typed(LOGIN_TYPE_DEFAULT, token)
            .await
    }

    /// Load and validate a token under an explicit login type (no renew).
    /// 按指定 login_type 读取并校验 token（不续签）。
    pub async fn load_token_info_no_renew_typed(
        &self,
        login_type: &str,
        token: &TokenValue,
    ) -> SaTokenResult<TokenInfo> {
        self.check_mapping_marker(token.as_str()).await?;

        let info = if self.is_login_id_value() {
            let key = self.token_key(login_type, token.as_str());
            let raw = self
                .dao
                .get_string(&key)
                .await?
                .ok_or(SaTokenError::TokenNotFound)?;
            if is_kick_out_marker(&raw) {
                return Err(SaTokenError::AccountKickedOut);
            }
            if is_replaced_marker(&raw) {
                return Err(SaTokenError::AccountReplaced);
            }
            self.synthesize_login_id_info(login_type, token.as_str(), &raw)
                .await?
        } else {
            self.get_token_info_typed(login_type, token.as_str())
                .await?
                .ok_or(SaTokenError::TokenNotFound)?
        };

        if info.is_expired() {
            return Err(SaTokenError::TokenExpired);
        }
        if self.last_active_enabled() {
            let la_key = self.last_active_key(login_type, token.as_str());
            if !self.dao.exists(&la_key).await? {
                return Err(SaTokenError::TokenInactive);
            }
        }
        if info.is_freeze(info.effective_active_timeout(&self.config)) {
            return Err(SaTokenError::TokenInactive);
        }
        Ok(info)
    }

    /// 读取并校验 token，按策略执行活跃刷新与自动续签。
    pub async fn load_valid_token_info(&self, token: &TokenValue) -> SaTokenResult<TokenInfo> {
        self.load_valid_token_info_typed(LOGIN_TYPE_DEFAULT, token)
            .await
    }

    /// Load, validate, refresh and renew under an explicit login type.
    /// 按指定 login_type 读取、校验、刷新并续签。
    pub async fn load_valid_token_info_typed(
        &self,
        login_type: &str,
        token: &TokenValue,
    ) -> SaTokenResult<TokenInfo> {
        let info = self
            .load_token_info_no_renew_typed(login_type, token)
            .await?;
        let info = if self.config.active_refresh {
            self.apply_active_refresh_typed(login_type, token.as_str(), info)
                .await?
        } else {
            info
        };
        if self.should_auto_renew(&info) {
            return self
                .apply_auto_renew_typed(login_type, token.as_str(), info)
                .await;
        }
        Ok(info)
    }

    /// Retire a token: delete, or write `-4`/`-5` with KEEPTTL.
    /// 下线 token：删除，或 KEEPTTL 写入 `-4`/`-5`。
    pub async fn retire(
        &self,
        login_type: &str,
        token: &str,
        mode: LogoutMode,
        keep_token_session: bool,
    ) -> SaTokenResult<()> {
        let token_key = self.token_key(login_type, token);
        match (self.is_login_id_value(), mode) {
            (true, LogoutMode::KickOut) => {
                self.set_keep_ttl_raw(&token_key, TOKEN_MAP_KICK_OUT)
                    .await?;
            }
            (true, LogoutMode::Replaced) => {
                self.set_keep_ttl_raw(&token_key, TOKEN_MAP_BE_REPLACED)
                    .await?;
            }
            (_, LogoutMode::Logout) | (false, _) => {
                self.dao.delete(&token_key).await?;
            }
        }

        if self.last_active_enabled() {
            let _ = self
                .dao
                .delete(&self.last_active_key(login_type, token))
                .await;
        }

        if !keep_token_session {
            let _ = self
                .dao
                .delete(&self.dao.keys().token_session_with_type(login_type, token))
                .await;
        }

        match mode {
            LogoutMode::Logout => self.delete_token_id_mapping(token).await?,
            LogoutMode::KickOut => {
                self.mark_token_id(token, TOKEN_MAP_KICK_OUT).await?;
            }
            LogoutMode::Replaced => {
                self.mark_token_id(token, TOKEN_MAP_BE_REPLACED).await?;
            }
        }
        Ok(())
    }

    /// 踢下线标记值 | Kick-out marker value
    pub fn kick_out_marker(&self) -> &'static str {
        TOKEN_MAP_KICK_OUT
    }

    /// 顶下线标记值 | Replaced marker value
    pub fn replaced_marker(&self) -> &'static str {
        TOKEN_MAP_BE_REPLACED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokenStyle;
    use crate::context::SaTokenContext;
    use sa_token_adapter::CountingStorage;
    use sa_token_adapter::storage::SaStorage;
    use sa_token_storage_memory::MemoryStorage;

    fn repo(auto_renew: bool, renew_threshold: i64, timeout: i64) -> TokenRepo {
        repo_cfg(SaTokenConfig {
            auto_renew,
            renew_threshold,
            timeout,
            active_timeout: -1,
            token_style: TokenStyle::Uuid,
            ..Default::default()
        })
    }

    fn repo_cfg(config: SaTokenConfig) -> TokenRepo {
        let config = Arc::new(config);
        let dao = Arc::new(SaTokenDao::new(
            Arc::new(MemoryStorage::new()),
            config.clone(),
        ));
        TokenRepo::new(dao, config)
    }

    async fn seed_token(
        repo: &TokenRepo,
        token: &str,
        idle_secs: i64,
        expire_in_secs: i64,
    ) -> TokenInfo {
        let mut info = TokenInfo::new(TokenValue::new(token), "u");
        info.last_active_time = Utc::now() - ChronoDuration::seconds(idle_secs);
        info.expire_time = Some(Utc::now() + ChronoDuration::seconds(expire_in_secs));
        repo.save_token_info(&info).await.unwrap();
        repo.get_token_info(token).await.unwrap().unwrap()
    }

    #[test]
    fn should_auto_renew_false_when_disabled() {
        let r = repo(false, -1, 3600);
        let mut info = TokenInfo::new(TokenValue::new("t"), "u");
        info.expire_time = Some(Utc::now() + ChronoDuration::seconds(10));
        assert!(!r.should_auto_renew(&info));
    }

    #[test]
    fn should_auto_renew_always_when_threshold_negative() {
        let r = repo(true, -1, 3600);
        let mut info = TokenInfo::new(TokenValue::new("t"), "u");
        info.expire_time = Some(Utc::now() + ChronoDuration::seconds(3500));
        assert!(r.should_auto_renew(&info));
    }

    #[test]
    fn should_auto_renew_only_when_remaining_within_threshold() {
        let r = repo(true, 300, 3600);
        let mut far = TokenInfo::new(TokenValue::new("t1"), "u");
        far.expire_time = Some(Utc::now() + ChronoDuration::seconds(3500));
        assert!(!r.should_auto_renew(&far));

        let mut near = TokenInfo::new(TokenValue::new("t2"), "u");
        near.expire_time = Some(Utc::now() + ChronoDuration::seconds(200));
        assert!(r.should_auto_renew(&near));
    }

    #[tokio::test]
    async fn active_refresh_false_does_not_advance_last_active() {
        let r = repo_cfg(SaTokenConfig {
            active_refresh: false,
            auto_renew: false,
            active_timeout: 3600,
            timeout: 86400,
            ..Default::default()
        });
        let before = seed_token(&r, "t", 10, 86400).await;
        let loaded = r
            .load_valid_token_info(&TokenValue::new("t"))
            .await
            .unwrap();
        assert_eq!(loaded.last_active_time, before.last_active_time);
        assert_eq!(loaded.expire_time, before.expire_time);
    }

    #[tokio::test]
    async fn active_refresh_true_advances_last_active_keeps_expire_time() {
        let r = repo_cfg(SaTokenConfig {
            active_refresh: true,
            auto_renew: false,
            active_timeout: 3600,
            timeout: 86400,
            ..Default::default()
        });
        let before = seed_token(&r, "t", 10, 86400).await;
        let loaded = r
            .load_valid_token_info(&TokenValue::new("t"))
            .await
            .unwrap();
        assert!(
            loaded.last_active_time > before.last_active_time,
            "active_refresh must advance last_active_time"
        );
        assert_eq!(loaded.expire_time, before.expire_time);
    }

    #[tokio::test]
    async fn active_refresh_skips_when_frozen() {
        let r = repo_cfg(SaTokenConfig {
            active_refresh: true,
            auto_renew: false,
            active_timeout: 60,
            timeout: 86400,
            ..Default::default()
        });
        let before = seed_token(&r, "t", 61, 86400).await;
        let err = r
            .load_valid_token_info(&TokenValue::new("t"))
            .await
            .unwrap_err();
        assert!(matches!(err, SaTokenError::TokenInactive));
        let stored = r.get_token_info("t").await.unwrap().unwrap();
        assert_eq!(stored.last_active_time, before.last_active_time);
    }

    #[tokio::test]
    async fn active_refresh_once_per_request_scope() {
        let counting = Arc::new(CountingStorage::new(Arc::new(MemoryStorage::new())));
        let config = Arc::new(SaTokenConfig {
            active_refresh: true,
            auto_renew: false,
            active_timeout: 3600,
            timeout: 86400,
            ..Default::default()
        });
        let storage: Arc<dyn SaStorage> = counting.clone();
        let dao = Arc::new(SaTokenDao::new(storage, config.clone()));
        let r = TokenRepo::new(dao, config);
        let before = seed_token(&r, "t", 10, 86400).await;
        let tv = TokenValue::new("t");
        let ctx = SaTokenContext::new();

        SaTokenContext::scope(ctx, async {
            let first = r.load_valid_token_info(&tv).await.unwrap();
            assert!(first.last_active_time > before.last_active_time);
            counting.reset_counts();
            let second = r.load_valid_token_info(&tv).await.unwrap();
            assert_eq!(second.last_active_time, first.last_active_time);
            assert_eq!(
                counting.set_count(),
                0,
                "second load in the same request must not write"
            );
        })
        .await;
    }

    #[test]
    fn ttl_for_none_is_permanent() {
        let r = repo(false, -1, 10);
        let info = TokenInfo::new(TokenValue::new("t"), "u");
        assert!(r.ttl_for(&info).is_none());
    }

    #[test]
    fn ttl_for_remaining_clamps_at_zero() {
        let r = repo(false, -1, 10);
        let mut info = TokenInfo::new(TokenValue::new("t"), "u");
        info.expire_time = Some(Utc::now() + ChronoDuration::seconds(3600));
        let secs = r.ttl_for(&info).expect("finite ttl").as_secs();
        assert!(
            (3590..=3600).contains(&secs),
            "remaining should be ~3600, got {secs}"
        );

        info.expire_time = Some(Utc::now() - ChronoDuration::seconds(5));
        assert_eq!(r.ttl_for(&info).expect("expired ttl").as_secs(), 0);
    }

    #[tokio::test]
    async fn save_token_info_uses_expire_time_not_global() {
        let r = repo(false, -1, 10);
        let mut info = TokenInfo::new(TokenValue::new("t"), "u");
        info.expire_time = Some(Utc::now() + ChronoDuration::seconds(3600));
        r.save_token_info(&info).await.expect("save");
        let key = r.dao().keys().token_info("t");
        let ttl = r
            .dao()
            .ttl(&key)
            .await
            .expect("ttl")
            .expect("finite")
            .as_secs();
        assert!(
            (3590..=3600).contains(&ttl),
            "token body ttl={ttl}, want ~3600 not global 10"
        );
    }

    #[tokio::test]
    async fn max_ttl_keeps_longer_and_permanent() {
        let r = repo(false, -1, 10);
        let key = "sa:login:tokens:u";
        r.dao()
            .list_push_unique(key, "t1", Some(Duration::from_secs(3600)))
            .await
            .expect("seed index");

        let kept = r
            .max_ttl(key, Some(Duration::from_secs(10)))
            .await
            .expect("max");
        let secs = kept.expect("finite").as_secs();
        assert!(
            (3590..=3600).contains(&secs),
            "max_ttl must not shorten, got {secs}"
        );

        let missing = r
            .max_ttl("sa:login:tokens:missing", Some(Duration::from_secs(10)))
            .await
            .expect("missing");
        assert_eq!(missing, Some(Duration::from_secs(10)));

        assert!(
            r.max_ttl(key, None).await.expect("permanent new").is_none(),
            "new permanent wins"
        );

        r.dao()
            .set_string("sa:login:token:perm", "t", None)
            .await
            .expect("seed permanent");
        assert!(
            r.max_ttl("sa:login:token:perm", Some(Duration::from_secs(10)))
                .await
                .expect("existing permanent")
                .is_none(),
            "existing permanent must not shorten"
        );
    }

    #[tokio::test]
    async fn append_index_takes_max_ttl() {
        let r = repo(false, -1, 10);
        r.append_index_with_ttl("default", "u", "t1", Some(Duration::from_secs(3600)))
            .await
            .expect("first");
        r.append_index_with_ttl("default", "u", "t2", Some(Duration::from_secs(10)))
            .await
            .expect("second");
        let key = r.index_key("default", "u");
        let ttl = r
            .dao()
            .ttl(&key)
            .await
            .expect("ttl")
            .expect("finite")
            .as_secs();
        assert!(
            (3590..=3600).contains(&ttl),
            "index ttl={ttl}, want ~3600 not 10"
        );
    }

    #[tokio::test]
    async fn apply_auto_renew_syncs_mapping_ttl() {
        let r = repo(true, -1, 3600);
        let token = "t-renew";
        let mut info = TokenInfo::new(TokenValue::new(token), "u");
        info.expire_time = Some(Utc::now() + ChronoDuration::seconds(10));
        r.save_token_info(&info).await.expect("save body");
        r.save_token_id_mapping_with_ttl(token, "default", "u", Some(Duration::from_secs(10)))
            .await
            .expect("save mapping");

        r.apply_auto_renew(token, info).await.expect("renew");
        let map_key = r.dao().keys().token_id_mapping(token);
        let ttl = r
            .dao()
            .ttl(&map_key)
            .await
            .expect("ttl")
            .expect("finite")
            .as_secs();
        assert!(
            (3590..=3600).contains(&ttl),
            "mapping ttl after auto_renew={ttl}, want ~3600"
        );
    }

    fn mixed_java_cfg(active_timeout: i64) -> SaTokenConfig {
        let mut wire = crate::compat::WireConfig::native();
        wire.token_value = TokenValueFormat::LoginId;
        wire.last_active = LastActiveStore::SeparateKey;
        wire.account_index = AccountIndex::SessionTerminals;
        wire.session_format = crate::compat::SessionFormat::Serde;
        wire.default_login_type = "login".into();
        wire.default_device_type = Some("DEF".into());
        wire.allow_login_id_colon = false;
        SaTokenConfig {
            token_name: "satoken".into(),
            key_layout: crate::keys::SaKeyLayout::JavaFourSegment,
            wire,
            timeout: 3600,
            active_timeout,
            auto_renew: false,
            active_refresh: true,
            max_login_count: 12,
            token_style: TokenStyle::Uuid,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn login_id_writes_plain_login_id_and_last_active_ms() {
        let r = repo_cfg(mixed_java_cfg(1800));
        let mut info = TokenInfo::new(TokenValue::new("tok-1"), "10001");
        info.login_type = intern_login_type("login");
        info.expire_time = Some(Utc::now() + ChronoDuration::seconds(3600));
        r.save_token_info_typed("login", &info).await.expect("save");

        let token_key = r.dao().keys().token_info_with_type("login", "tok-1");
        let raw = r.dao().get_string(&token_key).await.unwrap().unwrap();
        assert_eq!(raw, "10001");

        let la_key = r.dao().keys().last_active_with_type("login", "tok-1");
        let la = r.dao().get_string(&la_key).await.unwrap().unwrap();
        assert_eq!(
            la.len(),
            13,
            "last-active must be 13-digit millis, got {la}"
        );
        assert!(la.chars().all(|c| c.is_ascii_digit()));

        assert!(
            r.dao()
                .get_string(&r.dao().keys().login_token("login", "10001"))
                .await
                .unwrap()
                .is_none()
        );
        let index = r
            .dao()
            .list_range(&r.dao().keys().login_token_index("login", "10001"), 0, None)
            .await
            .unwrap();
        assert!(index.is_empty());
    }

    #[tokio::test]
    async fn retire_kick_out_keeps_token_key_as_minus_five() {
        let r = repo_cfg(mixed_java_cfg(1800));
        let mut info = TokenInfo::new(TokenValue::new("tok-k"), "10001");
        info.expire_time = Some(Utc::now() + ChronoDuration::seconds(3600));
        r.save_token_info_typed("login", &info).await.unwrap();

        r.retire("login", "tok-k", LogoutMode::KickOut, false)
            .await
            .unwrap();

        let token_key = r.dao().keys().token_info_with_type("login", "tok-k");
        assert!(r.dao().exists(&token_key).await.unwrap());
        let raw = r.dao().get_string(&token_key).await.unwrap().unwrap();
        assert_eq!(raw, "-5");

        let err = r
            .load_valid_token_info_typed("login", &TokenValue::new("tok-k"))
            .await
            .unwrap_err();
        assert!(matches!(err, SaTokenError::AccountKickedOut));
    }

    #[tokio::test]
    async fn missing_last_active_freezes_when_active_timeout_on() {
        let r = repo_cfg(mixed_java_cfg(1800));
        let token_key = r.dao().keys().token_info_with_type("login", "tok-m");
        r.dao()
            .set_string(&token_key, "10001", Some(Duration::from_secs(3600)))
            .await
            .unwrap();

        let err = r
            .load_valid_token_info_typed("login", &TokenValue::new("tok-m"))
            .await
            .unwrap_err();
        assert!(matches!(err, SaTokenError::TokenInactive));
    }

    #[tokio::test]
    async fn session_terminals_index_methods_are_noop() {
        let r = repo_cfg(mixed_java_cfg(-1));
        r.append_index("login", "10001", "t1").await.unwrap();
        r.save_login_mapping("login", "10001", "t1").await.unwrap();
        assert!(
            r.get_login_mapping("login", "10001")
                .await
                .unwrap()
                .is_none()
        );
        assert!(r.list_tokens("login", "10001").await.unwrap().is_empty());
        assert!(
            r.cas_login_mapping("login", "10001", None, "t2")
                .await
                .unwrap()
        );
        assert!(
            r.dao()
                .get_string(&r.dao().keys().login_token("login", "10001"))
                .await
                .unwrap()
                .is_none()
        );
    }
}
