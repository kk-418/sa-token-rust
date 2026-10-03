//! 认证服务：登录、登出、踢人、续期的唯一业务入口。
//!
//! 本模块承担「跨仓储编排」职责：单个仓储只保证单键操作正确，
//! 而一次登录要同时改动 6 个键、一次下线要同时改动 5 个键，
//! 这些复合操作的顺序、失败补偿与并发保护全部收敛在这里。
//!
//! Authentication service: the single entry point for login, logout, kickout and
//! renewal. Because `SaStorage` only guarantees single-key atomicity, a login is
//! made near-transactional through staged writes, reverse compensation, and a
//! compare-and-swap commit point on the `login:token` mapping.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};

use crate::compat::{AccountIndex, LastActiveStore, TokenValueFormat};
use crate::config::{
    LogoutMode, LogoutRange, ReplacedLoginExitMode, ReplacedRange, SaTokenConfig, TokenStyle,
};
use crate::dao::SaTokenDao;
use crate::distributed::DistributedSessionManager;
use crate::error::{SaTokenError, SaTokenResult};
use crate::event::{SaTokenEvent, SaTokenEventBus};
use crate::keys::{AccountNs, LOGIN_TYPE_DEFAULT, LoginId, SaKeys};
use crate::nonce::NonceManager;
use crate::online::OnlineManager;
use crate::refresh::RefreshTokenManager;
use crate::repository::{SessionRepo, TokenIdMapping, TokenRepo};
use crate::service::compensate::LoginCompensator;
use crate::service::login_request::LoginRequest;
use crate::session::SaTerminalInfo;
use crate::token::{
    JwtAlgorithm, JwtManager, TokenGenContext, TokenGenerator, TokenInfo, TokenValue,
};

/// 下线时解析出的账号身份 | Account identity resolved during logout
struct LogoutIdentity {
    login_type: String,
    login_id: String,
    /// token 体是否存在（决定是否需要清理终端与 Session）
    /// Whether the token body existed, deciding terminal/session cleanup
    _body_existed: bool,
}

/// 认证领域服务 | Authentication domain service
pub struct AuthService {
    dao: Arc<SaTokenDao>,
    token_repo: Arc<TokenRepo>,
    session_repo: Arc<SessionRepo>,
    config: Arc<SaTokenConfig>,
    event_bus: SaTokenEventBus,
    online_manager: Option<Arc<OnlineManager>>,
    /// Optional cross-service session; None keeps current login behaviour.
    /// 可选跨服务会话；None 时登录行为与现在一致。
    distributed: Option<Arc<DistributedSessionManager>>,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthService { .. }")
    }
}

impl AuthService {
    /// 构造服务。
    pub fn new(
        dao: Arc<SaTokenDao>,
        config: Arc<SaTokenConfig>,
        token_repo: Arc<TokenRepo>,
        session_repo: Arc<SessionRepo>,
        event_bus: SaTokenEventBus,
        online_manager: Option<Arc<OnlineManager>>,
        distributed: Option<Arc<DistributedSessionManager>>,
    ) -> Self {
        Self {
            dao,
            token_repo,
            session_repo,
            config,
            event_bus,
            online_manager,
            distributed,
        }
    }

    /// Token 仓储 | Token repository
    pub fn token_repo(&self) -> &Arc<TokenRepo> {
        &self.token_repo
    }

    /// Session 仓储 | Session repository
    pub fn session_repo(&self) -> &Arc<SessionRepo> {
        &self.session_repo
    }

    /// 账号命名空间构造（统一校验入口）| Build the account namespace with validation
    fn account_ns(&self, login_type: &str, login_id: &str) -> SaTokenResult<AccountNs> {
        let id = LoginId::try_new_with(login_id, self.config.wire.allow_login_id_colon)
            .map_err(|e| SaTokenError::ConfigError(e.to_string()))?;
        if self.config.wire.token_value == TokenValueFormat::LoginId {
            id.reject_reserved_markers()
                .map_err(|e| SaTokenError::ConfigError(e.to_string()))?;
        }
        Ok(SaKeys::account_ns(login_type, &id))
    }

    fn uses_session_terminals(&self) -> bool {
        self.config.wire.account_index == AccountIndex::SessionTerminals
    }

    fn uses_java_write_order(&self) -> bool {
        self.uses_session_terminals() || self.config.wire.token_value == TokenValueFormat::LoginId
    }

    /// Device for this login: request value, else `wire.default_device_type`.
    fn login_device<'a>(&'a self, req: &'a LoginRequest) -> Option<&'a str> {
        req.effective_device()
            .or(self.config.wire.default_device_type.as_deref())
    }

    /// JWT Stateless 模式（Java `StpLogicJwtForStateless`）。
    fn is_jwt_stateless(&self) -> bool {
        matches!(self.config.token_style, TokenStyle::JwtStateless)
    }

    /// JWT Mixin 模式（Java `StpLogicJwtForMixin`）。
    fn is_jwt_mixin(&self) -> bool {
        matches!(self.config.token_style, TokenStyle::JwtMixin)
    }

    /// 踢人 / 按账号登出 / 顶号在 Stateless 下不可用。
    fn reject_jwt_stateless(&self) -> SaTokenResult<()> {
        if self.is_jwt_stateless() {
            Err(SaTokenError::ApiDisabled("jwt-stateless".into()))
        } else {
            Ok(())
        }
    }

    /// 踢人 / 按账号登出 / 顶号 / 续期在 Mixin 下不可用。
    fn reject_jwt_mixin(&self) -> SaTokenResult<()> {
        if self.is_jwt_mixin() {
            Err(SaTokenError::ApiDisabled("jwt-mixin".into()))
        } else {
            Ok(())
        }
    }

    /// Stateless 与 Mixin 共用的禁用 API。
    fn reject_jwt_disabled_api(&self) -> SaTokenResult<()> {
        self.reject_jwt_stateless()?;
        self.reject_jwt_mixin()
    }

    /// JWT `loginType` claim：空 / default / login 映射到 `wire.default_login_type`。
    fn jwt_claim_login_type<'a>(&'a self, login_type: &'a str) -> &'a str {
        if login_type.is_empty()
            || login_type == LOGIN_TYPE_DEFAULT
            || login_type == crate::keys::LOGIN_TYPE_LOGIN
        {
            if self.config.wire.default_login_type.is_empty() {
                "default"
            } else {
                self.config.wire.default_login_type.as_str()
            }
        } else {
            login_type
        }
    }

    /// 按当前配置构造验签用 `JwtManager`。
    fn jwt_manager(&self) -> SaTokenResult<JwtManager> {
        let secret = self
            .config
            .jwt_secret_key
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                SaTokenError::ConfigError("jwt_secret_key is required for JWT token styles".into())
            })?;
        let algorithm = match self
            .config
            .jwt_algorithm
            .as_deref()
            .map(str::to_ascii_uppercase)
            .as_deref()
        {
            Some("HS384") => JwtAlgorithm::HS384,
            Some("HS512") => JwtAlgorithm::HS512,
            Some("RS256") => JwtAlgorithm::RS256,
            Some("RS384") => JwtAlgorithm::RS384,
            Some("RS512") => JwtAlgorithm::RS512,
            Some("ES256") => JwtAlgorithm::ES256,
            Some("ES384") => JwtAlgorithm::ES384,
            _ => JwtAlgorithm::HS256,
        };
        let mut mgr = JwtManager::with_algorithm(secret, algorithm);
        if let Some(ref issuer) = self.config.jwt_issuer {
            mgr = mgr.set_issuer(issuer);
        }
        if let Some(ref audience) = self.config.jwt_audience {
            mgr = mgr.set_audience(audience);
        }
        Ok(mgr)
    }

    /// 验签 JWT 并从 claims 合成 `TokenInfo`（不读 storage）。
    fn token_info_from_jwt(
        &self,
        login_type: &str,
        token: &TokenValue,
    ) -> SaTokenResult<TokenInfo> {
        if self.config.wire.jwt_claims == crate::compat::JwtClaimsFormat::Java {
            let mgr = self.jwt_manager()?;
            let expected = self.jwt_claim_login_type(login_type);
            let check_eff = matches!(
                self.config.token_style,
                TokenStyle::JwtStateless | TokenStyle::JwtMixin
            );
            let claims =
                crate::compat::java_jwt::validate(&mgr, token.as_str(), expected, check_eff)?;
            let mut info = TokenInfo::new(token.clone(), claims.login_id);
            info.login_type = crate::token::intern_login_type(&claims.login_type);
            info.device = claims.device_type;
            if let Some(eff) = claims.eff {
                if eff == crate::compat::java_jwt::NEVER_EXPIRE {
                    info.expire_time = None;
                } else if eff > 0 {
                    info.expire_time = DateTime::<Utc>::from_timestamp_millis(eff);
                }
            }
            if !claims.extra.is_empty() {
                info.extra_data = Some(serde_json::Value::Object(claims.extra));
            }
            return Ok(info);
        }
        let claims = self.jwt_manager()?.validate(token.as_str())?;
        let mut info = TokenInfo::new(token.clone(), claims.login_id);
        if let Some(exp) = claims.exp {
            info.expire_time = DateTime::<Utc>::from_timestamp(exp, 0);
        }
        Ok(info)
    }

    /// 登录主流程：阶段化写入 + 逆序补偿 + CAS 提交点。
    pub async fn login(&self, req: LoginRequest) -> SaTokenResult<TokenValue> {
        let login_type = req.effective_login_type().to_string();
        let login_id = req.login_id.clone();
        let ns = self.account_ns(&login_type, &login_id)?;

        let mut compensator = LoginCompensator::new();

        // 默认 login 服务封禁时拒绝登录（与 check_disable 契约对齐）
        {
            use crate::disable::{DEFAULT_DISABLE_SERVICE, MIN_DISABLE_LEVEL, NOT_DISABLE_LEVEL};
            let key = self
                .dao
                .keys()
                .disable(&login_type, &login_id, DEFAULT_DISABLE_SERVICE);
            if let Some(raw) = self.dao.get_string(&key).await? {
                let level: i32 = raw.parse().unwrap_or(MIN_DISABLE_LEVEL);
                if level != NOT_DISABLE_LEVEL && level >= MIN_DISABLE_LEVEL {
                    return Err(SaTokenError::AccountBanned(format!(
                        "service={DEFAULT_DISABLE_SERVICE} level={level}"
                    )));
                }
            }
        }

        if self.config.enable_nonce
            && let Some(ref nonce_str) = req.nonce
        {
            self.consume_nonce(nonce_str, &login_id, &mut compensator)
                .await?;
        }

        if !self.is_jwt_stateless()
            && !self.is_jwt_mixin()
            && self.config.is_share
            && let Some(existing) = self
                .find_share_token(&login_type, &login_id, &ns, &req)
                .await?
        {
            compensator.commit();
            if self.config.is_log {
                tracing::info!(login_id = %login_id, "login success");
            }
            return Ok(existing);
        }

        let mut token_info = self.build_token_info(&req, &login_type).await?;
        let token = token_info.token.clone();

        if self.is_jwt_stateless() {
            compensator.commit();
            let event =
                SaTokenEvent::login(login_id.clone(), token.as_str()).with_login_type(&login_type);
            self.event_bus.publish(event).await;
            if self.config.is_log {
                tracing::info!(login_id = %login_id, "login success");
            }
            return Ok(token);
        }

        let mapping_before = self
            .token_repo
            .get_login_mapping(&login_type, &login_id)
            .await?;

        if !self.config.is_concurrent {
            match self
                .handle_replaced_on_login(&login_type, &login_id, &ns, &req, token.as_str())
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    let _ = compensator.rollback(&self.dao).await;
                    return Err(e);
                }
            }
        }

        let refresh_mgr = if self.config.enable_refresh_token {
            Some(RefreshTokenManager::new(
                self.dao.clone(),
                self.token_repo.clone(),
                self.config.clone(),
            ))
        } else {
            None
        };
        if let Some(ref mgr) = refresh_mgr {
            token_info.refresh_token = Some(mgr.generate(&login_id));
            if self.config.refresh_token_timeout > 0 {
                token_info.refresh_token_expire_time =
                    Some(Utc::now() + ChronoDuration::seconds(self.config.refresh_token_timeout));
            }
        }

        let write_result = self
            .write_login_stages(
                &login_type,
                &login_id,
                &ns,
                &req,
                &token_info,
                mapping_before.as_deref(),
                refresh_mgr.as_ref(),
                &mut compensator,
            )
            .await;

        if let Err(e) = write_result {
            let _ = compensator.rollback(&self.dao).await;
            return Err(e);
        }

        if let Err(e) = self.enforce_max_login_count(&login_type, &login_id).await {
            tracing::warn!(
                login_id = %login_id,
                error = %e,
                "max_login_count enforcement failed after commit, login still succeeds"
            );
        }

        compensator.commit();

        if let Some(online) = &self.online_manager {
            let device = self.login_device(&req).unwrap_or("unknown");
            let mut user = crate::online::OnlineUser::new(
                login_id.clone(),
                token.as_str().to_string(),
                device.to_string(),
            );
            user.login_type = login_type.clone();
            if let Err(e) = online.mark_online(user).await {
                tracing::warn!(error = %e, login_id = %login_id, "failed to mark online after login");
            }
        }

        if let Some(dm) = &self.distributed {
            if let Err(e) = dm
                .create_session(login_id.clone(), token.as_str().to_string())
                .await
            {
                tracing::warn!(error = %e, login_id = %login_id, "distributed session create failed after login commit");
            }
        }

        let event =
            SaTokenEvent::login(login_id.clone(), token.as_str()).with_login_type(&login_type);
        self.event_bus.publish(event).await;

        if self.config.is_log {
            tracing::info!(login_id = %login_id, "login success");
        }

        Ok(token)
    }

    async fn consume_nonce(
        &self,
        nonce_str: &str,
        login_id: &str,
        compensator: &mut LoginCompensator,
    ) -> SaTokenResult<()> {
        let nonce_timeout = if self.config.nonce_timeout > 0 {
            self.config.nonce_timeout
        } else {
            self.config.timeout
        };

        let nonce_key = self.dao.keys().nonce(nonce_str);
        let snapshot = self.dao.get_string(&nonce_key).await?;

        let nonce_mgr = NonceManager::from_dao(self.dao.clone(), nonce_timeout);
        nonce_mgr.validate_and_consume(nonce_str, login_id).await?;

        if let Some(raw) = snapshot {
            let ttl = if nonce_timeout > 0 {
                Some(Duration::from_secs(nonce_timeout as u64))
            } else {
                None
            };
            compensator.on_fail_restore(nonce_key, raw, ttl);
        }

        Ok(())
    }

    async fn build_token_info(
        &self,
        req: &LoginRequest,
        login_type: &str,
    ) -> SaTokenResult<TokenInfo> {
        let token = match req.preset_token.as_deref() {
            Some(preset) if !preset.is_empty() => TokenValue::new(preset),
            _ => {
                let extra = req.extra_data.clone();
                let login_id = req.login_id.clone();
                let cfg = self.config.clone();
                let skip_store_check = self.is_jwt_stateless() || self.is_jwt_mixin();
                let mixin_ctx = TokenGenContext {
                    login_id: login_id.clone(),
                    login_type: self.jwt_claim_login_type(login_type).to_string(),
                    device: self.login_device(req).map(str::to_string),
                    timeout_secs: req.timeout_secs.unwrap_or(self.config.timeout),
                    extra: extra.clone(),
                };
                let is_mixin = self.is_jwt_mixin();
                crate::token::generate_unique(
                    cfg.max_try_times,
                    || {
                        if is_mixin {
                            TokenGenerator::generate_for(&cfg, &mixin_ctx)
                        } else {
                            match extra.as_ref() {
                                Some(extra) => TokenGenerator::generate_with_login_id_and_extra(
                                    &cfg, &login_id, extra,
                                ),
                                None => TokenGenerator::generate_with_login_id(&cfg, &login_id),
                            }
                        }
                    },
                    |t| {
                        let repo = self.token_repo.clone();
                        let token = t.to_string();
                        let lt = login_type.to_string();
                        async move {
                            if skip_store_check {
                                Ok(false)
                            } else {
                                Ok(repo.get_token_info_typed(&lt, &token).await?.is_some())
                            }
                        }
                    },
                )
                .await?
            }
        };

        let mut info = TokenInfo::new(token, req.login_id.as_str());
        info.login_type = crate::token::intern_login_type(login_type);
        info.device = req.device.clone();
        info.extra_data = req.extra_data.clone();
        info.nonce = req.nonce.clone();
        info.update_active_time();

        if let Some(secs) = req.timeout_secs {
            if secs > 0 {
                info.expire_time = Some(Utc::now() + ChronoDuration::seconds(secs));
            } else {
                info.expire_time = None;
            }
        } else if let Some(expire) = req.expire_time {
            info.expire_time = Some(expire);
        } else if let Some(timeout) = self.config.timeout_duration() {
            let d = ChronoDuration::from_std(timeout).map_err(|_| {
                SaTokenError::ConfigError("timeout value is out of supported range".to_string())
            })?;
            info.expire_time = Some(Utc::now() + d);
        }

        Ok(info)
    }

    async fn find_share_token(
        &self,
        login_type: &str,
        login_id: &str,
        ns: &AccountNs,
        req: &LoginRequest,
    ) -> SaTokenResult<Option<TokenValue>> {
        if self.uses_session_terminals() {
            let device = self.login_device(req);
            let tokens = self.session_repo.get_token_list(ns, device).await?;
            for t in tokens.into_iter().rev() {
                let tv = TokenValue::new(t);
                if self
                    .token_repo
                    .load_valid_token_info_typed(login_type, &tv)
                    .await
                    .is_ok()
                {
                    return Ok(Some(tv));
                }
            }
            return Ok(None);
        }
        let Some(existing) = self
            .token_repo
            .get_login_mapping(login_type, login_id)
            .await?
        else {
            return Ok(None);
        };
        let existing_token = TokenValue::new(existing);
        if self
            .token_repo
            .load_valid_token_info_typed(login_type, &existing_token)
            .await
            .is_ok()
        {
            Ok(Some(existing_token))
        } else {
            Ok(None)
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_login_stages(
        &self,
        login_type: &str,
        login_id: &str,
        ns: &AccountNs,
        req: &LoginRequest,
        token_info: &TokenInfo,
        mapping_before: Option<&str>,
        refresh_mgr: Option<&RefreshTokenManager>,
        compensator: &mut LoginCompensator,
    ) -> SaTokenResult<()> {
        if self.is_jwt_mixin() {
            return self
                .write_login_stages_mixin(login_type, ns, req, token_info, compensator)
                .await;
        }

        if self.uses_java_write_order() {
            return self
                .write_login_stages_java(
                    login_type,
                    login_id,
                    ns,
                    req,
                    token_info,
                    refresh_mgr,
                    compensator,
                )
                .await;
        }

        let token = token_info.token.as_str();
        let keys = self.dao.keys();
        let login_ttl = self.token_repo.ttl_for(token_info);

        self.token_repo
            .append_index_with_ttl(login_type, login_id, token, login_ttl)
            .await?;
        compensator.on_fail_list_remove(keys.login_token_index(login_type, login_id), token);

        let session_key = keys
            .session_by_ns(ns)
            .map_err(|e| SaTokenError::ConfigError(e.to_string()))?;
        match self.session_repo.snapshot_account_session(ns).await? {
            Some(old_raw) => {
                let remaining = self.dao.ttl(&session_key).await?;
                compensator.on_fail_restore(session_key, old_raw, remaining);
            }
            None => compensator.on_fail_delete(session_key),
        }
        self.session_repo.update_min_timeout(ns, login_ttl).await?;
        let mut terminal = SaTerminalInfo::new(token, self.login_device(req).unwrap_or(""));
        if let Some(extra) = req.extra_data.clone() {
            terminal = terminal.with_extra_data(extra);
        }
        self.session_repo
            .add_terminal_with_ttl(ns, terminal, login_ttl)
            .await?;

        self.token_repo
            .save_token_id_mapping_with_ttl(token, login_type, login_id, login_ttl)
            .await?;
        compensator.on_fail_delete(keys.token_id_mapping(token));

        self.token_repo
            .save_token_info_typed(login_type, token_info)
            .await?;
        compensator.on_fail_delete(keys.token_info_with_type(login_type, token));

        if self.config.right_now_create_token_session {
            self.session_repo
                .create_token_session_with_ttl_typed(login_type, &token_info.token, login_ttl)
                .await?;
            compensator.on_fail_delete(keys.token_session_with_type(login_type, token));
        }

        if let Some(mgr) = refresh_mgr
            && let Some(ref rt) = token_info.refresh_token
        {
            mgr.store_with_extra(
                rt,
                token,
                login_type,
                login_id,
                token_info.extra_data.as_ref(),
            )
            .await?;
            compensator.on_fail_delete(keys.refresh(rt));
        }

        self.commit_login_mapping(
            login_type,
            login_id,
            token,
            mapping_before,
            login_ttl,
            compensator,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_login_stages_java(
        &self,
        login_type: &str,
        login_id: &str,
        ns: &AccountNs,
        req: &LoginRequest,
        token_info: &TokenInfo,
        refresh_mgr: Option<&RefreshTokenManager>,
        compensator: &mut LoginCompensator,
    ) -> SaTokenResult<()> {
        let token = token_info.token.as_str();
        let keys = self.dao.keys();
        let login_ttl = self.token_repo.ttl_for(token_info);

        let session_key = keys
            .session_by_ns(ns)
            .map_err(|e| SaTokenError::ConfigError(e.to_string()))?;
        match self.session_repo.snapshot_account_session(ns).await? {
            Some(old_raw) => {
                let remaining = self.dao.ttl(&session_key).await?;
                compensator.on_fail_restore(session_key.clone(), old_raw, remaining);
            }
            None => compensator.on_fail_delete(session_key.clone()),
        }
        if !self.dao.exists(&session_key).await? {
            let empty = self.session_repo.new_account_session(ns)?;
            self.session_repo
                .save_by_ns_with_ttl(ns, &empty, login_ttl)
                .await?;
        }
        self.session_repo.update_min_timeout(ns, login_ttl).await?;

        let mut terminal = SaTerminalInfo::new(token, self.login_device(req).unwrap_or(""));
        if let Some(extra) = req.extra_data.clone() {
            terminal = terminal.with_extra_data(extra);
        }
        self.session_repo
            .add_terminal_with_ttl(ns, terminal, login_ttl)
            .await?;

        self.token_repo
            .save_token_info_typed(login_type, token_info)
            .await?;
        compensator.on_fail_delete(keys.token_info_with_type(login_type, token));
        if self.token_repo_last_active_enabled() {
            compensator.on_fail_delete(keys.last_active_with_type(login_type, token));
        }

        if self.config.right_now_create_token_session {
            self.session_repo
                .create_token_session_with_ttl_typed(login_type, &token_info.token, login_ttl)
                .await?;
            compensator.on_fail_delete(keys.token_session_with_type(login_type, token));
        }

        if let Some(mgr) = refresh_mgr
            && let Some(ref rt) = token_info.refresh_token
        {
            mgr.store_with_extra(
                rt,
                token,
                login_type,
                login_id,
                token_info.extra_data.as_ref(),
            )
            .await?;
            compensator.on_fail_delete(keys.refresh(rt));
        }

        Ok(())
    }

    /// Mixin：写 Account-Session + terminal，可选 last-active / token-session，不写 token key。
    async fn write_login_stages_mixin(
        &self,
        login_type: &str,
        ns: &AccountNs,
        req: &LoginRequest,
        token_info: &TokenInfo,
        compensator: &mut LoginCompensator,
    ) -> SaTokenResult<()> {
        let token = token_info.token.as_str();
        let keys = self.dao.keys();
        let login_ttl = self.token_repo.ttl_for(token_info);

        let session_key = keys
            .session_by_ns(ns)
            .map_err(|e| SaTokenError::ConfigError(e.to_string()))?;
        match self.session_repo.snapshot_account_session(ns).await? {
            Some(old_raw) => {
                let remaining = self.dao.ttl(&session_key).await?;
                compensator.on_fail_restore(session_key.clone(), old_raw, remaining);
            }
            None => compensator.on_fail_delete(session_key.clone()),
        }
        if !self.dao.exists(&session_key).await? {
            let empty = self.session_repo.new_account_session(ns)?;
            self.session_repo
                .save_by_ns_with_ttl(ns, &empty, login_ttl)
                .await?;
        }
        self.session_repo.update_min_timeout(ns, login_ttl).await?;

        let mut terminal = SaTerminalInfo::new(token, self.login_device(req).unwrap_or(""));
        if let Some(extra) = req.extra_data.clone() {
            terminal = terminal.with_extra_data(extra);
        }
        self.session_repo
            .add_terminal_with_ttl(ns, terminal, login_ttl)
            .await?;

        if self.token_repo_last_active_enabled() {
            let la_key = keys.last_active_with_type(login_type, token);
            let value = self.encode_last_active_value(token_info);
            self.dao.set_string(&la_key, &value, login_ttl).await?;
            compensator.on_fail_delete(la_key);
        }

        if self.config.right_now_create_token_session {
            let ts_ttl = self.mixin_token_session_ttl(login_type, &token_info.token)?;
            self.session_repo
                .create_token_session_with_ttl_typed(login_type, &token_info.token, ts_ttl)
                .await?;
            compensator.on_fail_delete(keys.token_session_with_type(login_type, token));
        }

        Ok(())
    }

    fn encode_last_active_value(&self, info: &TokenInfo) -> String {
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

    fn parse_last_active_value(raw: &str) -> Option<(DateTime<Utc>, Option<i64>)> {
        let (ms_raw, dyn_secs) = match raw.split_once(',') {
            Some((ms, secs)) => (ms, secs.parse::<i64>().ok()),
            None => (raw, None),
        };
        let ms = ms_raw.parse::<i64>().ok()?;
        let at = DateTime::from_timestamp_millis(ms)?;
        Some((at, dyn_secs))
    }

    /// Token-Session TTL from JWT `eff` (`-1` / missing → permanent).
    fn mixin_token_session_ttl(
        &self,
        login_type: &str,
        token: &TokenValue,
    ) -> SaTokenResult<Option<Duration>> {
        let info = self.token_info_from_jwt(login_type, token)?;
        Ok(Self::ttl_from_expire_ms(info.expire_time))
    }

    fn ttl_from_expire_ms(expire: Option<DateTime<Utc>>) -> Option<Duration> {
        let exp = expire?;
        let ms = exp.signed_duration_since(Utc::now()).num_milliseconds();
        if ms <= 0 {
            Some(Duration::ZERO)
        } else {
            Some(Duration::from_millis(ms as u64))
        }
    }

    fn token_repo_last_active_enabled(&self) -> bool {
        self.config.wire.last_active == LastActiveStore::SeparateKey
            && (self.config.active_timeout != -1 || self.config.dynamic_active_timeout)
    }

    async fn commit_login_mapping(
        &self,
        login_type: &str,
        login_id: &str,
        token: &str,
        mapping_before: Option<&str>,
        ttl: Option<Duration>,
        compensator: &mut LoginCompensator,
    ) -> SaTokenResult<()> {
        let key = self.dao.keys().login_token(login_type, login_id);

        if self.config.is_concurrent {
            self.token_repo
                .save_login_mapping_with_ttl(login_type, login_id, token, ttl)
                .await?;
        } else {
            let swapped = self
                .token_repo
                .cas_login_mapping_with_ttl(login_type, login_id, mapping_before, token, ttl)
                .await?;
            if !swapped {
                let swapped_absent = self
                    .token_repo
                    .cas_login_mapping_with_ttl(login_type, login_id, None, token, ttl)
                    .await?;
                if !swapped_absent {
                    tracing::warn!(
                        login_id = %login_id,
                        login_type = %login_type,
                        "concurrent login detected on commit point, rolling back this attempt"
                    );
                    return Err(SaTokenError::AccountReplaced);
                }
            }
        }

        compensator.on_fail_delete(key);
        Ok(())
    }

    async fn handle_replaced_on_login(
        &self,
        login_type: &str,
        login_id: &str,
        ns: &AccountNs,
        req: &LoginRequest,
        new_token: &str,
    ) -> SaTokenResult<()> {
        let device = self.login_device(req);
        let effective_range = match (self.config.replaced_range, device) {
            (ReplacedRange::CurrDeviceType, None) => {
                tracing::debug!(
                    login_id = %login_id,
                    "device type absent, replaced_range degraded to AllDeviceType"
                );
                ReplacedRange::AllDeviceType
            }
            (range, _) => range,
        };

        let mut targets: HashSet<String> = HashSet::new();

        match effective_range {
            ReplacedRange::CurrDeviceType => {
                // 仅收集同设备类型终端；不把 login:token 映射一律纳入，
                // 否则异端登录仍会顶掉其它设备（违背 CurrDeviceType）。
                for t in self.session_repo.get_terminal_list(ns, device).await? {
                    targets.insert(t.token_value);
                }
            }
            ReplacedRange::AllDeviceType => {
                if self.uses_session_terminals() {
                    for t in self.session_repo.get_token_list(ns, None).await? {
                        targets.insert(t);
                    }
                } else {
                    for t in self.token_repo.list_tokens(login_type, login_id).await? {
                        targets.insert(t);
                    }
                    if let Some(old) = self
                        .token_repo
                        .get_login_mapping(login_type, login_id)
                        .await?
                    {
                        targets.insert(old);
                    }
                }
            }
        }

        targets.remove(new_token);

        if targets.is_empty() {
            return Ok(());
        }

        match self.config.replaced_login_exit_mode {
            ReplacedLoginExitMode::NewDevice => Err(SaTokenError::AccountReplaced),
            ReplacedLoginExitMode::OldDevice => {
                for t in targets {
                    if let Err(e) = self.logout_replaced(&TokenValue::new(t.clone())).await {
                        tracing::warn!(token = %t, error = %e, "replace of stale token failed");
                    }
                }
                Ok(())
            }
        }
    }

    /// 登出（LOGOUT 模式）| Logout
    pub async fn logout(&self, token: &TokenValue, keep_token_session: bool) -> SaTokenResult<()> {
        if self.is_jwt_stateless() || self.is_jwt_mixin() {
            return Ok(());
        }
        let result = match self.config.logout_range {
            LogoutRange::Token => {
                self.logout_internal(token, LogoutMode::Logout, keep_token_session)
                    .await
            }
            LogoutRange::Account => match self
                .resolve_logout_identity(LOGIN_TYPE_DEFAULT, token.as_str())
                .await?
            {
                Some(id) => self.logout_by_login_id(&id.login_type, &id.login_id).await,
                None => {
                    self.logout_internal(token, LogoutMode::Logout, keep_token_session)
                        .await
                }
            },
        };
        if result.is_ok() && self.config.is_log {
            tracing::info!(token = %token.as_str(), "logout success");
        }
        result
    }

    /// 踢下线（KICKOUT 模式，标记 -5）| Kick out, marker `-5`
    pub async fn kick_out_by_token(
        &self,
        token: &TokenValue,
        keep_token_session: bool,
    ) -> SaTokenResult<()> {
        self.reject_jwt_disabled_api()?;
        self.logout_internal(token, LogoutMode::KickOut, keep_token_session)
            .await
    }

    /// 顶下线（REPLACED 模式，标记 -4）| Replace, marker `-4`
    pub async fn logout_replaced(&self, token: &TokenValue) -> SaTokenResult<()> {
        self.reject_jwt_disabled_api()?;
        self.logout_internal(
            token,
            LogoutMode::Replaced,
            self.config.is_logout_keep_token_session,
        )
        .await
    }

    async fn resolve_logout_identity(
        &self,
        login_type: &str,
        token: &str,
    ) -> SaTokenResult<Option<LogoutIdentity>> {
        if let Some(info) = self
            .token_repo
            .get_token_info_typed(login_type, token)
            .await?
        {
            return Ok(Some(LogoutIdentity {
                login_type: info.login_type.to_string(),
                login_id: info.login_id.to_string(),
                _body_existed: true,
            }));
        }

        match self.token_repo.get_token_id_mapping(token).await? {
            Some(TokenIdMapping::Identity {
                login_type,
                login_id,
            }) => Ok(Some(LogoutIdentity {
                login_type,
                login_id,
                _body_existed: false,
            })),
            _ => Ok(None),
        }
    }

    async fn logout_internal(
        &self,
        token: &TokenValue,
        mode: LogoutMode,
        keep_token_session: bool,
    ) -> SaTokenResult<()> {
        let token_str = token.as_str();
        tracing::debug!(mode = ?mode, token = %token_str, "logout_internal");

        let identity = self
            .resolve_logout_identity(LOGIN_TYPE_DEFAULT, token_str)
            .await?;
        let retire_lt = identity
            .as_ref()
            .map(|id| id.login_type.as_str())
            .unwrap_or(LOGIN_TYPE_DEFAULT);

        self.token_repo
            .retire(retire_lt, token_str, mode, keep_token_session)
            .await?;

        let Some(identity) = identity else {
            tracing::debug!(token = %token_str, "logout target has no resolvable identity, skipping account-level cleanup");
            return Ok(());
        };

        let lt = identity.login_type.as_str();
        let lid = identity.login_id.as_str();

        if let Err(e) = self.token_repo.remove_index(lt, lid, token_str).await {
            tracing::warn!(token = %token_str, error = %e, "failed to remove token from login index");
        }

        if let Ok(ns) = self.account_ns(lt, lid) {
            let removed = self
                .session_repo
                .remove_terminal(&ns, token_str)
                .await
                .unwrap_or(false);

            if removed {
                let count = self.session_repo.terminal_count(&ns).await.unwrap_or(0);
                if count == 0 && mode != LogoutMode::Replaced {
                    let _ = self.session_repo.delete_by_ns(&ns).await;
                }
            }
        }

        if mode == LogoutMode::Logout {
            let _ = self
                .token_repo
                .cas_delete_login_mapping(lt, lid, token_str)
                .await;
        }

        if let Some(dm) = &self.distributed {
            if let Err(e) = dm.delete_sessions_by_token(lid, token_str).await {
                tracing::warn!(error = %e, "distributed session delete failed on logout");
            }
        }

        if let Some(online) = &self.online_manager {
            if let Err(e) = online.mark_offline_with_type(lt, lid, token_str).await {
                tracing::warn!(error = %e, "failed to clear online presence on logout");
            }
        }

        let event = match mode {
            LogoutMode::Logout => SaTokenEvent::logout(lid, token_str),
            LogoutMode::KickOut => SaTokenEvent::kick_out(lid, token_str),
            LogoutMode::Replaced => SaTokenEvent::replaced(lid, token_str),
        };
        self.event_bus.publish(event.with_login_type(lt)).await;

        Ok(())
    }

    async fn collect_account_tokens(
        &self,
        login_type: &str,
        login_id: &str,
    ) -> SaTokenResult<Vec<String>> {
        if self.uses_session_terminals() {
            let ns = self.account_ns(login_type, login_id)?;
            return self.session_repo.get_token_list(&ns, None).await;
        }
        let (alive, pruned) = self.token_repo.prune_index(login_type, login_id).await?;
        if pruned > 0 {
            tracing::debug!(pruned, login_id = %login_id, "pruned orphan index entries");
        }
        if !alive.is_empty() {
            return Ok(alive);
        }

        let mut result = Vec::new();
        let keys = self.dao.keys();
        let pattern = keys.token_scan_pattern(Some(login_type));
        let mut cursor = 0u64;

        loop {
            let page = match self.dao.scan(&pattern, cursor, 100).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(error = %e, "scan fallback unavailable");
                    break;
                }
            };

            for key in &page.keys {
                let Some(token) = keys.parse_token_from_key(key, Some(login_type)) else {
                    continue;
                };
                if let Ok(Some(info)) = self
                    .token_repo
                    .get_token_info_typed(login_type, token)
                    .await
                    && info.login_id.as_ref() == login_id
                    && info.login_type.as_ref() == login_type
                {
                    result.push(token.to_string());
                }
            }

            if page.next_cursor == 0 {
                break;
            }
            cursor = page.next_cursor;
        }

        if result.is_empty()
            && let Some(one) = self
                .token_repo
                .get_login_mapping(login_type, login_id)
                .await?
        {
            result.push(one);
        }

        Ok(result)
    }

    /// 按账号登出全部 token（LOGOUT 模式）。
    ///
    /// Always uses per-token [`logout_internal`] so `logout_range=Account` cannot recurse.
    /// 始终按单 token 调用 [`logout_internal`]，避免 `logout_range=Account` 时递归。
    pub async fn logout_by_login_id(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        self.reject_jwt_disabled_api()?;
        let tokens = self.collect_account_tokens(login_type, login_id).await?;
        let keep = self.config.is_logout_keep_token_session;
        for t in tokens {
            if let Err(e) = self
                .logout_internal(&TokenValue::new(t.clone()), LogoutMode::Logout, keep)
                .await
            {
                tracing::warn!(token = %t, error = %e, "logout of one token failed during account logout");
            }
        }
        Ok(())
    }

    /// 按账号踢下线全部 token（KICKOUT 模式）。
    pub async fn kick_out(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        self.reject_jwt_disabled_api()?;
        if let Some(online) = &self.online_manager {
            let _ = online
                .mark_offline_all_with_type(login_type, login_id)
                .await;
            let _ = online
                .kick_out_notify(login_id, "Account kicked out".to_string())
                .await;
        }

        let tokens = self.collect_account_tokens(login_type, login_id).await?;
        for t in tokens {
            if let Err(e) = self
                .kick_out_by_token(
                    &TokenValue::new(t.clone()),
                    self.config.is_logout_keep_token_session,
                )
                .await
            {
                tracing::warn!(token = %t, error = %e, "kickout of one token failed");
            }
        }

        if let Ok(ns) = self.account_ns(login_type, login_id) {
            let _ = self.session_repo.delete_by_ns(&ns).await;
        }
        Ok(())
    }

    /// 按账号顶下线全部 token（REPLACED 模式）。不发 kick_out_notify。
    /// Replace every token of an account (`LogoutMode::Replaced`). No kick-out notify.
    pub async fn replaced(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        self.reject_jwt_disabled_api()?;
        if let Some(online) = &self.online_manager {
            let _ = online
                .mark_offline_all_with_type(login_type, login_id)
                .await;
        }

        let tokens = self.collect_account_tokens(login_type, login_id).await?;
        for t in tokens {
            if let Err(e) = self.logout_replaced(&TokenValue::new(t.clone())).await {
                tracing::warn!(token = %t, error = %e, "replaced of one token failed");
            }
        }

        if let Ok(ns) = self.account_ns(login_type, login_id) {
            let _ = self.session_repo.delete_by_ns(&ns).await;
        }
        Ok(())
    }

    /// 读取并校验 token（按策略自动续签）。
    pub async fn get_token_info(&self, token: &TokenValue) -> SaTokenResult<TokenInfo> {
        self.get_token_info_typed(LOGIN_TYPE_DEFAULT, token).await
    }

    /// Read and validate a token under an explicit login type.
    /// 按指定 login_type 读取并校验 token。
    pub async fn get_token_info_typed(
        &self,
        login_type: &str,
        token: &TokenValue,
    ) -> SaTokenResult<TokenInfo> {
        if self.is_jwt_stateless() {
            return self.token_info_from_jwt(login_type, token);
        }
        if self.is_jwt_mixin() {
            return self.get_token_info_jwt_mixin(login_type, token).await;
        }
        match self
            .token_repo
            .load_valid_token_info_typed(login_type, token)
            .await
        {
            Ok(info) => Ok(info),
            Err(SaTokenError::TokenExpired) => {
                let _ = self
                    .logout(token, self.config.is_logout_keep_token_session)
                    .await;
                Err(SaTokenError::TokenExpired)
            }
            Err(other) => Err(other),
        }
    }

    /// Mixin：验签 JWT + Account-Session terminalList 含该 JWT，不读 token key。
    async fn get_token_info_jwt_mixin(
        &self,
        login_type: &str,
        token: &TokenValue,
    ) -> SaTokenResult<TokenInfo> {
        let mut info = self.token_info_from_jwt(login_type, token)?;
        let ns = self.account_ns(info.login_type.as_ref(), info.login_id.as_ref())?;
        if self
            .session_repo
            .get_terminal(&ns, token.as_str())
            .await?
            .is_none()
        {
            return Err(SaTokenError::TokenNotFound);
        }

        if self.token_repo_last_active_enabled() {
            let la_key = self
                .dao
                .keys()
                .last_active_with_type(login_type, token.as_str());
            match self.dao.get_string(&la_key).await? {
                Some(raw) => {
                    if let Some((at, dyn_secs)) = Self::parse_last_active_value(&raw) {
                        info.last_active_time = at;
                        if let Some(secs) = dyn_secs {
                            info.active_timeout_override = Some(secs);
                        }
                    }
                }
                None => return Err(SaTokenError::TokenInactive),
            }
            if info.is_freeze(info.effective_active_timeout(&self.config)) {
                return Err(SaTokenError::TokenInactive);
            }
            if self.config.active_refresh {
                info = self
                    .token_repo
                    .apply_active_refresh_typed(login_type, token.as_str(), info)
                    .await?;
            }
        }

        Ok(info)
    }

    /// token 是否有效 | Whether the token is valid
    pub async fn is_valid(&self, token: &TokenValue) -> bool {
        self.is_valid_typed(LOGIN_TYPE_DEFAULT, token).await
    }

    /// Whether the token is valid under an explicit login type.
    /// 按指定 login_type 判断 token 是否有效。
    pub async fn is_valid_typed(&self, login_type: &str, token: &TokenValue) -> bool {
        self.get_token_info_typed(login_type, token).await.is_ok()
    }

    /// 手动续期到指定秒数（token 体、映射、Token-Session、账号 Session）。
    /// Renew to an explicit lifetime: body, mapping, token-session, account session.
    pub async fn renew_timeout(
        &self,
        token: &TokenValue,
        timeout_seconds: i64,
    ) -> SaTokenResult<()> {
        self.reject_jwt_disabled_api()?;
        let mut info = self
            .token_repo
            .load_token_info_no_renew_typed(LOGIN_TYPE_DEFAULT, token)
            .await?;
        let login_type = info.login_type.to_string();

        info.update_active_time();
        let ttl = if timeout_seconds > 0 {
            info.expire_time = Some(Utc::now() + ChronoDuration::seconds(timeout_seconds));
            Some(Duration::from_secs(timeout_seconds as u64))
        } else {
            info.expire_time = None;
            None
        };

        self.token_repo
            .save_token_info_typed(&login_type, &info)
            .await?;

        let map_key = self.dao.keys().token_id_mapping(token.as_str());
        self.write_key_ttl(&map_key, ttl).await?;

        let ts_key = self
            .session_repo
            .token_session_key_typed(&login_type, token.as_str());
        if self.dao.exists(&ts_key).await? {
            self.write_key_ttl(&ts_key, ttl).await?;
        }

        if let Ok(ns) = self.account_ns(info.login_type.as_ref(), info.login_id.as_ref()) {
            self.session_repo.update_min_timeout(&ns, ttl).await?;
        }

        let event =
            SaTokenEvent::renew_timeout(info.login_id.as_ref(), token.as_str(), timeout_seconds)
                .with_login_type(info.login_type.as_ref());
        self.event_bus.publish(event).await;

        Ok(())
    }

    /// Set remaining TTL on a scalar key; `None` rewrites as permanent.
    /// 写入标量键剩余 TTL；`None` 改写为永久。
    async fn write_key_ttl(&self, key: &str, ttl: Option<Duration>) -> SaTokenResult<()> {
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

    async fn enforce_max_login_count(&self, login_type: &str, login_id: &str) -> SaTokenResult<()> {
        if self.config.max_login_count <= 0 || !self.config.is_concurrent {
            return Ok(());
        }

        let alive = if self.uses_session_terminals() || self.is_jwt_mixin() {
            let ns = self.account_ns(login_type, login_id)?;
            self.session_repo.get_token_list(&ns, None).await?
        } else {
            let (alive, pruned) = self.token_repo.prune_index(login_type, login_id).await?;
            if pruned > 0 {
                tracing::debug!(
                    pruned,
                    login_id = %login_id,
                    "pruned orphan tokens before enforcing max_login_count"
                );
            }
            alive
        };

        let max = self.config.max_login_count as usize;
        if alive.len() <= max {
            return Ok(());
        }
        let overflow = alive.len() - max;

        if self.is_jwt_mixin() {
            let ns = self.account_ns(login_type, login_id)?;
            let keep = self.config.is_logout_keep_token_session;
            for stale in alive.iter().take(overflow) {
                let _ = self.session_repo.remove_terminal(&ns, stale).await;
                if self.token_repo_last_active_enabled() {
                    let _ = self
                        .dao
                        .delete(&self.dao.keys().last_active_with_type(login_type, stale))
                        .await;
                }
                if !keep {
                    let _ = self
                        .session_repo
                        .delete_token_session_typed(login_type, &TokenValue::new(stale.clone()))
                        .await;
                }
            }
            return Ok(());
        }

        for stale in alive.iter().take(overflow) {
            let _ = self
                .token_repo
                .remove_index(login_type, login_id, stale)
                .await;

            let token = TokenValue::new(stale.clone());
            let keep = self.config.is_logout_keep_token_session;
            let outcome = match self.config.overflow_logout_mode {
                LogoutMode::Logout => self.logout(&token, keep).await,
                LogoutMode::KickOut => self.kick_out_by_token(&token, keep).await,
                LogoutMode::Replaced => self.logout_replaced(&token).await,
            };
            if let Err(e) = outcome {
                tracing::warn!(token = %stale, error = %e, "overflow eviction failed");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SaTokenManager;
    use crate::compat::{
        AccountIndex, LastActiveStore, SessionFormat, TokenValueFormat, WireConfig,
    };
    use crate::keys::SaKeyLayout;
    use sa_token_storage_memory::MemoryStorage;

    fn mixed_java_cfg(active_timeout: i64) -> SaTokenConfig {
        let mut wire = WireConfig::native();
        wire.token_value = TokenValueFormat::LoginId;
        wire.last_active = LastActiveStore::SeparateKey;
        wire.account_index = AccountIndex::SessionTerminals;
        wire.session_format = SessionFormat::Serde;
        wire.default_login_type = "login".into();
        wire.default_device_type = Some("DEF".into());
        wire.allow_login_id_colon = false;
        SaTokenConfig {
            token_name: "satoken".into(),
            key_layout: SaKeyLayout::JavaFourSegment,
            wire,
            timeout: 3600,
            active_timeout,
            auto_renew: false,
            active_refresh: true,
            max_login_count: 12,
            token_style: TokenStyle::Uuid,
            is_concurrent: true,
            is_share: false,
            ..Default::default()
        }
    }

    fn mgr(active_timeout: i64) -> SaTokenManager {
        SaTokenManager::new(
            Arc::new(MemoryStorage::new()),
            mixed_java_cfg(active_timeout),
        )
    }

    #[tokio::test]
    async fn java_login_writes_login_id_last_active_and_terminals() {
        let mgr = mgr(1800);
        let token = mgr.login("10001").await.expect("login");
        let dao = mgr.dao();
        let keys = dao.keys();

        let token_key = keys.token_info_with_type("login", token.as_str());
        let raw = dao.get_string(&token_key).await.unwrap().unwrap();
        assert_eq!(raw, "10001");

        let la_key = keys.last_active_with_type("login", token.as_str());
        let la = dao.get_string(&la_key).await.unwrap().unwrap();
        assert_eq!(la.len(), 13);
        assert!(la.chars().all(|c| c.is_ascii_digit()));

        assert!(
            dao.get_string(&keys.login_token("login", "10001"))
                .await
                .unwrap()
                .is_none()
        );
        let index = dao
            .list_range(&keys.login_token_index("login", "10001"), 0, None)
            .await
            .unwrap();
        assert!(index.is_empty());

        let session = mgr
            .get_session_with_type("login", "10001")
            .await
            .expect("session");
        assert_eq!(session.session_type, "Account-Session");
        assert_eq!(session.terminal_list.len(), 1);
        assert_eq!(session.terminal_list[0].token_value, token.as_str());
        assert_eq!(session.terminal_list[0].device_type, "DEF");
        assert_eq!(session.id, keys.account_session("login", "10001"));
    }

    #[tokio::test]
    async fn java_kickout_keeps_token_key_as_minus_five() {
        let mgr = mgr(-1);
        let token = mgr.login("10001").await.expect("login");
        mgr.kick_out("login", "10001").await.expect("kick");

        let token_key = mgr.keys().token_info_with_type("login", token.as_str());
        assert!(mgr.dao().exists(&token_key).await.unwrap());
        let raw = mgr.dao().get_string(&token_key).await.unwrap().unwrap();
        assert_eq!(raw, "-5");

        let err = mgr.get_token_info_typed("login", &token).await.unwrap_err();
        assert!(matches!(err, SaTokenError::AccountKickedOut));
    }

    #[tokio::test]
    async fn java_missing_last_active_is_inactive() {
        let mgr = mgr(1800);
        let token = mgr.login("10001").await.expect("login");
        let la_key = mgr.keys().last_active_with_type("login", token.as_str());
        mgr.dao().delete(&la_key).await.unwrap();

        let err = mgr.get_token_info_typed("login", &token).await.unwrap_err();
        assert!(matches!(err, SaTokenError::TokenInactive));
    }

    #[tokio::test]
    async fn java_login_rejects_reserved_marker() {
        let mgr = mgr(-1);
        let err = mgr.login("-5").await.unwrap_err();
        assert!(matches!(err, SaTokenError::ConfigError(_)));
    }

    #[tokio::test]
    async fn java_is_share_reuses_same_device_token() {
        let mut cfg = mixed_java_cfg(-1);
        cfg.is_share = true;
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), cfg);
        let t1 = mgr.login("10001").await.unwrap();
        let t2 = mgr.login("10001").await.unwrap();
        assert_eq!(t1.as_str(), t2.as_str());
        let session = mgr.get_session_with_type("login", "10001").await.unwrap();
        assert_eq!(session.terminal_list.len(), 1);
    }

    fn mixin_java_cfg() -> SaTokenConfig {
        let mut cfg = SaTokenConfig::java_compatible();
        cfg.token_style = TokenStyle::JwtMixin;
        cfg.jwt_secret_key = Some("java-interop-secret-key-32bytes!!".into());
        cfg.timeout = -1;
        cfg.active_timeout = -1;
        cfg
    }

    fn mixin_mgr() -> SaTokenManager {
        SaTokenManager::new(Arc::new(MemoryStorage::new()), mixin_java_cfg())
    }

    #[tokio::test]
    async fn jwt_mixin_login_writes_session_not_token_key() {
        let mgr = mixin_mgr();
        let token = mgr.login("10001").await.expect("login");
        assert_eq!(token.as_str().matches('.').count(), 2);

        let dao = mgr.dao();
        let keys = dao.keys();
        let token_key = keys.token_info_with_type("login", token.as_str());
        assert!(
            dao.get_string(&token_key).await.unwrap().is_none(),
            "Mixin must not write satoken:login:token:{{jwt}}"
        );
        let la_key = keys.last_active_with_type("login", token.as_str());
        assert!(
            dao.get_string(&la_key).await.unwrap().is_none(),
            "timeout=-1 and activeTimeout=-1 must not write last-active"
        );

        let session = mgr
            .get_session_with_type("login", "10001")
            .await
            .expect("session");
        assert_eq!(session.session_type, "Account-Session");
        assert_eq!(session.terminal_list.len(), 1);
        assert_eq!(session.terminal_list[0].token_value, token.as_str());
        assert_eq!(session.terminal_list[0].device_type, "DEF");
    }

    #[tokio::test]
    async fn jwt_mixin_get_token_info_parses_login_id_from_jwt() {
        let mgr = mixin_mgr();
        let token = mgr.login("10001").await.expect("login");
        assert!(mgr.is_valid(&token).await);
        let info = mgr.get_token_info(&token).await.expect("info");
        assert_eq!(info.login_id.as_ref(), "10001");
        let typed = mgr
            .get_token_info_typed("login", &token)
            .await
            .expect("typed");
        assert_eq!(typed.login_id.as_ref(), "10001");
    }

    #[tokio::test]
    async fn jwt_mixin_kick_logout_by_login_id_renew_are_disabled() {
        let mgr = mixin_mgr();
        let token = mgr.login("10001").await.expect("login");

        let kick = mgr.kick_out("login", "10001").await.unwrap_err();
        assert!(matches!(kick, SaTokenError::ApiDisabled(ref s) if s == "jwt-mixin"));

        let by_id = mgr.logout_by_login_id("login", "10001").await.unwrap_err();
        assert!(matches!(by_id, SaTokenError::ApiDisabled(ref s) if s == "jwt-mixin"));

        let replaced = mgr.replaced("login", "10001").await.unwrap_err();
        assert!(matches!(replaced, SaTokenError::ApiDisabled(ref s) if s == "jwt-mixin"));

        let renew = mgr.renew_timeout(&token, 3600).await.unwrap_err();
        assert!(matches!(renew, SaTokenError::ApiDisabled(ref s) if s == "jwt-mixin"));

        let by_token = mgr.kick_out_by_token(&token).await.unwrap_err();
        assert!(matches!(by_token, SaTokenError::ApiDisabled(ref s) if s == "jwt-mixin"));

        assert!(mgr.is_valid(&token).await);
        let session = mgr.get_session_with_type("login", "10001").await.unwrap();
        assert_eq!(session.terminal_list.len(), 1);
    }

    #[tokio::test]
    async fn jwt_mixin_logout_does_not_touch_storage() {
        let mgr = mixin_mgr();
        let token = mgr.login("10001").await.expect("login");
        mgr.logout(&token).await.expect("logout");
        assert!(mgr.is_valid(&token).await);
        let session = mgr.get_session_with_type("login", "10001").await.unwrap();
        assert_eq!(session.terminal_list.len(), 1);
        assert_eq!(session.terminal_list[0].token_value, token.as_str());
    }

    #[tokio::test]
    async fn jwt_mixin_invalid_without_terminal() {
        let mgr = mixin_mgr();
        let token = mgr.login("10001").await.expect("login");
        let ns = mgr.account_ns("login", "10001");
        mgr.session_repo()
            .remove_terminal(&ns, token.as_str())
            .await
            .unwrap();
        let err = mgr.get_token_info(&token).await.unwrap_err();
        assert!(matches!(err, SaTokenError::TokenNotFound));
    }

    #[tokio::test]
    async fn jwt_mixin_writes_last_active_when_active_timeout_on() {
        let mut cfg = mixin_java_cfg();
        cfg.active_timeout = 1800;
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), cfg);
        let token = mgr.login("10001").await.expect("login");
        let dao = mgr.dao();
        let keys = dao.keys();
        assert!(
            dao.get_string(&keys.token_info_with_type("login", token.as_str()))
                .await
                .unwrap()
                .is_none()
        );
        let la = dao
            .get_string(&keys.last_active_with_type("login", token.as_str()))
            .await
            .unwrap()
            .expect("last-active");
        assert_eq!(la.len(), 13);
        assert!(la.chars().all(|c| c.is_ascii_digit()));
        assert!(mgr.is_valid(&token).await);
    }
}
