//! 与 Java sa-token v1.46.0 会话行为逐项对齐的测试。
//! 过期/冻结用灰盒拨钟，禁止 sleep。

mod common;

use std::collections::HashMap;

use common::setup;
use sa_token_adapter::context::{CookieOptions, SaRequest, SaResponse};
use sa_token_core::{
    LogoutMode, SaTokenConfig, SaTokenContext, StpUtil, apply_token_prefix, config::TokenStyle,
    delete_token_cookie, read_token, write_token_cookie_with_max_age,
};
use serial_test::serial;

fn init_stp() {
    let _mgr = setup::shared_manager();
}

// ── 最小 SaRequest / SaResponse mock（HashMap）────────────────────────────

struct MockRequest {
    headers: HashMap<String, String>,
    cookies: HashMap<String, String>,
}

impl MockRequest {
    fn new() -> Self {
        Self {
            headers: HashMap::new(),
            cookies: HashMap::new(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    fn with_cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.insert(name.to_string(), value.to_string());
        self
    }
}

impl SaRequest for MockRequest {
    fn get_header(&self, name: &str) -> Option<String> {
        self.headers.get(name).cloned()
    }

    fn get_cookie(&self, name: &str) -> Option<String> {
        self.cookies.get(name).cloned()
    }

    fn get_param(&self, _name: &str) -> Option<String> {
        None
    }

    fn get_path(&self) -> String {
        "/".to_string()
    }

    fn get_method(&self) -> String {
        "GET".to_string()
    }
}

struct MockResponse {
    cookies: Vec<(String, String, CookieOptions)>,
}

impl MockResponse {
    fn new() -> Self {
        Self {
            cookies: Vec::new(),
        }
    }
}

impl SaResponse for MockResponse {
    fn set_header(&mut self, _name: &str, _value: &str) {}

    fn set_cookie(&mut self, name: &str, value: &str, options: CookieOptions) {
        self.cookies
            .push((name.to_string(), value.to_string(), options));
    }

    fn set_status(&mut self, _status: u16) {}

    fn set_json_body<T>(&mut self, _body: T) -> Result<(), serde_json::Error> {
        Ok(())
    }
}

// ── Uuid token 走存储映射 ─────────────────────────────────────────────────

/// `TokenStyle::Uuid` 登录后 token 不含 JWT 的两个 `.`；
/// `get_token_info` 经存储中的 token→loginId 映射解析
/// （对应 Java `StpLogic#getLoginIdNotHandle` L1302 的 Dao 读取）。
#[tokio::test]
async fn uuid_token_uses_storage_mapping_get_login_id_not_handle_l1302() {
    let config = SaTokenConfig::builder()
        .token_style(TokenStyle::Uuid)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let id = setup::unique_login_id("jp_uuid");
    let token = mgr.login(&id).await.expect("login");
    assert!(
        !token.as_str().contains('.'),
        "Uuid 风格不生成 JWT，token 不应含 JWT 的 '.'，got {}",
        token.as_str()
    );
    assert_ne!(
        token.as_str().matches('.').count(),
        2,
        "token must not look like header.payload.signature"
    );
    let info = mgr.get_token_info(&token).await.expect("storage mapping");
    assert_eq!(info.login_id.as_ref(), id);
}

// ── token 读取与前缀 ──────────────────────────────────────────────────────

/// `getTokenValueNotCut` L347 读裸值；`getTokenValue` L309 按 `token_prefix` 裁剪。
/// Header 有值但无前缀时不得回退 Cookie。
#[test]
fn read_token_strips_prefix_and_fills_cookie_get_token_value_l309_not_cut_l347() {
    let tok = "parity-read-token-value";

    // 1) Header `Authorization: Bearer <tok>`，`is_read_cookie=false` → 读出 tok
    let req_header = MockRequest::new().with_header("Authorization", &format!("Bearer {tok}"));
    let cfg_header = SaTokenConfig::builder()
        .token_prefix("Bearer")
        .is_read_cookie(false)
        .is_read_header(true)
        .build_config();
    assert_eq!(read_token(&req_header, &cfg_header).as_deref(), Some(tok));
    assert_eq!(
        apply_token_prefix(&format!("Bearer {tok}"), Some("Bearer")).as_deref(),
        Some(tok)
    );

    // 2) Cookie 裸 tok + cookie_auto_fill_prefix + token_prefix=Bearer + 不读 header
    let req_cookie = MockRequest::new().with_cookie("sa-token", tok);
    let cfg_cookie = SaTokenConfig::builder()
        .cookie_auto_fill_prefix(true)
        .token_prefix("Bearer")
        .is_read_header(false)
        .is_read_cookie(true)
        .build_config();
    assert_eq!(read_token(&req_cookie, &cfg_cookie).as_deref(), Some(tok));

    // 3) Header 有值但无 Bearer 前缀时不回退 Cookie
    let req_no_fallback = MockRequest::new()
        .with_header("Authorization", "not-a-bearer")
        .with_cookie("sa-token", tok);
    let cfg_no_fallback = SaTokenConfig::builder()
        .cookie_auto_fill_prefix(true)
        .token_prefix("Bearer")
        .is_read_header(true)
        .is_read_cookie(true)
        .build_config();
    assert_eq!(
        read_token(&req_no_fallback, &cfg_no_fallback),
        None,
        "header without Bearer must not fall back to cookie"
    );
}

// ── 按次登录 timeout 与 Cookie Max-Age ────────────────────────────────────

/// `createLoginSession` L488 + `SaLoginParameter#getCookieTimeout`。
/// `login_with_timeout(id, 604800)` 剩余约 7 天；Cookie Max-Age 跟随本次 timeout。
#[tokio::test]
#[serial]
async fn login_with_timeout_sets_ttl_and_cookie_max_age_create_login_session_l488() {
    init_stp();
    let id = setup::unique_login_id("jp_login_to");
    let token = StpUtil::login_with_timeout(&id, 604800)
        .await
        .expect("login_with_timeout");
    let remaining = StpUtil::get_token_timeout(&token)
        .await
        .expect("get_token_timeout")
        .expect("timeout must be some");
    assert!(
        (604790..=604800).contains(&remaining),
        "expected ~7d remaining, got {remaining}"
    );

    let config = SaTokenConfig::builder()
        .is_write_cookie(true)
        .build_config();
    assert!(config.cookie.is_write_cookie);
    let mut res = MockResponse::new();
    write_token_cookie_with_max_age(&mut res, &token, &config, 604800);
    assert_eq!(res.cookies.len(), 1);
    assert_eq!(res.cookies[0].1, token.as_str());
    assert_eq!(res.cookies[0].2.max_age, Some(604800));
}

// ── 超出最大登录数淘汰最旧 ────────────────────────────────────────────────

/// `logoutByMaxLoginCount` L1066，overflowLogoutMode 默认 LOGOUT。
/// 索引按插入顺序，`alive.iter().take(overflow)` 淘汰最旧。
#[tokio::test]
async fn overflow_logout_evicts_oldest_logout_by_max_login_count_l1066() {
    let config = SaTokenConfig::builder()
        .max_login_count(3)
        .is_concurrent(true)
        .is_share(false)
        .overflow_logout_mode(LogoutMode::Logout)
        .timeout(3600)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let id = setup::unique_login_id("jp_overflow");
    let t1 = mgr.login(&id).await.expect("t1");
    let t2 = mgr.login(&id).await.expect("t2");
    let t3 = mgr.login(&id).await.expect("t3");
    let t4 = mgr.login(&id).await.expect("t4");
    setup::assert_err(mgr.get_token_info(&t1).await, "not_found");
    assert!(mgr.is_valid(&t2).await, "t2 must stay valid");
    assert!(mgr.is_valid(&t3).await, "t3 must stay valid");
    assert!(mgr.is_valid(&t4).await, "t4 must stay valid");
    mgr.get_token_info(&t2).await.expect("t2 info");
    mgr.get_token_info(&t3).await.expect("t3 info");
    mgr.get_token_info(&t4).await.expect("t4 info");
}

// ── 活跃刷新（KEEPTTL） ───────────────────────────────────────────────────

/// `getLoginId` L1126 → `checkActiveTimeoutByConfig` L1760 →
/// `updateLastActiveToNow` L1707。`active_refresh` 推进 last_active，不改 expire_time；
/// 同请求 scope 内只刷新一次。
#[tokio::test]
async fn active_refresh_keeps_expire_time_once_per_scope_check_active_timeout_l1760() {
    let config = SaTokenConfig::builder()
        .active_refresh(true)
        .auto_renew(false)
        .active_timeout(7200)
        .timeout(86400)
        .token_style(TokenStyle::Uuid)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let id = setup::unique_login_id("jp_active");
    let token = mgr.login(&id).await.expect("login");

    let baseline = mgr.get_token_info(&token).await.expect("baseline");
    let expire = baseline.expire_time;
    setup::freeze_active(&mgr, &token, 10).await;
    let refreshed = mgr.get_token_info(&token).await.expect("active_refresh");
    assert!(
        refreshed.last_active_time > baseline.last_active_time,
        "get_token_info must advance last_active"
    );
    assert_eq!(
        refreshed.expire_time, expire,
        "active_refresh must keep expire_time"
    );

    setup::freeze_active(&mgr, &token, 60).await;
    let ctx = SaTokenContext::builder()
        .token(token.clone())
        .login_id(id.clone())
        .build();
    SaTokenContext::scope(ctx, async {
        let first = mgr.get_token_info(&token).await.expect("scope first");
        let second = mgr.get_token_info(&token).await.expect("scope second");
        assert_eq!(
            second.last_active_time, first.last_active_time,
            "second get_token_info in the same scope must not advance last_active"
        );
    })
    .await;

    setup::freeze_active(&mgr, &token, 7201).await;
    setup::assert_err(mgr.get_token_info(&token).await, "inactive");
}

// ── 登出清 Cookie ─────────────────────────────────────────────────────────

/// `logout` L673 清 Cookie：value 为空、Max-Age=0（以增代删）。
#[test]
fn logout_deletes_cookie_with_max_age_zero_logout_l673() {
    let config = SaTokenConfig::builder()
        .is_write_cookie(true)
        .build_config();
    assert!(config.cookie.is_write_cookie);
    let mut res = MockResponse::new();
    delete_token_cookie(&mut res, &config);
    assert_eq!(res.cookies.len(), 1);
    assert_eq!(res.cookies[0].1, "");
    assert_eq!(res.cookies[0].2.max_age, Some(0));
}
