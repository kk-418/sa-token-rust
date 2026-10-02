//! Java `isLastingCookie`：记住我 vs 会话 Cookie。

mod common;

use std::sync::OnceLock;

use common::setup;
use sa_token_adapter::context::{CookieOptions, SaResponse};
use sa_token_core::token::TokenValue;
use sa_token_core::{
    LoginRequest, PendingCookie, SaTokenConfig, SaTokenContext, StpUtil,
    write_token_cookie_with_max_age,
};
use serial_test::serial;

fn init_stp() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let config = SaTokenConfig::builder()
            .timeout(3600)
            .is_read_cookie(true)
            .is_write_cookie(true)
            .build_config();
        let mgr = setup::fresh_manager_with_config(config);
        let _init = StpUtil::try_init_manager((*mgr).clone());
    });
}

fn bind_ctx() -> SaTokenContext {
    let ctx = SaTokenContext::new();
    SaTokenContext::set_current(ctx.clone());
    ctx
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

fn write_cfg() -> SaTokenConfig {
    SaTokenConfig::builder()
        .timeout(3600)
        .is_write_cookie(true)
        .build_config()
}

/// `is_lasting_cookie=false` → pending Cookie Max-Age &lt; 0（会话 Cookie）。
#[tokio::test]
#[serial]
async fn login_with_lasting_cookie_false_is_session_cookie() {
    init_stp();
    let ctx = bind_ctx();
    let id = setup::unique_login_id("remember_session");
    let token = StpUtil::login_with_lasting_cookie(&id, false)
        .await
        .expect("login_with_lasting_cookie false");
    match ctx.take_pending_cookie() {
        Some(PendingCookie::Write { max_age, token: t }) => {
            assert!(
                max_age < 0,
                "session cookie max_age must be < 0, got {max_age}"
            );
            assert_eq!(t.as_str(), token.as_str());
        }
        other => panic!("expected PendingCookie::Write, got {other:?}"),
    }
    setup::assert_stp_logged_in(&token, &id).await;
    SaTokenContext::clear();
}

/// `is_lasting_cookie=true` → pending Cookie Max-Age = config.timeout（3600）。
#[tokio::test]
#[serial]
async fn login_with_lasting_cookie_true_uses_config_timeout() {
    init_stp();
    let ctx = bind_ctx();
    let id = setup::unique_login_id("remember_lasting");
    let token = StpUtil::login_with_lasting_cookie(&id, true)
        .await
        .expect("login_with_lasting_cookie true");
    match ctx.take_pending_cookie() {
        Some(PendingCookie::Write { max_age, token: t }) => {
            assert_eq!(max_age, 3600);
            assert_eq!(t.as_str(), token.as_str());
        }
        other => panic!("expected PendingCookie::Write, got {other:?}"),
    }
    setup::assert_stp_logged_in(&token, &id).await;
    SaTokenContext::clear();
}

/// 默认 `StpUtil::login` 仍是 lasting=true，max_age = config.timeout。
#[tokio::test]
#[serial]
async fn default_login_is_lasting_cookie() {
    init_stp();
    let ctx = bind_ctx();
    let id = setup::unique_login_id("remember_default");
    let token = StpUtil::login(&id).await.expect("login");
    match ctx.take_pending_cookie() {
        Some(PendingCookie::Write { max_age, token: t }) => {
            assert_eq!(max_age, 3600, "default login must stay lasting=true");
            assert_eq!(t.as_str(), token.as_str());
        }
        other => panic!("expected PendingCookie::Write, got {other:?}"),
    }
    setup::assert_stp_logged_in(&token, &id).await;
    SaTokenContext::clear();
}

/// `TokenBuilder::is_lasting_cookie(false)` → 会话 Cookie。
#[tokio::test]
#[serial]
async fn token_builder_is_lasting_cookie_false_is_session_cookie() {
    init_stp();
    let ctx = bind_ctx();
    let id = setup::unique_login_id("remember_builder_session");
    let token = StpUtil::builder(&id)
        .is_lasting_cookie(false)
        .login(None::<String>)
        .await
        .expect("builder login session");
    match ctx.take_pending_cookie() {
        Some(PendingCookie::Write { max_age, token: t }) => {
            assert!(
                max_age < 0,
                "builder session cookie max_age must be < 0, got {max_age}"
            );
            assert_eq!(t.as_str(), token.as_str());
        }
        other => panic!("expected PendingCookie::Write, got {other:?}"),
    }
    setup::assert_stp_logged_in(&token, &id).await;
    SaTokenContext::clear();
}

/// `TokenBuilder` 默认 lasting=true；配合 timeout 时 Max-Age 跟随本次 timeout。
#[tokio::test]
#[serial]
async fn token_builder_lasting_true_uses_timeout() {
    init_stp();
    let ctx = bind_ctx();
    let id = setup::unique_login_id("remember_builder_timeout");
    let token = StpUtil::builder(&id)
        .timeout(7200)
        .is_lasting_cookie(true)
        .login(None::<String>)
        .await
        .expect("builder login lasting");
    match ctx.take_pending_cookie() {
        Some(PendingCookie::Write { max_age, token: t }) => {
            assert_eq!(max_age, 7200);
            assert_eq!(t.as_str(), token.as_str());
        }
        other => panic!("expected PendingCookie::Write, got {other:?}"),
    }
    setup::assert_stp_logged_in(&token, &id).await;
    SaTokenContext::clear();
}

/// `login_by_request`：false → -1；timeout 仍只影响 token，不改会话 Cookie。
#[tokio::test]
#[serial]
async fn login_by_request_session_cookie_ignores_timeout_for_max_age() {
    init_stp();
    let ctx = bind_ctx();
    let id = setup::unique_login_id("remember_by_request");
    let token = StpUtil::login_by_request(
        LoginRequest::new(&id)
            .timeout(7200)
            .is_lasting_cookie(false),
    )
    .await
    .expect("login_by_request");
    match ctx.take_pending_cookie() {
        Some(PendingCookie::Write { max_age, .. }) => {
            assert!(
                max_age < 0,
                "session cookie max_age must be < 0, got {max_age}"
            );
        }
        other => panic!("expected PendingCookie::Write, got {other:?}"),
    }
    setup::assert_stp_logged_in(&token, &id).await;
    SaTokenContext::clear();
}

/// `write_token_cookie_with_max_age(-1)` → `options.max_age == None`。
#[test]
#[serial]
fn write_token_cookie_session_when_max_age_negative() {
    init_stp();
    let mut res = MockResponse::new();
    let token = TokenValue::new("remember-session-tok");
    write_token_cookie_with_max_age(&mut res, &token, &write_cfg(), -1);
    assert_eq!(res.cookies.len(), 1);
    assert_eq!(res.cookies[0].1, "remember-session-tok");
    assert_eq!(res.cookies[0].2.max_age, None);
}

/// `write_token_cookie_with_max_age(timeout)` → `options.max_age == Some(timeout)`。
#[test]
#[serial]
fn write_token_cookie_lasting_uses_timeout() {
    init_stp();
    let mut res = MockResponse::new();
    let token = TokenValue::new("remember-lasting-tok");
    write_token_cookie_with_max_age(&mut res, &token, &write_cfg(), 3600);
    assert_eq!(res.cookies.len(), 1);
    assert_eq!(res.cookies[0].1, "remember-lasting-tok");
    assert_eq!(res.cookies[0].2.max_age, Some(3600));
}

/// `is_lasting_cookie=false` 的 pending max_age 写出后 `options.max_age == None`。
#[tokio::test]
#[serial]
async fn pending_session_cookie_writes_without_max_age() {
    init_stp();
    let ctx = bind_ctx();
    let id = setup::unique_login_id("remember_write_pending");
    let token = StpUtil::login_with_lasting_cookie(&id, false)
        .await
        .expect("login_with_lasting_cookie false");
    let pending = ctx.take_pending_cookie();
    let mut res = MockResponse::new();
    match pending {
        Some(PendingCookie::Write { max_age, token: t }) => {
            assert!(max_age < 0);
            write_token_cookie_with_max_age(&mut res, &t, &write_cfg(), max_age);
            assert_eq!(t.as_str(), token.as_str());
        }
        other => panic!("expected PendingCookie::Write, got {other:?}"),
    }
    assert_eq!(res.cookies.len(), 1);
    assert_eq!(res.cookies[0].2.max_age, None);
    SaTokenContext::clear();
}
