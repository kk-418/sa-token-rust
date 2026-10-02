//! Java parity: StpUtil timeout / current session / search / TokenStyle alias.

mod common;

use common::setup;
use sa_token_core::config::TokenStyle;
use sa_token_core::token::TokenValue;
use sa_token_core::{SaTokenConfig, SaTokenContext, SaTokenError, StpUtil};
use serial_test::serial;

fn init_stp() {
    let _mgr = setup::shared_manager();
}

#[tokio::test]
#[serial]
async fn test_login_with_timeout_one_day() {
    init_stp();
    let id = setup::unique_login_id("jp_to");
    let token = StpUtil::login_with_timeout(&id, 86400)
        .await
        .expect("login_with_timeout");
    let remaining = StpUtil::get_token_timeout(&token)
        .await
        .expect("get_token_timeout")
        .expect("timeout must be some");
    assert!(
        (86390..=86400).contains(&remaining),
        "expected ~86400s remaining, got {remaining}"
    );
}

#[tokio::test]
#[serial]
async fn test_get_session_current_custom_value() {
    init_stp();
    let id = setup::unique_login_id("jp_sess");
    let token = StpUtil::login(&id).await.expect("login");
    let ctx = SaTokenContext::builder()
        .token(token)
        .login_id(id.clone())
        .build();

    SaTokenContext::scope(ctx, async {
        let mut session = StpUtil::get_session_current()
            .await
            .expect("get_session_current");
        session.set("theme", "dark").expect("set theme");
        StpUtil::save_session(&session).await.expect("save");

        let session2 = StpUtil::get_session_current().await.expect("reload");
        let theme: Option<String> = session2.get("theme");
        assert_eq!(theme.as_deref(), Some("dark"));

        StpUtil::remove_session_value(&id, "theme")
            .await
            .expect("delete theme");
        let session3 = StpUtil::get_session_current().await.expect("after delete");
        let theme: Option<String> = session3.get("theme");
        assert_eq!(theme, None);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_search_token_value_resolves_login_id() {
    init_stp();
    let ids = [
        setup::unique_login_id("jp_search0"),
        setup::unique_login_id("jp_search1"),
        setup::unique_login_id("jp_search2"),
    ];
    for id in &ids {
        StpUtil::login(id).await.expect("login");
    }
    let found = StpUtil::search_token_value("", 0, 10, true)
        .await
        .expect("search_token_value");
    assert!(!found.is_empty(), "search must return tokens");

    let mut resolved = Vec::new();
    for raw in &found {
        let token = TokenValue::new(raw);
        let login_id = StpUtil::get_login_id(&token)
            .await
            .expect("returned string must get_login_id");
        resolved.push(login_id);
    }
    for id in &ids {
        assert!(
            resolved.iter().any(|r| r == id),
            "search result should include login_id {id}, got {resolved:?}"
        );
    }
}

#[test]
fn test_token_style_jwt_alias() {
    let style: TokenStyle = serde_json::from_str("\"jwt\"").expect("parse jwt");
    assert!(matches!(style, TokenStyle::Jwt));
}

#[test]
fn test_cookie_auto_fill_prefix_default_false() {
    assert!(!SaTokenConfig::default().cookie_auto_fill_prefix);
}

#[tokio::test]
#[serial]
async fn test_current_user_permission_role_api() {
    init_stp();
    let id = setup::unique_login_id("jp_cur");
    let token = StpUtil::login(&id).await.expect("login");
    StpUtil::set_permissions(&id, vec!["p".into()])
        .await
        .expect("set_permissions");
    StpUtil::set_roles(&id, vec!["admin".into()])
        .await
        .expect("set_roles");
    let ctx = SaTokenContext::builder()
        .token(token)
        .login_id(id.clone())
        .build();

    SaTokenContext::scope(ctx, async {
        assert!(StpUtil::has_permission_current("p").await);
        assert!(!StpUtil::has_permission_current("nope").await);
        StpUtil::check_role_current("admin")
            .await
            .expect("check_role_current admin");
        let denied = StpUtil::check_role_current("guest").await;
        assert!(matches!(
            denied,
            Err(SaTokenError::RoleDenied(ref r)) if r == "guest"
        ));
        assert_eq!(StpUtil::get_login_type(), "default");
        assert_eq!(
            StpUtil::get_login_id_current_opt().await.as_deref(),
            Some(id.as_str())
        );
    })
    .await;

    assert_eq!(StpUtil::get_login_id_current_opt().await, None);
    assert!(!StpUtil::has_permission_current("p").await);
}

#[tokio::test]
#[serial]
async fn test_session_value_current() {
    init_stp();
    let id = setup::unique_login_id("jp_sv");
    let token = StpUtil::login(&id).await.expect("login");
    let ctx = SaTokenContext::builder()
        .token(token)
        .login_id(id.clone())
        .build();

    SaTokenContext::scope(ctx, async {
        StpUtil::set_session_value_current("theme", "dark")
            .await
            .expect("set_session_value_current");
        let theme: Option<String> = StpUtil::get_session_value_current("theme")
            .await
            .expect("get_session_value_current");
        assert_eq!(theme.as_deref(), Some("dark"));

        StpUtil::remove_session_value_current("theme")
            .await
            .expect("remove_session_value_current");
        let theme: Option<String> = StpUtil::get_session_value_current("theme")
            .await
            .expect("get after remove");
        assert_eq!(theme, None);
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_get_login_id_as_string_uses_context_cache() {
    init_stp();
    let id = setup::unique_login_id("jp_cache");
    let token = StpUtil::login(&id).await.expect("login");
    let ctx = SaTokenContext::builder()
        .token(token)
        .login_id("cached")
        .build();

    SaTokenContext::scope(ctx, async {
        let got = StpUtil::get_login_id_as_string()
            .await
            .expect("cached login_id");
        assert_eq!(got, "cached");
    })
    .await;
}

#[tokio::test]
#[serial]
async fn test_logout_current_clears_context_login_id() {
    init_stp();
    let id = setup::unique_login_id("jp_lo");
    let token = StpUtil::login(&id).await.expect("login");
    let ctx = SaTokenContext::builder()
        .token(token)
        .login_id(id.clone())
        .build();

    SaTokenContext::scope(ctx, async {
        assert_eq!(
            StpUtil::get_login_id_current_opt().await.as_deref(),
            Some(id.as_str())
        );
        StpUtil::logout_current().await.expect("logout_current");
        assert_eq!(StpUtil::get_login_id_current_opt().await, None);
    })
    .await;
}
