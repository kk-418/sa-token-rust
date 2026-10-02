//! Java parity: StpUtil timeout / current session / search / TokenStyle alias.

mod common;

use common::setup;
use sa_token_core::config::TokenStyle;
use sa_token_core::token::TokenValue;
use sa_token_core::{SaTokenConfig, SaTokenContext, StpUtil};
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
