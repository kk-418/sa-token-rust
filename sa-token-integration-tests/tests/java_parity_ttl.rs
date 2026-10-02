//! Java parity: per-login timeout must be written as storage TTL.

mod common;

use std::time::Duration;

use common::setup;
use sa_token_core::config::TokenStyle;
use sa_token_core::keys::{LoginId, SaKeys};
use sa_token_core::service::LoginRequest;
use sa_token_core::token::TokenValue;
use sa_token_core::{SaTokenConfig, SaTokenManager};

fn assert_ttl_around(name: &str, ttl: Option<Duration>, lo: u64, hi: u64) {
    let secs = ttl.expect(name).as_secs();
    assert!(
        (lo..=hi).contains(&secs),
        "{name} ttl={secs}, want {lo}..={hi}"
    );
}

fn session_key(mgr: &SaTokenManager, login_id: &str) -> String {
    let id = LoginId::try_new(login_id).expect("login id");
    let ns = SaKeys::account_ns("default", &id);
    mgr.dao().keys().session_by_ns(&ns).expect("session key")
}

#[tokio::test]
async fn login_with_timeout_writes_storage_ttl_not_global() {
    let config = SaTokenConfig::builder()
        .timeout(10)
        .token_style(TokenStyle::Uuid)
        .is_concurrent(true)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let id = setup::unique_login_id("ttl");
    let token = mgr
        .auth_service()
        .login(LoginRequest::new(&id).timeout(3600))
        .await
        .expect("login");

    let keys = mgr.dao().keys();
    let token_s = token.as_str();
    let info_ttl = mgr
        .dao()
        .ttl(&keys.token_info(token_s))
        .await
        .expect("info ttl");
    let map_ttl = mgr
        .dao()
        .ttl(&keys.token_id_mapping(token_s))
        .await
        .expect("map ttl");
    let login_ttl = mgr
        .dao()
        .ttl(&keys.login_token("default", &id))
        .await
        .expect("login ttl");
    let idx_ttl = mgr
        .dao()
        .ttl(&keys.login_token_index("default", &id))
        .await
        .expect("idx ttl");
    let sess_ttl = mgr
        .dao()
        .ttl(&session_key(&mgr, &id))
        .await
        .expect("sess ttl");

    for (name, ttl) in [
        ("info", info_ttl),
        ("map", map_ttl),
        ("login", login_ttl),
        ("idx", idx_ttl),
        ("session", sess_ttl),
    ] {
        assert_ttl_around(name, ttl, 3590, 3600);
    }
}

#[tokio::test]
async fn renew_timeout_extends_mapping_and_session_ttl() {
    let config = SaTokenConfig::builder()
        .timeout(10)
        .token_style(TokenStyle::Uuid)
        .is_concurrent(true)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let id = setup::unique_login_id("renew");
    let token = mgr
        .auth_service()
        .login(LoginRequest::new(&id).timeout(100))
        .await
        .expect("login");

    mgr.renew_timeout(&token, 3600).await.expect("renew");

    let keys = mgr.dao().keys();
    let token_s = token.as_str();
    assert_ttl_around(
        "info",
        mgr.dao()
            .ttl(&keys.token_info(token_s))
            .await
            .expect("info"),
        3590,
        3600,
    );
    assert_ttl_around(
        "map",
        mgr.dao()
            .ttl(&keys.token_id_mapping(token_s))
            .await
            .expect("map"),
        3590,
        3600,
    );
    assert_ttl_around(
        "session",
        mgr.dao().ttl(&session_key(&mgr, &id)).await.expect("sess"),
        3590,
        3600,
    );
}

#[tokio::test]
async fn concurrent_shorter_login_does_not_shorten_index_or_mapping() {
    let config = SaTokenConfig::builder()
        .timeout(3600)
        .token_style(TokenStyle::Uuid)
        .is_concurrent(true)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let id = setup::unique_login_id("max");

    let _token_a: TokenValue = mgr
        .auth_service()
        .login(LoginRequest::new(&id).timeout(3600))
        .await
        .expect("login A");
    let _token_b = mgr
        .auth_service()
        .login(LoginRequest::new(&id).timeout(10))
        .await
        .expect("login B");

    let keys = mgr.dao().keys();
    assert_ttl_around(
        "login",
        mgr.dao()
            .ttl(&keys.login_token("default", &id))
            .await
            .expect("login"),
        3590,
        3600,
    );
    assert_ttl_around(
        "idx",
        mgr.dao()
            .ttl(&keys.login_token_index("default", &id))
            .await
            .expect("idx"),
        3590,
        3600,
    );
    assert_ttl_around(
        "session",
        mgr.dao().ttl(&session_key(&mgr, &id)).await.expect("sess"),
        3590,
        3600,
    );
}
