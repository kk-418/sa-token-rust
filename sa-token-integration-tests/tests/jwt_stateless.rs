//! JWT Stateless：登录不写映射，验签读 claims，踢人禁用。

mod common;

use common::setup;
use sa_token_adapter::storage::SaStorage;
use sa_token_core::{SaTokenConfig, SaTokenError, TokenValue, config::TokenStyle};

const TEST_SECRET: &str = "test-secret-key-for-jwt-minimum-32-chars-long";

fn stateless_config() -> SaTokenConfig {
    SaTokenConfig::builder()
        .token_style(TokenStyle::JwtStateless)
        .jwt_secret_key(TEST_SECRET)
        .timeout(3600)
        .build_config()
}

#[tokio::test]
async fn test_jwt_stateless_login_shape_and_login_id() {
    let mgr = setup::fresh_manager_with_config(stateless_config());
    let token = mgr.login("user_stateless").await.expect("login");
    assert_eq!(
        token.as_str().matches('.').count(),
        2,
        "JWT must contain two dots"
    );
    assert!(mgr.is_valid(&token).await);
    let info = mgr.get_token_info(&token).await.expect("info");
    assert_eq!(info.login_id.as_ref(), "user_stateless");
}

#[tokio::test]
async fn test_jwt_stateless_survives_storage_clear() {
    let mgr = setup::fresh_manager_with_config(stateless_config());
    let token = mgr.login("user_stateless_clear").await.expect("login");
    let before = mgr.get_token_info(&token).await.expect("info before clear");
    assert_eq!(before.login_id.as_ref(), "user_stateless_clear");

    SaStorage::clear(mgr.storage().as_ref())
        .await
        .expect("clear storage");

    let after = mgr
        .get_token_info(&token)
        .await
        .expect("stateless jwt still valid after storage clear");
    assert_eq!(after.login_id.as_ref(), "user_stateless_clear");
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_jwt_stateless_tampered_signature_rejected() {
    let mgr = setup::fresh_manager_with_config(stateless_config());
    let token = mgr.login("user_stateless_tamper").await.expect("login");
    let raw = token.as_str();
    let tampered = if raw.len() > 4 {
        format!("{}XXXX", &raw[..raw.len() - 4])
    } else {
        format!("{raw}x")
    };
    let bad = TokenValue::new(tampered);
    let err = mgr
        .get_token_info(&bad)
        .await
        .expect_err("tampered signature must fail");
    assert!(
        matches!(err, SaTokenError::InvalidToken(_)),
        "expected InvalidToken, got {err:?}"
    );
}

#[tokio::test]
async fn test_jwt_stateless_kick_out_disabled_token_still_valid() {
    let mgr = setup::fresh_manager_with_config(stateless_config());
    let token = mgr.login("user_stateless_kick").await.expect("login");
    assert!(mgr.is_valid(&token).await);

    let err = mgr
        .kick_out_by_token(&token)
        .await
        .expect_err("kick must be disabled");
    assert!(
        matches!(err, SaTokenError::ApiDisabled(ref s) if s == "jwt-stateless"),
        "expected ApiDisabled(jwt-stateless), got {err:?}"
    );

    let info = mgr
        .get_token_info(&token)
        .await
        .expect("jwt still parses after kick");
    assert_eq!(info.login_id.as_ref(), "user_stateless_kick");
    assert!(mgr.is_valid(&token).await);
}

#[tokio::test]
async fn test_jwt_stateless_account_kick_and_logout_disabled() {
    let mgr = setup::fresh_manager_with_config(stateless_config());
    let token = mgr.login("user_stateless_account").await.expect("login");

    let kick = mgr
        .kick_out("login", "user_stateless_account")
        .await
        .expect_err("kick_out disabled");
    assert!(matches!(kick, SaTokenError::ApiDisabled(ref s) if s == "jwt-stateless"));

    let logout = mgr
        .logout_by_login_id("login", "user_stateless_account")
        .await
        .expect_err("logout_by_login_id disabled");
    assert!(matches!(logout, SaTokenError::ApiDisabled(ref s) if s == "jwt-stateless"));

    let replaced = mgr
        .replaced_by_token(&token)
        .await
        .expect_err("replaced_by_token disabled");
    assert!(matches!(replaced, SaTokenError::ApiDisabled(ref s) if s == "jwt-stateless"));

    let info = mgr.get_token_info(&token).await.expect("still valid");
    assert_eq!(info.login_id.as_ref(), "user_stateless_account");
}
