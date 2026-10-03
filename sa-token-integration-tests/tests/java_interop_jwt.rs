//! JWT Simple / Mixin / Stateless 互通。

mod common;

use common::java_interop::{
    JWT_SECRET, all_keys, dump_config, fixture_token, fresh_manager, get_raw, java_config,
    load_and_inject, maybe_dump,
};
use sa_token_core::config::TokenStyle;
use sa_token_core::{JwtManager, LoginRequest, SaTokenConfig, SaTokenError, TokenValue};
use serde_json::json;

fn jwt_cfg(style: TokenStyle) -> SaTokenConfig {
    let mut cfg = java_config();
    cfg.token_style = style;
    cfg.jwt_secret_key = Some(JWT_SECRET.to_string());
    cfg
}

fn payload(token: &str) -> serde_json::Value {
    JwtManager::new(JWT_SECRET)
        .validate_payload(token)
        .expect("validate_payload")
}

#[tokio::test]
async fn simple_payload_has_login_type_id_rnstr_no_eff_writes_token_key() {
    let mgr = fresh_manager(jwt_cfg(TokenStyle::Jwt));
    let token = mgr
        .auth_service()
        .login(LoginRequest::new("10001").extra_data(json!({ "age": 18 })))
        .await
        .expect("jwt simple login");
    assert_eq!(token.as_str().matches('.').count(), 2);

    let obj = payload(token.as_str());
    let map = obj.as_object().expect("payload object");
    assert_eq!(map.get("loginType"), Some(&json!("login")));
    assert_eq!(map.get("loginId"), Some(&json!(10001)));
    let rn = map.get("rnStr").and_then(|v| v.as_str()).expect("rnStr");
    assert_eq!(rn.len(), 32);
    assert!(rn.bytes().all(|b| b.is_ascii_alphanumeric()), "rnStr={rn}");
    assert!(!map.contains_key("eff"), "Simple JWT must not have eff");
    assert!(
        !map.contains_key("deviceType"),
        "Simple JWT must not have deviceType"
    );
    assert_eq!(map.get("age"), Some(&json!(18)));

    let token_key = mgr.keys().token_info(token.as_str());
    assert_eq!(
        get_raw(&mgr, &token_key).await.as_deref(),
        Some("10001"),
        "Simple still writes token key"
    );

    maybe_dump(
        &mgr,
        "jwt_simple",
        "Rust JWT Simple",
        dump_config("simple", "login", &[]),
        json!({ "loginId": 10001, "extraAge": 18 }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn mixin_no_token_key_session_has_terminal_kick_out_api_disabled() {
    let mgr = fresh_manager(jwt_cfg(TokenStyle::JwtMixin));
    let token = mgr.login("10001").await.expect("mixin login");
    let obj = payload(token.as_str());
    assert_eq!(obj["loginType"], "login");
    assert_eq!(obj["loginId"], 10001);
    assert_eq!(obj["deviceType"], "DEF");
    assert_eq!(obj["eff"], -1);

    let token_key = mgr.keys().token_info(token.as_str());
    assert!(
        get_raw(&mgr, &token_key).await.is_none(),
        "Mixin must not write token key"
    );
    let session = mgr.get_session("10001").await.expect("session");
    assert_eq!(session.terminal_list.len(), 1);
    assert_eq!(session.terminal_list[0].token_value, token.as_str());

    let err = mgr
        .kick_out("login", "10001")
        .await
        .expect_err("mixin kick_out");
    assert!(
        matches!(err, SaTokenError::ApiDisabled(ref s) if s == "jwt-mixin"),
        "kick_out → ApiDisabled, got {err:?}"
    );

    maybe_dump(
        &mgr,
        "jwt_mixin",
        "Rust JWT Mixin",
        dump_config("mixin", "login", &[]),
        json!({ "loginId": 10001, "device": "DEF" }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn stateless_kv_has_no_session_or_token() {
    let mgr = fresh_manager(jwt_cfg(TokenStyle::JwtStateless));
    let token = mgr.login("10001").await.expect("stateless login");
    let obj = payload(token.as_str());
    assert_eq!(obj["loginType"], "login");
    assert_eq!(obj["loginId"], 10001);
    assert_eq!(obj["eff"], -1);

    let keys = all_keys(&mgr).await;
    let leftover: Vec<_> = keys
        .iter()
        .filter(|k| k.contains(":session:") || k.contains(":token:"))
        .collect();
    assert!(
        leftover.is_empty(),
        "Stateless must not persist session/token keys, got {leftover:?}"
    );

    let info = mgr.get_token_info(&token).await.expect("validate");
    assert_eq!(info.login_id.as_ref(), "10001");

    maybe_dump(
        &mgr,
        "jwt_stateless",
        "Rust JWT Stateless",
        dump_config("stateless", "login", &[]),
        json!({ "loginId": 10001, "device": "DEF" }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn validate_gold_jwt_simple_token_string() {
    let (mgr, fx) = load_and_inject("jwt_simple").await;
    let token = fixture_token(&fx, "token");
    let info = mgr.get_token_info(&token).await.expect("gold simple");
    assert_eq!(info.login_id.as_ref(), "10001");
    let obj = payload(token.as_str());
    assert_eq!(obj["loginType"], "login");
    assert_eq!(obj["loginId"], 10001);
    assert_eq!(obj["age"], 18);
}

#[tokio::test]
async fn validate_gold_jwt_stateless_and_expired() {
    let (mgr, fx) = load_and_inject("jwt_stateless").await;
    let token = fixture_token(&fx, "token");
    let info = mgr.get_token_info(&token).await.expect("gold stateless");
    assert_eq!(info.login_id.as_ref(), "10001");

    let (mgr_exp, fx_exp) = load_and_inject("jwt_expired").await;
    let expired = TokenValue::new(fx_exp["tokens"]["token"].as_str().expect("expired"));
    let err = mgr_exp
        .get_token_info(&expired)
        .await
        .expect_err("expired jwt");
    assert!(matches!(err, SaTokenError::TokenExpired), "got {err:?}");
}
