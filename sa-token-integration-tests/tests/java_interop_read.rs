//! Java → Rust：把金样 kv 原样灌进 MemoryStorage，再用 Rust API 断言。

mod common;

use common::java_interop::{
    fixture_token, get_raw, is_last_active_format, load_and_inject, load_fixture,
};
use common::setup;
use sa_token_core::token::TokenValue;
use sa_token_core::{ApiKeyManager, SaTokenError, TempTokenManager};
use serde_json::Value;

#[tokio::test]
async fn login_long_get_login_id_and_account_session() {
    let (mgr, fx) = load_and_inject("login_long").await;
    let token = fixture_token(&fx, "token");
    assert!(mgr.is_valid(&token).await, "login_long token must be valid");
    let info = mgr.get_token_info(&token).await.expect("get_token_info");
    assert_eq!(info.login_id.as_ref(), "10001");

    let session = mgr.get_session("10001").await.expect("Account-Session");
    assert_eq!(session.session_type, "Account-Session");
    assert!(
        !session.terminal_list.is_empty(),
        "terminalList must not be empty"
    );
    let ext = session.java_ext().expect("wire_ext after Jackson decode");
    assert_eq!(ext.login_id.as_deref(), Some("10001"));
    assert_eq!(ext.login_type.as_deref(), Some("login"));
    let typed = ext.login_id_typed.as_ref().expect("loginId typed node");
    let is_long = typed.as_array().is_some_and(|a| {
        a.iter().any(|v| v.as_str() == Some("java.lang.Long"))
            && a.iter().any(|v| v.as_i64() == Some(10001))
    }) || typed.as_i64() == Some(10001);
    assert!(is_long, "loginId Long or equivalent, got {typed}");
}

#[tokio::test]
async fn login_string_get_login_id() {
    let (mgr, fx) = load_and_inject("login_string").await;
    let token = fixture_token(&fx, "token");
    assert!(mgr.is_valid(&token).await);
    let info = mgr.get_token_info(&token).await.expect("get_token_info");
    assert_eq!(info.login_id.as_ref(), "user-a");
}

#[tokio::test]
async fn login_admin_type_uses_admin_logic() {
    let (mgr, fx) = load_and_inject("login_admin_type").await;
    let token = fixture_token(&fx, "token");
    assert!(
        mgr.is_valid_typed("admin", &token).await,
        "admin token must be valid under loginType=admin"
    );
    let info = mgr
        .get_token_info_typed("admin", &token)
        .await
        .expect("get_token_info_typed admin");
    assert_eq!(info.login_id.as_ref(), "20001");
    assert_eq!(info.login_type.as_ref(), "admin");

    let session = mgr
        .get_session_with_type("admin", "20001")
        .await
        .expect("admin Account-Session");
    assert_eq!(
        session
            .java_ext()
            .and_then(|e| e.login_type.clone())
            .as_deref(),
        Some("admin")
    );
}

#[tokio::test]
async fn kickout_token_value_minus_five() {
    let (mgr, fx) = load_and_inject("kickout").await;
    let token = fixture_token(&fx, "token");
    setup::assert_err(mgr.get_token_info(&token).await, "kicked");
    assert!(!mgr.is_valid(&token).await);
    let key = mgr.keys().token_info(token.as_str());
    assert_eq!(get_raw(&mgr, &key).await.as_deref(), Some("-5"));
}

#[tokio::test]
async fn replaced_old_token_minus_four_new_valid() {
    let (mgr, fx) = load_and_inject("replaced").await;
    let neu = fixture_token(&fx, "token");
    let old = fixture_token(&fx, "replacedToken");
    let info = mgr.get_token_info(&neu).await.expect("new token");
    assert_eq!(info.login_id.as_ref(), "10001");
    setup::assert_err(mgr.get_token_info(&old).await, "replaced");
    let old_key = mgr.keys().token_info(old.as_str());
    assert_eq!(get_raw(&mgr, &old_key).await.as_deref(), Some("-4"));
}

#[tokio::test]
async fn logout_token_invalid() {
    let (mgr, fx) = load_and_inject("logout").await;
    let token = fixture_token(&fx, "token");
    let err = mgr.get_token_info(&token).await.expect_err("logged-out");
    assert!(
        matches!(
            err,
            SaTokenError::TokenNotFound | SaTokenError::NotLogin | SaTokenError::TokenExpired
        ),
        "logout token should be invalid, got {err:?}"
    );
    assert!(!mgr.is_valid(&token).await);
}

#[tokio::test]
async fn disable_is_disable() {
    let (mgr, fx) = load_and_inject("disable").await;
    let token = fixture_token(&fx, "token");
    assert!(mgr.is_valid(&token).await);
    assert!(
        mgr.is_disable("10001").await.expect("is_disable"),
        "account 10001 must be disabled"
    );
}

#[tokio::test]
async fn safe_is_safe() {
    let (mgr, fx) = load_and_inject("safe").await;
    let token = fixture_token(&fx, "token");
    let service = mgr.config.wire.default_safe_service.clone();
    assert_eq!(service, "important");
    assert!(
        mgr.is_safe(&token, &service).await.expect("is_safe"),
        "token must pass secondary auth"
    );
}

#[tokio::test]
async fn active_timeout_last_active_present() {
    let (mgr, fx) = load_and_inject("active_timeout").await;
    let token = fixture_token(&fx, "token");
    let key = mgr.keys().last_active(token.as_str());
    let raw = get_raw(&mgr, &key)
        .await
        .expect("last-active key must exist");
    assert!(
        is_last_active_format(&raw),
        "last-active format <ms> or <ms>,<secs>, got {raw}"
    );
}

#[tokio::test]
async fn active_timeout_dynamic_last_active_csv() {
    let (mgr, fx) = load_and_inject("active_timeout_dynamic").await;
    let token = fixture_token(&fx, "token");
    let key = mgr.keys().last_active(token.as_str());
    let raw = get_raw(&mgr, &key)
        .await
        .expect("dynamic last-active key must exist");
    assert!(
        raw.contains(','),
        "dynamic last-active should be <ms>,<secs>, got {raw}"
    );
    assert!(is_last_active_format(&raw), "got {raw}");
}

#[tokio::test]
async fn token_session_decode_has_class_type() {
    let (mgr, fx) = load_and_inject("token_session").await;
    let token = fixture_token(&fx, "token");
    let session = mgr.get_token_session(&token).await.expect("token-session");
    assert_eq!(session.session_type, "Token-Session");
    assert_eq!(session.get::<String>("name").as_deref(), Some("zhang"));
    let key = mgr.keys().token_session(token.as_str());
    let raw = get_raw(&mgr, &key).await.expect("token-session json");
    assert!(raw.contains("\"@class\""), "token-session JSON has @class");
    assert!(raw.contains("Token-Session"), "type Token-Session");
}

#[tokio::test]
async fn custom_session_decode_has_class_type() {
    let (mgr, _fx) = load_and_inject("custom_session").await;
    let key = mgr.keys().custom_session("role-1001");
    let session = mgr
        .dao()
        .get_session(&key)
        .await
        .expect("decode custom")
        .expect("custom session exists");
    assert_eq!(session.session_type, "Custom-Session");
    let count = session
        .get::<i64>("count")
        .or_else(|| session.get::<i32>("count").map(i64::from));
    assert_eq!(count, Some(1));
    let raw = get_raw(&mgr, &key).await.expect("custom json");
    assert!(raw.contains("\"@class\""));
    assert!(raw.contains("Custom-Session"));
}

#[tokio::test]
async fn raw_session_decode_has_class_type() {
    let (mgr, _fx) = load_and_inject("raw_session").await;
    let key = mgr.keys().raw_session("user", "10001");
    let session = mgr
        .dao()
        .get_session(&key)
        .await
        .expect("decode raw")
        .expect("raw session exists");
    assert_eq!(session.get::<String>("flag").as_deref(), Some("raw"));
    let raw = get_raw(&mgr, &key).await.expect("raw json");
    assert!(raw.contains("\"@class\""));
}

#[tokio::test]
async fn temp_token_str_parses_hello() {
    let (mgr, fx) = load_and_inject("temp_token_str").await;
    let temp = fx["tokens"]["tempToken"].as_str().expect("tempToken");
    let ns = mgr.config.wire.temp_token_namespace.clone();
    let rec = TempTokenManager::new(mgr.dao().clone())
        .parse(&ns, temp)
        .await
        .expect("parse str");
    assert_eq!(rec.value.as_str(), Some("hello"));
}

#[tokio::test]
async fn temp_token_long_parses_10001() {
    let (mgr, fx) = load_and_inject("temp_token_long").await;
    let temp = fx["tokens"]["tempToken"].as_str().expect("tempToken");
    let ns = mgr.config.wire.temp_token_namespace.clone();
    let rec = TempTokenManager::new(mgr.dao().clone())
        .parse(&ns, temp)
        .await
        .expect("parse long");
    assert_eq!(rec.value.as_i64(), Some(10001));
}

#[tokio::test]
async fn temp_token_map_decode_root_without_class() {
    let (mgr, fx) = load_and_inject("temp_token_map").await;
    let temp = fx["tokens"]["tempToken"].as_str().expect("tempToken");
    let ns = mgr.config.wire.temp_token_namespace.clone();
    let key = mgr.keys().temp_token(&ns, temp);
    let raw = get_raw(&mgr, &key).await.expect("temp map body");
    assert!(
        raw.starts_with('{') && !raw.contains("\"@class\""),
        "root Map JSON has no @class: {raw}"
    );
    let v = mgr.dao().wire().decode_root(&raw).expect("decode_root");
    assert_eq!(v["name"].as_str(), Some("alice"));
    assert_eq!(v["id"].as_i64(), Some(10001));
}

#[tokio::test]
async fn apikey_check_passes() {
    let (mgr, fx) = load_and_inject("apikey").await;
    let api_key = fx["tokens"]["apiKey"].as_str().expect("apiKey");
    let api = ApiKeyManager::new(mgr.dao().clone());
    let model = api.check(api_key).await.expect("checkApiKey");
    assert_eq!(model.login_id, "10001");
    assert!(
        api.has_scope(api_key, &["user.read"]).await,
        "scope user.read"
    );
}

#[tokio::test]
async fn jwt_simple_validate_login_id() {
    let (mgr, fx) = load_and_inject("jwt_simple").await;
    let token = fixture_token(&fx, "token");
    let info = mgr.get_token_info(&token).await.expect("jwt_simple");
    assert_eq!(info.login_id.as_ref(), "10001");
}

#[tokio::test]
async fn jwt_mixin_validate_login_id() {
    let (mgr, fx) = load_and_inject("jwt_mixin").await;
    let token = fixture_token(&fx, "token");
    let info = mgr.get_token_info(&token).await.expect("jwt_mixin");
    assert_eq!(info.login_id.as_ref(), "10001");
}

#[tokio::test]
async fn jwt_stateless_validate_login_id() {
    let (mgr, fx) = load_and_inject("jwt_stateless").await;
    let token = fixture_token(&fx, "token");
    let info = mgr.get_token_info(&token).await.expect("jwt_stateless");
    assert_eq!(info.login_id.as_ref(), "10001");
}

#[tokio::test]
async fn jwt_expired_returns_expired_error() {
    let (mgr, fx) = load_and_inject("jwt_expired").await;
    let token = match fx["tokens"]["token"].as_str() {
        Some(s) if !s.is_empty() => TokenValue::new(s),
        _ => fixture_token(&fx, "jwt"),
    };
    let err = mgr
        .get_token_info(&token)
        .await
        .expect_err("expired jwt must fail");
    assert!(
        matches!(err, SaTokenError::TokenExpired),
        "expected TokenExpired, got {err:?}"
    );
}

/// 金样文件齐全，避免漏场景。
#[test]
fn gold_fixture_files_present() {
    let names = [
        "login_long",
        "login_string",
        "login_admin_type",
        "kickout",
        "replaced",
        "logout",
        "disable",
        "safe",
        "active_timeout",
        "token_session",
        "custom_session",
        "raw_session",
        "temp_token_str",
        "temp_token_long",
        "temp_token_map",
        "apikey",
        "jwt_simple",
        "jwt_mixin",
        "jwt_stateless",
        "jwt_expired",
    ];
    for name in names {
        let fx = load_fixture(name);
        assert_eq!(fx["scenario"].as_str(), Some(name));
        assert!(fx.get("kv").is_some(), "{name} missing kv");
    }
}

/// 未覆盖到的金样字段用 decode 再断言，避免 `let _ =` 丢 Result。
#[tokio::test]
async fn login_long_session_json_roundtrip() {
    let (mgr, _fx) = load_and_inject("login_long").await;
    let key = mgr.keys().account_session("login", "10001");
    let raw = get_raw(&mgr, &key).await.expect("session json");
    let decoded = mgr.dao().wire().decode_session(&raw).expect("decode");
    assert_eq!(decoded.session_type, "Account-Session");
    let v: Value = serde_json::from_str(&raw).expect("json");
    assert_eq!(
        v["@class"].as_str(),
        Some("cn.dev33.satoken.session.SaSession")
    );
}
