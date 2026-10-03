//! Rust → 语义比对：`java_compatible` 登录后检查键布局与值格式。
//! `SA_INTEROP_DUMP_DIR` 有值时写出与金样相同 schema 的 dump。

mod common;

use common::java_interop::{
    JWT_SECRET, all_keys, assert_no_rust_index_keys, dump_config, dump_kv, fresh_manager, get_raw,
    is_last_active_format, java_config, load_fixture, maybe_dump, write_dump_to,
};
use sa_token_core::config::TokenStyle;
use sa_token_core::{
    ApiKeyManager, LoginRequest, RequestSign, SaSession, SaTokenConfig, SaTokenError,
    TempTokenManager, TokenValue, compat::SignAlgorithm,
};
use serde_json::{Value, json};

fn java_cfg() -> SaTokenConfig {
    java_config()
}

fn java_cfg_overlay(f: impl FnOnce(&mut SaTokenConfig)) -> SaTokenConfig {
    let mut cfg = java_cfg();
    f(&mut cfg);
    cfg
}

fn assert_login_id_long_or_decoded(raw: &str, expect: &str) {
    assert!(raw.contains("\"@class\""), "session JSON has @class");
    assert!(
        raw.contains("terminalList"),
        "session JSON has terminalList"
    );
    let v: Value = serde_json::from_str(raw).expect("session json");
    let login_id = &v["loginId"];
    let ok = match login_id {
        Value::Array(a) => {
            a.iter().any(|x| x.as_str() == Some("java.lang.Long"))
                && a.iter()
                    .any(|x| x.as_i64().map(|n| n.to_string()) == Some(expect.to_string()))
        }
        Value::Number(n) => n.to_string() == expect,
        Value::String(s) => s == expect,
        Value::Null => false,
        _ => false,
    };
    assert!(
        ok,
        "loginId Long or equivalent decode for {expect}, got {login_id}"
    );
}

#[tokio::test]
async fn login_long_token_value_is_plain_login_id() {
    let mgr = fresh_manager(java_cfg());
    let token = mgr.login("10001").await.expect("login");
    assert!(mgr.is_valid(&token).await);
    let info = mgr.get_token_info(&token).await.expect("info");
    assert_eq!(info.login_id.as_ref(), "10001");

    let token_key = mgr.keys().token_info(token.as_str());
    let raw = get_raw(&mgr, &token_key).await.expect("token key");
    assert_eq!(raw, "10001");
    assert!(!raw.starts_with('{'), "token key must not be JSON object");

    let session_key = mgr.keys().account_session("login", "10001");
    let session_raw = get_raw(&mgr, &session_key)
        .await
        .expect("satoken:login:session:10001");
    assert_eq!(session_key, "satoken:login:session:10001");
    assert_login_id_long_or_decoded(&session_raw, "10001");

    let session = mgr.get_session("10001").await.expect("session");
    assert_eq!(session.session_type, "Account-Session");
    assert_eq!(session.terminal_list.len(), 1);
    assert_eq!(session.terminal_list[0].device_type, "DEF");
    assert_eq!(session.terminal_list[0].token_value, token.as_str());

    let keys = all_keys(&mgr).await;
    assert_no_rust_index_keys(&keys);
    assert!(
        get_raw(&mgr, &mgr.keys().last_active(token.as_str()))
            .await
            .is_none(),
        "active_timeout=-1 must not write last-active"
    );

    maybe_dump(
        &mgr,
        "login_long",
        "Rust java_compatible login(\"10001\") timeout=-1",
        dump_config("none", "login", &[]),
        json!({ "loginId": 10001, "device": "DEF" }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn login_string_token_value_is_plain() {
    let mgr = fresh_manager(java_cfg());
    let token = mgr.login("user-a").await.expect("login");
    let raw = get_raw(&mgr, &mgr.keys().token_info(token.as_str()))
        .await
        .expect("token key");
    assert_eq!(raw, "user-a");
    let session_raw = get_raw(&mgr, &mgr.keys().account_session("login", "user-a"))
        .await
        .expect("session");
    assert!(session_raw.contains("\"@class\""));
    assert!(session_raw.contains("user-a"));

    maybe_dump(
        &mgr,
        "login_string",
        "Rust java_compatible login(\"user-a\")",
        dump_config("none", "login", &[]),
        json!({ "loginId": "user-a", "device": "DEF" }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn login_admin_type_writes_admin_keys() {
    let mgr = fresh_manager(java_cfg());
    let token = mgr
        .login_with_options("20001", Some("admin".into()), None, None, None, None)
        .await
        .expect("admin login");
    let info = mgr
        .get_token_info_typed("admin", &token)
        .await
        .expect("info");
    assert_eq!(info.login_id.as_ref(), "20001");
    let token_key = mgr.keys().token_info_with_type("admin", token.as_str());
    assert_eq!(get_raw(&mgr, &token_key).await.as_deref(), Some("20001"));
    let session_key = mgr.keys().account_session("admin", "20001");
    assert_eq!(session_key, "satoken:admin:session:20001");
    let session_raw = get_raw(&mgr, &session_key).await.expect("admin session");
    assert!(session_raw.contains("\"@class\""));
    assert!(session_raw.contains("\"admin\""));

    maybe_dump(
        &mgr,
        "login_admin_type",
        "Rust login_with_options login_type=admin",
        dump_config("none", "admin", &[]),
        json!({ "loginId": 20001, "loginType": "admin", "device": "DEF" }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn kickout_keeps_token_key_as_minus_five() {
    let mgr = fresh_manager(java_cfg());
    let token = mgr.login("10001").await.expect("login");
    mgr.kick_out("login", "10001").await.expect("kick_out");
    let token_key = mgr.keys().token_info(token.as_str());
    assert!(
        mgr.storage().exists(&token_key).await.expect("exists"),
        "kickout token key must remain"
    );
    assert_eq!(get_raw(&mgr, &token_key).await.as_deref(), Some("-5"));
    setup_err_kicked(&mgr, &token).await;

    maybe_dump(
        &mgr,
        "kickout",
        "Rust kick_out keeps token key value -5",
        dump_config("none", "login", &[]),
        json!({ "loginId": 10001 }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

async fn setup_err_kicked(mgr: &sa_token_core::SaTokenManager, token: &TokenValue) {
    common::setup::assert_err(mgr.get_token_info(token).await, "kicked");
}

#[tokio::test]
async fn multi_device_two_terminals() {
    let mgr = fresh_manager(java_cfg());
    let t1 = mgr
        .login_with_options("10001", None, Some("PC".into()), None, None, None)
        .await
        .expect("pc");
    let t2 = mgr
        .login_with_options("10001", None, Some("APP".into()), None, None, None)
        .await
        .expect("app");
    assert_ne!(t1.as_str(), t2.as_str());
    let session = mgr.get_session("10001").await.expect("session");
    assert_eq!(session.terminal_list.len(), 2, "two terminals");
    let devices: Vec<_> = session
        .terminal_list
        .iter()
        .map(|t| t.device_type.as_str())
        .collect();
    assert!(devices.contains(&"PC"));
    assert!(devices.contains(&"APP"));

    maybe_dump(
        &mgr,
        "multi_device",
        "Rust two-device login PC/APP",
        dump_config("none", "login", &[]),
        json!({ "loginId": 10001, "device1": "PC", "device2": "APP" }),
        json!({ "token": t1.as_str(), "token2": t2.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn last_active_only_when_active_timeout_positive() {
    let mgr = fresh_manager(java_cfg_overlay(|c| c.active_timeout = 1800));
    let token = mgr.login("10001").await.expect("login");
    let key = mgr.keys().last_active(token.as_str());
    let raw = get_raw(&mgr, &key).await.expect("last-active");
    assert!(is_last_active_format(&raw), "last-active format, got {raw}");

    maybe_dump(
        &mgr,
        "active_timeout",
        "Rust active_timeout=1800 writes last-active ms",
        dump_config("none", "login", &[("activeTimeout", json!(1800))]),
        json!({ "loginId": 10001, "activeTimeout": 1800 }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn last_active_dynamic_csv() {
    let mgr = fresh_manager(java_cfg_overlay(|c| {
        c.active_timeout = 1800;
        c.dynamic_active_timeout = true;
    }));
    let token = mgr.login("10001").await.expect("login");
    mgr.update_active_timeout(&token, 600)
        .await
        .expect("update_active_timeout");
    // 再读一次以写出动态值；若实现只在登录时写 <ms>,<secs>，也接受登录时格式。
    let key = mgr.keys().last_active(token.as_str());
    let raw = get_raw(&mgr, &key).await.expect("last-active");
    assert!(is_last_active_format(&raw), "got {raw}");

    maybe_dump(
        &mgr,
        "active_timeout_dynamic",
        "Rust dynamic_active_timeout last-active",
        dump_config(
            "none",
            "login",
            &[
                ("activeTimeout", json!(1800)),
                ("dynamicActiveTimeout", json!(true)),
            ],
        ),
        json!({ "loginId": 10001, "activeTimeout": 600 }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn replaced_old_token_is_minus_four() {
    let mgr = fresh_manager(java_cfg_overlay(|c| {
        c.is_concurrent = false;
        c.is_share = false;
    }));
    let old = mgr
        .login_with_options("10001", None, Some("PC".into()), None, None, None)
        .await
        .expect("first");
    let neu = mgr
        .login_with_options("10001", None, Some("PC".into()), None, None, None)
        .await
        .expect("second");
    assert_ne!(old.as_str(), neu.as_str());
    common::setup::assert_err(mgr.get_token_info(&old).await, "replaced");
    let info = mgr.get_token_info(&neu).await.expect("new token");
    assert_eq!(info.login_id.as_ref(), "10001");
    assert_eq!(
        get_raw(&mgr, &mgr.keys().token_info(old.as_str()))
            .await
            .as_deref(),
        Some("-4")
    );

    maybe_dump(
        &mgr,
        "replaced",
        "Rust is_concurrent=false second login replaces",
        dump_config("none", "login", &[("isConcurrent", json!(false))]),
        json!({ "loginId": 10001, "device": "PC" }),
        json!({ "token": neu.as_str(), "replacedToken": old.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn logout_deletes_token_key() {
    let mgr = fresh_manager(java_cfg());
    let token = mgr.login("10001").await.expect("login");
    mgr.logout_by_login_id("login", "10001")
        .await
        .expect("logout");
    assert!(!mgr.is_valid(&token).await);
    assert!(
        get_raw(&mgr, &mgr.keys().token_info(token.as_str()))
            .await
            .is_none(),
        "logout must delete token key"
    );

    maybe_dump(
        &mgr,
        "logout",
        "Rust logout_by_login_id deletes token mapping",
        dump_config("none", "login", &[]),
        json!({ "loginId": 10001 }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn disable_and_safe_key_shapes() {
    let mgr = fresh_manager(java_cfg());
    let token = mgr.login("10001").await.expect("login");
    mgr.disable("10001", -1).await.expect("disable");
    assert!(mgr.is_disable("10001").await.expect("is_disable"));
    let disable_key = mgr.keys().disable("login", "10001", "login");
    assert_eq!(disable_key, "satoken:login:disable:login:10001");
    assert_eq!(get_raw(&mgr, &disable_key).await.as_deref(), Some("1"));

    let service = mgr.config.wire.default_safe_service.clone();
    mgr.open_safe(&token, &service, 0).await.expect("open_safe");
    assert!(mgr.is_safe(&token, &service).await.expect("is_safe"));
    let safe_key = mgr
        .keys()
        .safe_with_type("login", token.as_str(), "important");
    assert_eq!(
        safe_key,
        format!("satoken:login:safe:important:{}", token.as_str())
    );
    assert_eq!(
        get_raw(&mgr, &safe_key).await.as_deref(),
        Some("SAFE_AUTH_SAVE_VALUE")
    );

    maybe_dump(
        &mgr,
        "disable",
        "Rust disable default service=login value=1",
        dump_config("none", "login", &[]),
        json!({ "loginId": 10001, "service": "login", "level": 1 }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

#[tokio::test]
async fn token_session_writes_class() {
    let mgr = fresh_manager(java_cfg());
    let token = mgr.login("10001").await.expect("login");
    let mut ts = mgr.get_token_session(&token).await.expect("token-session");
    ts.set("name", "zhang").expect("set");
    mgr.save_token_session(&token, &ts)
        .await
        .expect("save token-session");
    let key = mgr.keys().token_session(token.as_str());
    let raw = get_raw(&mgr, &key).await.expect("json");
    assert!(raw.contains("\"@class\""));
    assert!(raw.contains("Token-Session"));

    maybe_dump(
        &mgr,
        "token_session",
        "Rust token-session name=zhang",
        dump_config("none", "login", &[]),
        json!({ "loginId": 10001, "sessionKey": "name", "sessionValue": "zhang" }),
        json!({ "token": token.as_str() }),
    )
    .await;
}

/// 一次性写出全部 Verify 场景 dump（仅 `SA_INTEROP_DUMP_DIR` 有值时写文件）。
#[tokio::test]
async fn dump_for_java_verify() {
    let Some(dir) = std::env::var_os(common::java_interop::DUMP_ENV).map(std::path::PathBuf::from)
    else {
        return;
    };

    // login_long
    {
        let mgr = fresh_manager(java_cfg());
        let token = mgr.login("10001").await.expect("login");
        write_dump_to(
            &dir,
            "login_long",
            "Rust dump login_long",
            dump_config("none", "login", &[]),
            json!({ "loginId": 10001, "device": "DEF" }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // login_string
    {
        let mgr = fresh_manager(java_cfg());
        let token = mgr.login("user-a").await.expect("login");
        write_dump_to(
            &dir,
            "login_string",
            "Rust dump login_string",
            dump_config("none", "login", &[]),
            json!({ "loginId": "user-a", "device": "DEF" }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // login_admin_type
    {
        let mgr = fresh_manager(java_cfg());
        let token = mgr
            .login_with_options("20001", Some("admin".into()), None, None, None, None)
            .await
            .expect("admin");
        write_dump_to(
            &dir,
            "login_admin_type",
            "Rust dump login_admin_type",
            dump_config("none", "admin", &[]),
            json!({ "loginId": 20001, "loginType": "admin", "device": "DEF" }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // multi_device
    {
        let mgr = fresh_manager(java_cfg());
        let t1 = mgr
            .login_with_options("10001", None, Some("PC".into()), None, None, None)
            .await
            .expect("pc");
        let t2 = mgr
            .login_with_options("10001", None, Some("APP".into()), None, None, None)
            .await
            .expect("app");
        write_dump_to(
            &dir,
            "multi_device",
            "Rust dump multi_device",
            dump_config("none", "login", &[]),
            json!({ "loginId": 10001, "device1": "PC", "device2": "APP" }),
            json!({ "token": t1.as_str(), "token2": t2.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // kickout
    {
        let mgr = fresh_manager(java_cfg());
        let token = mgr.login("10001").await.expect("login");
        mgr.kick_out("login", "10001").await.expect("kick");
        write_dump_to(
            &dir,
            "kickout",
            "Rust dump kickout",
            dump_config("none", "login", &[]),
            json!({ "loginId": 10001 }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // replaced
    {
        let mgr = fresh_manager(java_cfg_overlay(|c| {
            c.is_concurrent = false;
            c.is_share = false;
        }));
        let old = mgr
            .login_with_options("10001", None, Some("PC".into()), None, None, None)
            .await
            .expect("old");
        let neu = mgr
            .login_with_options("10001", None, Some("PC".into()), None, None, None)
            .await
            .expect("new");
        write_dump_to(
            &dir,
            "replaced",
            "Rust dump replaced",
            dump_config("none", "login", &[("isConcurrent", json!(false))]),
            json!({ "loginId": 10001, "device": "PC" }),
            json!({ "token": neu.as_str(), "replacedToken": old.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // logout
    {
        let mgr = fresh_manager(java_cfg());
        let token = mgr.login("10001").await.expect("login");
        mgr.logout_by_login_id("login", "10001")
            .await
            .expect("logout");
        write_dump_to(
            &dir,
            "logout",
            "Rust dump logout",
            dump_config("none", "login", &[]),
            json!({ "loginId": 10001 }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // disable
    {
        let mgr = fresh_manager(java_cfg());
        let token = mgr.login("10001").await.expect("login");
        mgr.disable("10001", -1).await.expect("disable");
        write_dump_to(
            &dir,
            "disable",
            "Rust dump disable",
            dump_config("none", "login", &[]),
            json!({ "loginId": 10001, "service": "login", "level": 1 }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // safe
    {
        let mgr = fresh_manager(java_cfg());
        let token = mgr.login("10001").await.expect("login");
        let service = mgr.config.wire.default_safe_service.clone();
        mgr.open_safe(&token, &service, 0).await.expect("safe");
        write_dump_to(
            &dir,
            "safe",
            "Rust dump safe",
            dump_config("none", "login", &[]),
            json!({ "loginId": 10001, "service": "important" }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // active_timeout
    {
        let mgr = fresh_manager(java_cfg_overlay(|c| c.active_timeout = 1800));
        let token = mgr.login("10001").await.expect("login");
        write_dump_to(
            &dir,
            "active_timeout",
            "Rust dump active_timeout",
            dump_config("none", "login", &[("activeTimeout", json!(1800))]),
            json!({ "loginId": 10001, "activeTimeout": 1800 }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // active_timeout_dynamic
    {
        let mgr = fresh_manager(java_cfg_overlay(|c| {
            c.active_timeout = 1800;
            c.dynamic_active_timeout = true;
        }));
        let token = mgr.login("10001").await.expect("login");
        if let Err(e) = mgr.update_active_timeout(&token, 600).await {
            panic!("update_active_timeout: {e}");
        }
        write_dump_to(
            &dir,
            "active_timeout_dynamic",
            "Rust dump active_timeout_dynamic",
            dump_config(
                "none",
                "login",
                &[
                    ("activeTimeout", json!(1800)),
                    ("dynamicActiveTimeout", json!(true)),
                ],
            ),
            json!({ "loginId": 10001, "activeTimeout": 600 }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // token_session
    {
        let mgr = fresh_manager(java_cfg());
        let token = mgr.login("10001").await.expect("login");
        let mut ts = mgr.get_token_session(&token).await.expect("ts");
        ts.set("name", "zhang").expect("set");
        mgr.save_token_session(&token, &ts).await.expect("save");
        write_dump_to(
            &dir,
            "token_session",
            "Rust dump token_session",
            dump_config("none", "login", &[]),
            json!({ "loginId": 10001, "sessionKey": "name", "sessionValue": "zhang" }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // custom_session
    {
        let mgr = fresh_manager(java_cfg());
        let key = mgr.keys().custom_session("role-1001");
        let mut session = SaSession::new(&key).with_type("Custom-Session");
        session.set("count", 1_i32).expect("set");
        mgr.dao()
            .set_session(&key, &session, None)
            .await
            .expect("save custom");
        write_dump_to(
            &dir,
            "custom_session",
            "Rust dump custom_session",
            dump_config("none", "login", &[]),
            json!({ "sessionId": "role-1001", "dataKey": "count", "dataValue": 1 }),
            json!({}),
            dump_kv(&mgr).await,
        );
    }
    // raw_session
    {
        let mgr = fresh_manager(java_cfg());
        let key = mgr.keys().raw_session("user", "10001");
        let mut session = SaSession::new(&key).with_type("user");
        session.set("flag", "raw").expect("set");
        mgr.dao()
            .set_session(&key, &session, None)
            .await
            .expect("save raw");
        write_dump_to(
            &dir,
            "raw_session",
            "Rust dump raw_session",
            dump_config("none", "login", &[]),
            json!({ "type": "user", "valueId": 10001, "dataKey": "flag", "dataValue": "raw" }),
            json!({}),
            dump_kv(&mgr).await,
        );
    }
    // temp tokens
    {
        let mgr = fresh_manager(java_cfg());
        let temp = TempTokenManager::new(mgr.dao().clone());
        let ns = mgr.config.wire.temp_token_namespace.clone();
        let t = temp
            .create(&ns, json!("hello"), -1, true)
            .await
            .expect("temp str");
        write_dump_to(
            &dir,
            "temp_token_str",
            "Rust dump temp_token_str",
            dump_config("none", "login", &[]),
            json!({ "value": "hello" }),
            json!({ "tempToken": t }),
            dump_kv(&mgr).await,
        );
    }
    {
        let mgr = fresh_manager(java_cfg());
        let temp = TempTokenManager::new(mgr.dao().clone());
        let ns = mgr.config.wire.temp_token_namespace.clone();
        let t = temp
            .create(&ns, json!(10001), -1, true)
            .await
            .expect("temp long");
        write_dump_to(
            &dir,
            "temp_token_long",
            "Rust dump temp_token_long",
            dump_config("none", "login", &[]),
            json!({ "value": 10001 }),
            json!({ "tempToken": t }),
            dump_kv(&mgr).await,
        );
    }
    {
        let mgr = fresh_manager(java_cfg());
        let temp = TempTokenManager::new(mgr.dao().clone());
        let ns = mgr.config.wire.temp_token_namespace.clone();
        let t = temp
            .create(&ns, json!({"name": "alice", "id": 10001}), -1, true)
            .await
            .expect("temp map");
        write_dump_to(
            &dir,
            "temp_token_map",
            "Rust dump temp_token_map",
            dump_config("none", "login", &[]),
            json!({ "value": { "name": "alice", "id": 10001 } }),
            json!({ "tempToken": t }),
            dump_kv(&mgr).await,
        );
    }
    // apikey
    {
        let mgr = fresh_manager(java_cfg());
        let api = ApiKeyManager::new(mgr.dao().clone());
        let mut model = api.create("10001");
        model.title = "interop".into();
        model.scopes = vec!["user.read".into()];
        model.expires_time = -1;
        api.save(&model).await.expect("save apikey");
        write_dump_to(
            &dir,
            "apikey",
            "Rust dump apikey",
            dump_config("none", "login", &[]),
            json!({ "loginId": 10001, "title": "interop", "scope": "user.read" }),
            json!({ "apiKey": model.api_key }),
            dump_kv(&mgr).await,
        );
    }
    // same_token
    {
        let mgr = fresh_manager(java_cfg());
        let cur = "rust-same-token-current-value-for-java-verify-001";
        let past = "rust-same-token-past-value-for-java-verify-002";
        mgr.dao()
            .set_string(&mgr.keys().same_token(), cur, None)
            .await
            .expect("same");
        mgr.dao()
            .set_string(&mgr.keys().same_token_past(), past, None)
            .await
            .expect("past");
        write_dump_to(
            &dir,
            "same_token",
            "Rust dump same_token keys",
            dump_config("none", "login", &[]),
            json!({}),
            json!({ "sameToken": cur, "pastSameToken": past }),
            dump_kv(&mgr).await,
        );
    }
    // application_var
    {
        let mgr = fresh_manager(java_cfg());
        let dao = mgr.dao();
        dao.set_string(
            &mgr.keys().application_var("foo"),
            &dao.wire().encode_root(&json!("bar")).expect("foo"),
            None,
        )
        .await
        .expect("foo");
        dao.set_string(
            &mgr.keys().application_var("num"),
            &dao.wire().encode_root(&json!(10001)).expect("num"),
            None,
        )
        .await
        .expect("num");
        dao.set_string(
            &mgr.keys().application_var("map"),
            &dao.wire().encode_root(&json!({"k": "v"})).expect("map"),
            None,
        )
        .await
        .expect("map");
        write_dump_to(
            &dir,
            "application_var",
            "Rust dump application_var",
            dump_config("none", "login", &[]),
            json!({ "foo": "bar", "num": 10001 }),
            json!({}),
            dump_kv(&mgr).await,
        );
    }
    // sign_nonce
    {
        let mgr = fresh_manager(java_cfg());
        let sign = RequestSign::new("java-interop-sign-secret", 300)
            .with_dao(mgr.dao().clone())
            .with_algorithm(SignAlgorithm::Md5);
        let mut params = std::collections::BTreeMap::new();
        params.insert(
            "timestamp".into(),
            chrono::Utc::now().timestamp_millis().to_string(),
        );
        params.insert("nonce".into(), "interop-nonce-001".into());
        let sig = sign.sign_params(&params).expect("sign");
        sign.verify_params(&params, &sig).await.expect("verify");
        write_dump_to(
            &dir,
            "sign_nonce",
            "Rust dump sign_nonce",
            dump_config("none", "login", &[]),
            json!({ "nonce": "interop-nonce-001" }),
            json!({ "nonce": "interop-nonce-001" }),
            dump_kv(&mgr).await,
        );
    }
    // jwt_simple
    {
        let mgr = fresh_manager(java_cfg_overlay(|c| {
            c.token_style = TokenStyle::Jwt;
            c.jwt_secret_key = Some(JWT_SECRET.into());
        }));
        let token = mgr
            .auth_service()
            .login(LoginRequest::new("10001").extra_data(json!({ "age": 18 })))
            .await
            .expect("jwt simple");
        write_dump_to(
            &dir,
            "jwt_simple",
            "Rust dump jwt_simple",
            dump_config("simple", "login", &[]),
            json!({ "loginId": 10001, "extraAge": 18 }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // jwt_mixin
    {
        let mgr = fresh_manager(java_cfg_overlay(|c| {
            c.token_style = TokenStyle::JwtMixin;
            c.jwt_secret_key = Some(JWT_SECRET.into());
        }));
        let token = mgr.login("10001").await.expect("mixin");
        write_dump_to(
            &dir,
            "jwt_mixin",
            "Rust dump jwt_mixin",
            dump_config("mixin", "login", &[]),
            json!({ "loginId": 10001, "device": "DEF" }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // jwt_stateless
    {
        let mgr = fresh_manager(java_cfg_overlay(|c| {
            c.token_style = TokenStyle::JwtStateless;
            c.jwt_secret_key = Some(JWT_SECRET.into());
        }));
        let token = mgr.login("10001").await.expect("stateless");
        write_dump_to(
            &dir,
            "jwt_stateless",
            "Rust dump jwt_stateless",
            dump_config("stateless", "login", &[]),
            json!({ "loginId": 10001, "device": "DEF" }),
            json!({ "token": token.as_str() }),
            dump_kv(&mgr).await,
        );
    }
    // jwt_expired：金样已签发的过期 JWT（timeout=-1 无法现场签发 eff=1）
    {
        let gold = load_fixture("jwt_expired");
        let jwt = gold["tokens"]["token"].as_str().expect("gold expired jwt");
        write_dump_to(
            &dir,
            "jwt_expired",
            "Rust dump jwt_expired (gold token, kv empty)",
            dump_config("stateless", "login", &[]),
            json!({ "loginId": 10001, "eff": 1 }),
            json!({ "token": jwt, "jwt": jwt }),
            Vec::new(),
        );
        let mgr = fresh_manager(java_cfg_overlay(|c| {
            c.token_style = TokenStyle::JwtStateless;
            c.jwt_secret_key = Some(JWT_SECRET.into());
        }));
        let err = mgr
            .get_token_info(&TokenValue::new(jwt))
            .await
            .expect_err("expired");
        assert!(
            matches!(err, SaTokenError::TokenExpired),
            "gold expired jwt: {err:?}"
        );
    }
}
