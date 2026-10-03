//! 临时 Token / API Key / Same-Token / 应用变量 / nonce / safe / disable / custom session 键形状。

mod common;

use common::java_interop::{
    dump_config, fresh_manager, get_raw, inject_kv, java_config, load_fixture, maybe_dump,
};
use sa_token_core::{
    ApiKeyManager, RequestSign, SaSession, TempTokenManager, compat::SignAlgorithm,
};
use serde_json::json;

#[tokio::test]
async fn temp_token_java_raw_quoted_string_key() {
    let mgr = fresh_manager(java_config());
    let temp = TempTokenManager::new(mgr.dao().clone());
    let ns = mgr.config.wire.temp_token_namespace.clone();
    assert_eq!(ns, "temp-token");
    let token = temp
        .create(&ns, json!("hello"), -1, true)
        .await
        .expect("create");
    let key = mgr.keys().temp_token(&ns, &token);
    assert_eq!(key, format!("satoken:temp-token:{token}"));
    let body = get_raw(&mgr, &key).await.expect("body");
    assert_eq!(body, r#""hello""#);

    maybe_dump(
        &mgr,
        "temp_token_str",
        "Rust temp_token JavaRaw quoted str",
        dump_config("none", "login", &[]),
        json!({ "value": "hello" }),
        json!({ "tempToken": token }),
    )
    .await;
}

#[tokio::test]
async fn api_key_java_model_has_class() {
    let mgr = fresh_manager(java_config());
    let api = ApiKeyManager::new(mgr.dao().clone());
    let mut model = api.create("10001");
    model.title = "interop".into();
    model.scopes = vec!["user.read".into()];
    model.expires_time = -1;
    api.save(&model).await.expect("save");
    let key = api.save_key(&model.api_key);
    assert_eq!(key, format!("satoken:apikey:{}", model.api_key));
    let raw = get_raw(&mgr, &key).await.expect("model json");
    assert!(
        raw.contains("cn.dev33.satoken.apikey.model.ApiKeyModel"),
        "@class ApiKeyModel, got {raw}"
    );
    let checked = api.check(&model.api_key).await.expect("check");
    assert_eq!(checked.login_id, "10001");

    maybe_dump(
        &mgr,
        "apikey",
        "Rust api_key JavaModel",
        dump_config("none", "login", &[]),
        json!({ "loginId": 10001, "title": "interop", "scope": "user.read" }),
        json!({ "apiKey": model.api_key }),
    )
    .await;
}

#[tokio::test]
async fn same_token_key_is_satoken_var_same_token() {
    let mgr = fresh_manager(java_config());
    assert_eq!(mgr.keys().same_token(), "satoken:var:same-token");
    assert_eq!(mgr.keys().same_token_past(), "satoken:var:past-same-token");
    mgr.dao()
        .set_string(&mgr.keys().same_token(), "cur-token", None)
        .await
        .expect("set current");
    mgr.dao()
        .set_string(&mgr.keys().same_token_past(), "past-token", None)
        .await
        .expect("set past");
    assert_eq!(
        get_raw(&mgr, "satoken:var:same-token").await.as_deref(),
        Some("cur-token")
    );

    maybe_dump(
        &mgr,
        "same_token",
        "Rust same_token key shape",
        dump_config("none", "login", &[]),
        json!({}),
        json!({
            "sameToken": "cur-token",
            "pastSameToken": "past-token"
        }),
    )
    .await;
}

#[tokio::test]
async fn application_var_map_has_no_class() {
    let mgr = fresh_manager(java_config());
    let dao = mgr.dao();
    let map_raw = dao
        .wire()
        .encode_root(&json!({"k": "v"}))
        .expect("encode map");
    assert_eq!(map_raw, r#"{"k":"v"}"#);
    assert!(!map_raw.contains("@class"));
    dao.set_string(&mgr.keys().application_var("map"), &map_raw, None)
        .await
        .expect("set map");
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
    assert_eq!(mgr.keys().application_var("foo"), "satoken:var:foo");
    assert_eq!(
        get_raw(&mgr, "satoken:var:foo").await.as_deref(),
        Some("\"bar\"")
    );
    assert_eq!(
        get_raw(&mgr, "satoken:var:num").await.as_deref(),
        Some("10001")
    );

    maybe_dump(
        &mgr,
        "application_var",
        "Rust application_var JavaRoot",
        dump_config("none", "login", &[]),
        json!({ "foo": "bar", "num": 10001 }),
        json!({}),
    )
    .await;
}

#[tokio::test]
async fn sign_nonce_value_equals_nonce() {
    let mgr = fresh_manager(java_config());
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
    let key = mgr.keys().sign_nonce("interop-nonce-001");
    assert_eq!(key, "satoken:sign:nonce:interop-nonce-001");
    assert_eq!(
        get_raw(&mgr, &key).await.as_deref(),
        Some("interop-nonce-001")
    );

    maybe_dump(
        &mgr,
        "sign_nonce",
        "Rust sign_nonce value=nonce",
        dump_config("none", "login", &[]),
        json!({ "nonce": "interop-nonce-001" }),
        json!({ "nonce": "interop-nonce-001" }),
    )
    .await;
}

#[tokio::test]
async fn safe_and_disable_key_shapes() {
    let mgr = fresh_manager(java_config());
    let token = mgr.login("10001").await.expect("login");
    mgr.disable("10001", -1).await.expect("disable");
    mgr.open_safe(&token, "important", 0)
        .await
        .expect("open_safe");
    assert_eq!(
        mgr.keys().disable("login", "10001", "login"),
        "satoken:login:disable:login:10001"
    );
    assert_eq!(
        mgr.keys()
            .safe_with_type("login", token.as_str(), "important"),
        format!("satoken:login:safe:important:{}", token.as_str())
    );
    assert_eq!(
        get_raw(&mgr, "satoken:login:disable:login:10001")
            .await
            .as_deref(),
        Some("1")
    );
    assert_eq!(
        get_raw(
            &mgr,
            &format!("satoken:login:safe:important:{}", token.as_str())
        )
        .await
        .as_deref(),
        Some("SAFE_AUTH_SAVE_VALUE")
    );
}

#[tokio::test]
async fn custom_session_key_shape() {
    let mgr = fresh_manager(java_config());
    let key = mgr.keys().custom_session("role-1001");
    assert_eq!(key, "satoken:custom:session:role-1001");
    let mut session = SaSession::new(&key).with_type("Custom-Session");
    session.set("count", 1_i32).expect("set");
    mgr.dao()
        .set_session(&key, &session, None)
        .await
        .expect("save");
    let raw = get_raw(&mgr, &key).await.expect("json");
    assert!(raw.contains("Custom-Session"));
    assert!(raw.contains("\"@class\""));

    maybe_dump(
        &mgr,
        "custom_session",
        "Rust custom_session key",
        dump_config("none", "login", &[]),
        json!({ "sessionId": "role-1001", "dataKey": "count", "dataValue": 1 }),
        json!({}),
    )
    .await;
}

#[tokio::test]
async fn gold_same_token_and_application_inject() {
    let mgr = fresh_manager(java_config());
    let fx = load_fixture("same_token");
    inject_kv(&mgr, &fx).await;
    assert_eq!(
        get_raw(&mgr, "satoken:var:same-token").await.as_deref(),
        fx["tokens"]["sameToken"].as_str()
    );
    assert_eq!(
        get_raw(&mgr, "satoken:var:past-same-token")
            .await
            .as_deref(),
        fx["tokens"]["pastSameToken"].as_str()
    );

    let mgr2 = fresh_manager(java_config());
    let fx2 = load_fixture("application_var");
    inject_kv(&mgr2, &fx2).await;
    let map_raw = get_raw(&mgr2, "satoken:var:map").await.expect("map");
    let decoded = mgr2
        .dao()
        .wire()
        .decode_root(&map_raw)
        .expect("decode_root");
    assert_eq!(decoded["k"].as_str(), Some("v"));
    assert!(!map_raw.contains("@class"));
}

#[tokio::test]
async fn gold_sign_nonce_value_is_nonce() {
    let mgr = fresh_manager(java_config());
    let fx = load_fixture("sign_nonce");
    inject_kv(&mgr, &fx).await;
    let nonce = fx["tokens"]["nonce"].as_str().expect("nonce");
    let key = mgr.keys().sign_nonce(nonce);
    assert_eq!(get_raw(&mgr, &key).await.as_deref(), Some(nonce));
}
