//! API Key 集成测试（对齐 Java `SaApiKeyTemplate`）。

mod common;

use common::setup;
use sa_token_core::{ApiKeyManager, SaTokenContext, SaTokenError};

fn api_of(mgr: &sa_token_core::SaTokenManager) -> ApiKeyManager {
    ApiKeyManager::new(mgr)
}

#[tokio::test]
async fn create_save_check_success() {
    let mgr = setup::fresh_manager();
    let api = api_of(&mgr);
    let login_id = setup::unique_login_id("ak");
    let model = api.create(&login_id);
    api.save(&model).await.expect("save");
    let checked = api.check(&model.api_key).await.expect("check");
    assert_eq!(checked.login_id, login_id);
    assert_eq!(checked.api_key, model.api_key);
    assert!(checked.is_valid);
}

#[tokio::test]
async fn check_invalid_when_tampered_or_missing() {
    let mgr = setup::fresh_manager();
    let api = api_of(&mgr);
    let login_id = setup::unique_login_id("ak");
    let model = api.create(&login_id);
    api.save(&model).await.expect("save");

    let mut tampered = model.api_key.clone();
    let last = tampered.pop().unwrap_or('0');
    tampered.push(if last == '0' { '1' } else { '0' });
    let err = api.check(&tampered).await.expect_err("tampered");
    assert!(
        matches!(err, SaTokenError::ApiKeyInvalid),
        "tampered key, got {err:?}"
    );

    let err = api
        .check("AK-does-not-exist-00000000000000000000")
        .await
        .expect_err("missing");
    assert!(
        matches!(err, SaTokenError::ApiKeyInvalid),
        "missing key, got {err:?}"
    );
}

#[tokio::test]
async fn check_expired_via_storage_clock() {
    let mgr = setup::fresh_manager();
    let api = api_of(&mgr);
    let login_id = setup::unique_login_id("ak");
    let model = api.create(&login_id);
    api.save(&model).await.expect("save");

    let mut loaded = api
        .get(&model.api_key)
        .await
        .expect("get")
        .expect("model in storage");
    loaded.expires_time = chrono::Utc::now().timestamp_millis() - 5_000;
    let key = format!("{}:apikey:{}", mgr.config.token_name, loaded.api_key);
    let raw = mgr.config.encode(&loaded).expect("encode");
    mgr.storage()
        .set(&key, &raw, None)
        .await
        .expect("storage set");

    let err = api.check(&model.api_key).await.expect_err("expired");
    assert!(
        matches!(err, SaTokenError::ApiKeyExpired),
        "expired key, got {err:?}"
    );
}

#[tokio::test]
async fn check_disabled_when_is_valid_false() {
    let mgr = setup::fresh_manager();
    let api = api_of(&mgr);
    let login_id = setup::unique_login_id("ak");
    let mut model = api.create(&login_id);
    model.is_valid = false;
    api.save(&model).await.expect("save");
    let err = api.check(&model.api_key).await.expect_err("disabled");
    assert!(
        matches!(err, SaTokenError::ApiKeyDisabled),
        "disabled key, got {err:?}"
    );
}

#[tokio::test]
async fn delete_then_check_invalid() {
    let mgr = setup::fresh_manager();
    let api = api_of(&mgr);
    let login_id = setup::unique_login_id("ak");
    let model = api.create(&login_id);
    api.save(&model).await.expect("save");
    api.delete(&model.api_key).await.expect("delete");
    let err = api.check(&model.api_key).await.expect_err("deleted");
    assert!(
        matches!(err, SaTokenError::ApiKeyInvalid),
        "deleted key, got {err:?}"
    );
}

#[tokio::test]
async fn list_and_delete_by_login_id() {
    let mgr = setup::fresh_manager();
    let api = api_of(&mgr);
    let login_id = setup::unique_login_id("ak");
    let model = api.create(&login_id);
    api.save(&model).await.expect("save");

    let list = api.list_by_login_id(&login_id).await.expect("list");
    assert!(
        list.iter().any(|m| m.api_key == model.api_key),
        "list should contain the saved key"
    );

    api.delete_by_login_id(&login_id)
        .await
        .expect("delete_by_login_id");
    let list = api.list_by_login_id(&login_id).await.expect("list after");
    assert!(
        list.is_empty(),
        "list should be empty after delete_by_login_id"
    );
}

#[tokio::test]
async fn check_scope_and_requires_all() {
    let mgr = setup::fresh_manager();
    let api = api_of(&mgr);
    let login_id = setup::unique_login_id("ak");
    let mut model = api.create(&login_id);
    model.scopes = vec!["read".into(), "write".into()];
    api.save(&model).await.expect("save");

    api.check_scope(&model.api_key, &["read", "write"])
        .await
        .expect("and all present");
    assert!(api.has_scope(&model.api_key, &["read", "write"]).await);

    let err = api
        .check_scope(&model.api_key, &["read", "admin"])
        .await
        .expect_err("missing admin");
    assert!(
        matches!(err, SaTokenError::ApiKeyScopeDenied(ref s) if s == "admin"),
        "AND missing scope, got {err:?}"
    );
    assert!(!api.has_scope(&model.api_key, &["read", "admin"]).await);
}

#[tokio::test]
async fn check_scope_or_requires_any() {
    let mgr = setup::fresh_manager();
    let api = api_of(&mgr);
    let login_id = setup::unique_login_id("ak");
    let mut model = api.create(&login_id);
    model.scopes = vec!["read".into(), "write".into()];
    api.save(&model).await.expect("save");

    api.check_scope_or(&model.api_key, &["admin", "read"])
        .await
        .expect("or one present");
    assert!(api.has_scope_or(&model.api_key, &["admin", "read"]).await);

    let err = api
        .check_scope_or(&model.api_key, &["admin", "delete"])
        .await
        .expect_err("none present");
    assert!(
        matches!(err, SaTokenError::ApiKeyScopeDenied(_)),
        "OR none present, got {err:?}"
    );
    assert!(!api.has_scope_or(&model.api_key, &["admin", "delete"]).await);
}

#[tokio::test]
async fn current_login_id_from_context() {
    let mgr = setup::fresh_manager();
    let api = api_of(&mgr);
    let login_id = setup::unique_login_id("ak");
    let model = api.create(&login_id);
    api.save(&model).await.expect("save");

    SaTokenContext::clear();
    SaTokenContext::set_current(SaTokenContext::new());
    let key = model.api_key.clone();
    assert!(
        SaTokenContext::with_current_mut(|inner| {
            inner.auth_meta.params.insert("apikey".into(), key);
        })
        .is_some(),
        "context must be set"
    );
    let current = api.current_login_id().await.expect("current_login_id");
    assert_eq!(current, login_id);
    SaTokenContext::clear();
}
