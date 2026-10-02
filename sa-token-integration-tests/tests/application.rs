//! SaApplication global KV.

mod common;

use common::setup;
use sa_token_core::StpUtil;
use sa_token_core::application::SaApplication;
use serial_test::serial;

fn init_stp() {
    let _mgr = setup::shared_manager();
}

#[tokio::test]
#[serial]
async fn test_application_set_get_delete() {
    init_stp();
    let key = setup::unique_login_id("app");
    assert!(!SaApplication::exists(&key).await.expect("exists"));

    SaApplication::set(&key, "hello", 3600).await.expect("set");
    assert!(SaApplication::exists(&key).await.expect("exists after set"));
    let value: Option<String> = SaApplication::get(&key).await.expect("get");
    assert_eq!(value.as_deref(), Some("hello"));

    SaApplication::delete(&key).await.expect("delete");
    assert!(
        !SaApplication::exists(&key)
            .await
            .expect("exists after delete"),
        "deleted key must not exist"
    );
    let after: Option<String> = SaApplication::get(&key).await.expect("get after delete");
    assert_eq!(after, None);
}

#[tokio::test]
#[serial]
async fn test_application_ttl_negative_is_permanent() {
    init_stp();
    let key = setup::unique_login_id("app_perm");
    SaApplication::set(&key, "forever", -1)
        .await
        .expect("set permanent");
    assert!(SaApplication::exists(&key).await.expect("exists"));
    let value: Option<String> = SaApplication::get(&key).await.expect("get");
    assert_eq!(value.as_deref(), Some("forever"));

    let mgr = StpUtil::try_get_manager().expect("manager");
    let storage_key = mgr.keys().application_var(&key);
    let ttl = mgr.dao().ttl(&storage_key).await.expect("ttl");
    assert!(ttl.is_none(), "ttl<0 must be stored as permanent (no TTL)");
}
