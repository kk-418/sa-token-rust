//! Raw Session / Custom Session / is_trust_device_id.

mod common;

use common::setup;
use sa_token_core::SaTerminalInfo;
use sa_token_core::session::raw::{RawSession, SaSessionCustom};
use serial_test::serial;

fn init_stp() {
    let _mgr = setup::shared_manager();
}

#[tokio::test]
#[serial]
async fn test_raw_session_create_get_set_delete() {
    init_stp();
    let id = setup::unique_login_id("raw");
    assert!(
        !RawSession::is_exists("role", &id).await.expect("is_exists"),
        "missing session must not exist"
    );

    let mut session = RawSession::get_or_create("role", &id)
        .await
        .expect("get_or_create");
    assert_eq!(session.session_type, "role");
    assert_eq!(
        session.id,
        RawSession::session_id("role", &id).expect("session_id")
    );
    assert!(
        RawSession::is_exists("role", &id).await.expect("is_exists"),
        "created session must exist"
    );

    session.set("count", 1_i32).expect("set");
    RawSession::save(&session).await.expect("save");

    let loaded = RawSession::get("role", &id, false)
        .await
        .expect("get")
        .expect("created session must be present");
    assert_eq!(loaded.get::<i32>("count"), Some(1));
    assert_eq!(loaded.session_type, "role");

    RawSession::delete("role", &id).await.expect("delete");
    assert!(
        !RawSession::is_exists("role", &id).await.expect("is_exists"),
        "deleted session must not exist"
    );
    let after = RawSession::get("role", &id, false)
        .await
        .expect("get after delete");
    assert!(after.is_none(), "deleted session must not be readable");
}

#[tokio::test]
#[serial]
async fn test_raw_session_is_exists_false_when_missing() {
    init_stp();
    let id = setup::unique_login_id("raw_miss");
    assert!(!RawSession::is_exists("role", &id).await.expect("is_exists"));
    let none = RawSession::get("role", &id, false)
        .await
        .expect("get without create");
    assert!(none.is_none());
}

#[tokio::test]
#[serial]
async fn test_custom_session_isolated_from_role() {
    init_stp();
    let id = setup::unique_login_id("iso");

    let mut custom = SaSessionCustom::get_or_create(&id)
        .await
        .expect("custom create");
    custom.set("v", "custom").expect("set custom");
    SaSessionCustom::save(&custom).await.expect("save custom");
    assert_eq!(custom.session_type, "custom");
    assert!(
        SaSessionCustom::is_exists(&id)
            .await
            .expect("custom exists")
    );

    let mut role = RawSession::get_or_create("role", &id)
        .await
        .expect("role create");
    role.set("v", "role").expect("set role");
    RawSession::save(&role).await.expect("save role");

    let custom2 = SaSessionCustom::get_or_create(&id)
        .await
        .expect("reload custom");
    assert_eq!(custom2.get::<String>("v").as_deref(), Some("custom"));
    let role2 = RawSession::get_or_create("role", &id)
        .await
        .expect("reload role");
    assert_eq!(role2.get::<String>("v").as_deref(), Some("role"));

    SaSessionCustom::delete(&id).await.expect("delete custom");
    assert!(!SaSessionCustom::is_exists(&id).await.expect("custom gone"));
    assert!(
        RawSession::is_exists("role", &id)
            .await
            .expect("role still there"),
        "deleting custom must not drop role session"
    );
}

#[tokio::test]
#[serial]
async fn test_is_trust_device_id() {
    init_stp();
    let id = setup::unique_login_id("trust");
    let mut session = RawSession::get_or_create("role", &id)
        .await
        .expect("create");
    assert!(!session.is_trust_device_id(""));
    assert!(!session.is_trust_device_id("dev-1"));

    session.add_terminal(SaTerminalInfo::new("tok", "PC").with_device_id("dev-1"));
    RawSession::save(&session).await.expect("save");

    let loaded = RawSession::get_or_create("role", &id)
        .await
        .expect("reload");
    assert!(loaded.is_trust_device_id("dev-1"));
    assert!(!loaded.is_trust_device_id("dev-other"));
    assert!(!loaded.is_trust_device_id(""));
}
