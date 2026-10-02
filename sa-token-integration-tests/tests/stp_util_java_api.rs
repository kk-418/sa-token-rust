//! Java StpUtil 公开 API 对齐：replaced / disable / anon session / extra / device.

mod common;

use common::setup;
use sa_token_core::StpUtil;
use sa_token_core::token::TokenValue;
use serial_test::serial;

fn init_stp() {
    let _mgr = setup::shared_manager();
}

#[tokio::test]
#[serial]
async fn replaced_by_token_marks_account_replaced() {
    init_stp();
    let id = setup::unique_login_id("rep_tok");
    let token = StpUtil::login(&id).await.expect("login");
    StpUtil::replaced_by_token(&token)
        .await
        .expect("replaced_by_token");
    setup::assert_err(StpUtil::get_token_info(&token).await, "replaced");
    assert!(
        !StpUtil::is_login(&token).await,
        "replaced token must not be logged in"
    );
}

#[tokio::test]
#[serial]
async fn replaced_login_id_kicks_all_tokens() {
    init_stp();
    let id = setup::unique_login_id("rep_acc");
    let t1 = StpUtil::login(&id).await.expect("t1");
    let t2 = StpUtil::login(&id).await.expect("t2");
    StpUtil::replaced(&id).await.expect("replaced");
    setup::assert_err(StpUtil::get_token_info(&t1).await, "replaced");
    setup::assert_err(StpUtil::get_token_info(&t2).await, "replaced");
}

#[tokio::test]
#[serial]
async fn get_disable_time_and_is_disable() {
    init_stp();
    let id = setup::unique_login_id("dis");
    assert_eq!(
        StpUtil::get_disable_time(&id).await.expect("not banned"),
        -2
    );
    assert!(!StpUtil::is_disable(&id).await.expect("is_disable false"));

    StpUtil::disable(&id, 120).await.expect("disable");
    let remaining = StpUtil::get_disable_time(&id).await.expect("ttl");
    assert!(remaining > 0, "expected remaining > 0, got {remaining}");
    assert!(StpUtil::is_disable(&id).await.expect("is_disable true"));

    StpUtil::untie_disable_default(&id).await.expect("untie");
    assert_eq!(StpUtil::get_disable_time(&id).await.expect("cleared"), -2);
    assert!(!StpUtil::is_disable(&id).await.expect("cleared bool"));
}

#[tokio::test]
#[serial]
async fn get_anon_token_session_set_get_without_login() {
    init_stp();
    let token = TokenValue::new(setup::unique_login_id("anon-tok"));
    let mut session = StpUtil::get_anon_token_session(&token)
        .await
        .expect("anon session");
    session.set("k", "v").expect("set");
    StpUtil::save_token_session(&token, &session)
        .await
        .expect("save");
    let loaded = StpUtil::get_anon_token_session(&token)
        .await
        .expect("reload");
    assert_eq!(loaded.get::<String>("k").as_deref(), Some("v"));
}

#[tokio::test]
#[serial]
async fn is_trust_device_id_after_terminal_device_id() {
    init_stp();
    let id = setup::unique_login_id("trust");
    StpUtil::login(&id).await.expect("login");
    let mut session = StpUtil::get_session(&id).await.expect("session");
    assert!(
        !session.terminal_list.is_empty(),
        "login must record a terminal"
    );
    session.terminal_list[0].device_id = Some("dev-trust-1".to_string());
    StpUtil::save_session(&session).await.expect("save");
    assert!(
        StpUtil::is_trust_device_id(&id, "dev-trust-1")
            .await
            .expect("trust")
    );
    assert!(
        !StpUtil::is_trust_device_id(&id, "dev-other")
            .await
            .expect("untrusted")
    );
}

#[tokio::test]
#[serial]
async fn get_token_name_non_empty() {
    init_stp();
    let name = StpUtil::get_token_name().expect("token_name");
    assert!(!name.is_empty(), "token_name must be non-empty");
}

#[tokio::test]
#[serial]
async fn get_extra_read_write() {
    init_stp();
    let id = setup::unique_login_id("extra");
    let token = StpUtil::login(&id).await.expect("login");
    StpUtil::set_extra_data(&token, serde_json::json!({"ip": "10.0.0.1"}))
        .await
        .expect("set extra");
    let ip = StpUtil::get_extra(&token, "ip").await.expect("get extra");
    assert_eq!(ip, Some(serde_json::json!("10.0.0.1")));
    assert_eq!(
        StpUtil::get_extra(&token, "missing")
            .await
            .expect("missing"),
        None
    );
}
