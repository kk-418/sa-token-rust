//! Java parity: Vague permission matching (`user:*` covers `user:profile:edit`).

mod common;

use common::setup;
use sa_token_core::SaTokenConfig;
use sa_token_core::config::PermissionMatchMode;

#[tokio::test]
async fn vague_mode_star_covers_three_segment() {
    let config = SaTokenConfig::builder()
        .timeout(3600)
        .permission_match_mode(PermissionMatchMode::Vague)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let id = setup::unique_login_id("vague");
    mgr.set_permissions(&id, vec!["user:*".into()])
        .await
        .expect("set_permissions");
    let ok = mgr
        .authz_service()
        .has_permission("default", &id, "user:profile:edit")
        .await
        .expect("has_permission");
    assert!(ok, "Vague mode: user:* must cover user:profile:edit");
}

#[tokio::test]
async fn ant_mode_star_does_not_cover_three_segment() {
    let config = SaTokenConfig::builder()
        .timeout(3600)
        .permission_match_mode(PermissionMatchMode::Ant)
        .build_config();
    let mgr = setup::fresh_manager_with_config(config);
    let id = setup::unique_login_id("ant");
    mgr.set_permissions(&id, vec!["user:*".into()])
        .await
        .expect("set_permissions");
    let ok = mgr
        .authz_service()
        .has_permission("default", &id, "user:profile:edit")
        .await
        .expect("has_permission");
    assert!(!ok, "Ant mode: user:* must not cover user:profile:edit");
}
