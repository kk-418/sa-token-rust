//! 宏编译与展开 smoke test

use sa_token_core::SaTokenResult;
use sa_token_macro::*;

#[sa_check_safe]
async fn need_safe_default() -> SaTokenResult<()> {
    Ok(())
}

#[sa_check_safe("pay")]
async fn need_safe_pay() -> SaTokenResult<()> {
    Ok(())
}

#[sa_check_disable]
async fn need_not_disabled() -> SaTokenResult<()> {
    Ok(())
}

#[sa_check_disable("login", level = 1)]
async fn need_not_disabled_level() -> SaTokenResult<()> {
    Ok(())
}

#[sa_check_or(permission = "admin:read", role = "admin")]
async fn need_or_auth() -> SaTokenResult<()> {
    Ok(())
}

#[sa_check_or(login, permission = "user:read")]
async fn need_or_login_or_perm() -> SaTokenResult<()> {
    Ok(())
}

#[sa_check_http_digest]
async fn need_digest_default() -> SaTokenResult<()> {
    Ok(())
}

#[sa_check_http_digest("user:pass")]
async fn need_digest_account() -> SaTokenResult<()> {
    Ok(())
}

#[sa_check_http_digest(username = "user", password = "pass", realm = "Sa-Token")]
async fn need_digest_named() -> SaTokenResult<()> {
    Ok(())
}

#[sa_check_or(digest = "user:pass")]
async fn need_or_digest() -> SaTokenResult<()> {
    Ok(())
}

#[sa_check_or(basic = "user:pass", digest = "user:pass")]
async fn need_or_basic_or_digest() -> SaTokenResult<()> {
    Ok(())
}
