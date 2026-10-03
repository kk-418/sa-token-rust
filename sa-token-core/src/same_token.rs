// Author: 金书记 | Author: Jin Shuji
//
//! Same-Token: shared secret for intra-cluster / gateway-to-service calls.
//! Same-Token：集群内 / 网关到服务 调用使用的共享口令。
//!
//! Current value plus one previous value (grace window) are both accepted.
//! 当前值与上一次值（宽限期）均视为有效。

use std::time::Duration;

use crate::compat::{OpaqueGen, SameTokenPastTtl};
use crate::error::{SaTokenError, SaTokenResult};
use crate::manager::SaTokenManager;
use crate::util::StpUtil;

/// Default header name.
/// 默认请求头名。
pub const DEFAULT_HEADER: &str = "SA-SAME-TOKEN";

fn ttl(timeout_secs: i64) -> Option<Duration> {
    if timeout_secs > 0 {
        Some(Duration::from_secs(timeout_secs as u64))
    } else {
        None
    }
}

fn generate_token(opaque_gen: OpaqueGen) -> SaTokenResult<String> {
    match opaque_gen {
        OpaqueGen::Native => crate::token::random_hex(32),
        OpaqueGen::Java => crate::token::random_alnum(64),
    }
}

/// Past-key TTL: full timeout, or remaining lifetime of the current token.
/// past 键 TTL：完整 timeout，或当前 token 的剩余寿命。
async fn past_ttl(
    manager: &SaTokenManager,
    cur_key: &str,
    full: Option<Duration>,
) -> SaTokenResult<Option<Duration>> {
    match manager.config.wire.same_token_past_ttl {
        SameTokenPastTtl::Full => Ok(full),
        SameTokenPastTtl::Remaining => manager.dao().ttl(cur_key).await,
    }
}

/// Read current Same-Token without creating one.
/// 读取当前 Same-Token（不自动创建）。
pub async fn get_token_nh() -> SaTokenResult<Option<String>> {
    let manager = StpUtil::try_get_manager()?;
    get_token_nh_on(manager).await
}

async fn get_token_nh_on(manager: &SaTokenManager) -> SaTokenResult<Option<String>> {
    let key = manager.keys().same_token();
    manager.dao().get_string(&key).await
}

/// Read past Same-Token (grace window).
/// 读取宽限期内的上一次 Same-Token。
pub async fn get_past_token_nh() -> SaTokenResult<Option<String>> {
    let manager = StpUtil::try_get_manager()?;
    get_past_token_nh_on(manager).await
}

async fn get_past_token_nh_on(manager: &SaTokenManager) -> SaTokenResult<Option<String>> {
    let key = manager.keys().same_token_past();
    manager.dao().get_string(&key).await
}

/// Get current token, creating one if missing.
/// 获取当前 token，不存在则创建。
pub async fn get_token() -> SaTokenResult<String> {
    if let Some(existing) = get_token_nh().await?
        && !existing.is_empty()
    {
        return Ok(existing);
    }
    refresh_token().await
}

/// Whether `token` equals current or past value (constant-time on equal length).
/// `token` 是否等于当前或宽限值（等长时恒定时间比较）。
pub async fn is_valid(token: &str) -> SaTokenResult<bool> {
    if token.is_empty() {
        return Ok(false);
    }
    let current = get_token_nh().await?;
    if current
        .as_deref()
        .is_some_and(|c| crate::http_basic::ct_eq(c.as_bytes(), token.as_bytes()))
    {
        return Ok(true);
    }
    let past = get_past_token_nh().await?;
    Ok(past
        .as_deref()
        .is_some_and(|p| crate::http_basic::ct_eq(p.as_bytes(), token.as_bytes())))
}

/// Refresh: move current → past, CAS-write a new current.
/// 刷新：当前值写入 past，再用 CAS 写入新的当前值。
pub async fn refresh_token() -> SaTokenResult<String> {
    let manager = StpUtil::try_get_manager()?;
    refresh_token_on(manager).await
}

async fn refresh_token_on(manager: &SaTokenManager) -> SaTokenResult<String> {
    let timeout = manager.config.same_token_timeout;
    let ttl_opt = ttl(timeout);
    let dao = manager.dao();
    let cur_key = manager.keys().same_token();
    let past_key = manager.keys().same_token_past();

    let current = dao.get_string(&cur_key).await?;
    if let Some(ref cur) = current
        && !cur.is_empty()
    {
        let past = past_ttl(manager, &cur_key, ttl_opt).await?;
        dao.set_string(&past_key, cur, past).await?;
    }

    let next = generate_token(manager.config.wire.opaque_gen)?;
    let expected = current.as_deref().filter(|s| !s.is_empty());
    let won = dao.cas(&cur_key, expected, &next, ttl_opt).await?;
    if won {
        return Ok(next);
    }
    // Another instance won; return whatever is stored so callers do not split the cluster secret.
    // 另一实例已写入；返回存储中的值，避免集群共享口令分叉。
    dao.get_string(&cur_key)
        .await?
        .filter(|s| !s.is_empty())
        .ok_or(SaTokenError::SameTokenInvalid)
}

/// Check a raw token string.
/// 校验原始 token 字符串。
pub async fn check_token(token: &str) -> SaTokenResult<()> {
    if is_valid(token).await? {
        Ok(())
    } else {
        Err(SaTokenError::SameTokenInvalid)
    }
}

/// Check the Same-Token captured on the current request.
/// 校验当前请求上下文中捕获的 Same-Token。
pub async fn check_current_request() -> SaTokenResult<()> {
    let value = crate::context::SaTokenContext::try_current()
        .and_then(|ctx| ctx.auth_meta().same_token)
        .unwrap_or_default();
    check_token(&value).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaTokenConfig;
    use sa_token_storage_memory::MemoryStorage;
    use std::sync::Arc;
    use std::time::Duration;

    fn manager_with(past: SameTokenPastTtl, timeout: i64) -> SaTokenManager {
        let mut cfg = SaTokenConfig::default();
        cfg.same_token_timeout = timeout;
        cfg.wire.same_token_past_ttl = past;
        SaTokenManager::new(Arc::new(MemoryStorage::new()), cfg)
    }

    #[tokio::test]
    async fn full_past_ttl_uses_complete_timeout() {
        let mgr = manager_with(SameTokenPastTtl::Full, 86400);
        let dao = mgr.dao();
        let cur_key = mgr.keys().same_token();
        dao.set_string(&cur_key, "old", Some(Duration::from_secs(10)))
            .await
            .unwrap();
        refresh_token_on(&mgr).await.unwrap();
        let past_ttl = dao
            .ttl(&mgr.keys().same_token_past())
            .await
            .unwrap()
            .expect("past ttl");
        assert!(
            past_ttl.as_secs() > 100,
            "Full must copy the configured timeout, got {}",
            past_ttl.as_secs()
        );
    }

    #[tokio::test]
    async fn remaining_past_ttl_uses_current_remaining() {
        let mgr = manager_with(SameTokenPastTtl::Remaining, 86400);
        let dao = mgr.dao();
        let cur_key = mgr.keys().same_token();
        dao.set_string(&cur_key, "old", Some(Duration::from_secs(10)))
            .await
            .unwrap();
        refresh_token_on(&mgr).await.unwrap();
        let past_ttl = dao
            .ttl(&mgr.keys().same_token_past())
            .await
            .unwrap()
            .expect("past ttl");
        assert!(
            past_ttl.as_secs() <= 10,
            "Remaining must copy leftover lifetime, got {}",
            past_ttl.as_secs()
        );
        assert_eq!(
            dao.get_string(&mgr.keys().same_token_past())
                .await
                .unwrap()
                .as_deref(),
            Some("old")
        );
    }

    #[tokio::test]
    async fn java_keys_are_var_same_token_and_past_same_token() {
        let mut cfg = SaTokenConfig::java_compatible();
        cfg.same_token_timeout = -1;
        let mgr = SaTokenManager::new(Arc::new(MemoryStorage::new()), cfg);
        assert_eq!(mgr.keys().same_token(), "satoken:var:same-token");
        assert_eq!(mgr.keys().same_token_past(), "satoken:var:past-same-token");
        let first = refresh_token_on(&mgr).await.unwrap();
        let second = refresh_token_on(&mgr).await.unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|b| b.is_ascii_alphanumeric()));
        assert_eq!(second.len(), 64);
        assert_ne!(first, second);
        assert_eq!(
            get_past_token_nh_on(&mgr).await.unwrap().as_deref(),
            Some(first.as_str())
        );
        assert_eq!(
            get_token_nh_on(&mgr).await.unwrap().as_deref(),
            Some(second.as_str())
        );
        assert!(
            mgr.dao()
                .ttl(&mgr.keys().same_token())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            mgr.dao()
                .ttl(&mgr.keys().same_token_past())
                .await
                .unwrap()
                .is_none()
        );
    }
}
