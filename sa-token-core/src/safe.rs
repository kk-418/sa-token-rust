// Author: 金书记
//
//! Secondary authentication (safe window).
//! 二级认证（安全窗口）。

use std::time::Duration;

use crate::error::{SaTokenError, SaTokenResult};
use crate::manager::SaTokenManager;
use crate::token::TokenValue;

/// Default secondary-auth service id (native).
/// 默认二级认证业务标识（原生）。
pub const DEFAULT_SAFE_SERVICE: &str = "";

/// Native secondary-auth occupancy value.
/// 原生二级认证存储标记值。
pub const SAFE_AUTH_VALUE: &str = "ok";

/// Java `SaStrategy.safeAuthSaveValue`.
const JAVA_SAFE_AUTH_VALUE: &str = "SAFE_AUTH_SAVE_VALUE";

impl SaTokenManager {
    fn safe_key(&self, token: &str, service: &str) -> String {
        self.keys()
            .safe_with_type(&self.config.wire.default_login_type, token, service)
    }

    fn safe_key_with_type(&self, login_type: &str, token: &str, service: &str) -> String {
        self.keys().safe_with_type(login_type, token, service)
    }

    #[inline]
    fn is_safe_marker(&self, value: &str) -> bool {
        value == SAFE_AUTH_VALUE
            || value == JAVA_SAFE_AUTH_VALUE
            || value == self.config.wire.safe_value
    }

    /// 为指定 token 开启二级认证
    pub async fn open_safe(
        &self,
        token: &TokenValue,
        service: &str,
        safe_time: i64,
    ) -> SaTokenResult<()> {
        let login_type = self.config.wire.default_login_type.clone();
        self.open_safe_with_type(&login_type, token, service, safe_time)
            .await
    }

    /// Open secondary auth for a login type.
    /// 按登录类型开启二级认证。
    pub async fn open_safe_with_type(
        &self,
        login_type: &str,
        token: &TokenValue,
        service: &str,
        safe_time: i64,
    ) -> SaTokenResult<()> {
        if safe_time < 0 {
            return Err(SaTokenError::ConfigError(
                "safe_time must be >= 0".to_string(),
            ));
        }

        let ttl = if safe_time == 0 {
            None
        } else {
            Some(Duration::from_secs(safe_time as u64))
        };

        self.dao
            .set_string(
                &self.safe_key_with_type(login_type, token.as_str(), service),
                &self.config.wire.safe_value,
                ttl,
            )
            .await?;

        self.event_bus
            .publish(crate::event::SaTokenEvent::open_safe(
                token.as_str(),
                service,
            ))
            .await;

        Ok(())
    }

    /// 判断 token 是否已通过指定业务的二级认证
    pub async fn is_safe(&self, token: &TokenValue, service: &str) -> SaTokenResult<bool> {
        let login_type = self.config.wire.default_login_type.clone();
        self.is_safe_with_type(&login_type, token, service).await
    }

    /// Whether secondary auth is active for a login type.
    /// 按登录类型判断二级认证是否有效。
    pub async fn is_safe_with_type(
        &self,
        login_type: &str,
        token: &TokenValue,
        service: &str,
    ) -> SaTokenResult<bool> {
        if token.as_str().is_empty() {
            return Ok(false);
        }

        if !self.is_valid(token).await {
            return Ok(false);
        }

        Ok(self
            .dao
            .get_string(&self.safe_key_with_type(login_type, token.as_str(), service))
            .await?
            .as_deref()
            .is_some_and(|v| self.is_safe_marker(v)))
    }

    /// 校验二级认证；未通过抛出 [`SaTokenError::NotSafe`]
    pub async fn check_safe(&self, token: &TokenValue, service: &str) -> SaTokenResult<()> {
        let login_type = self.config.wire.default_login_type.clone();
        self.check_safe_with_type(&login_type, token, service).await
    }

    /// Check secondary auth for a login type.
    /// 按登录类型校验二级认证。
    pub async fn check_safe_with_type(
        &self,
        login_type: &str,
        token: &TokenValue,
        service: &str,
    ) -> SaTokenResult<()> {
        if !self.is_valid(token).await {
            return Err(SaTokenError::NotLogin);
        }

        if !self.is_safe_with_type(login_type, token, service).await? {
            return Err(SaTokenError::NotSafe(service.to_string()));
        }

        let event = crate::event::SaTokenEvent::safe_verify(token.as_str(), service);
        self.event_bus.publish(event).await;

        Ok(())
    }

    /// 关闭二级认证
    pub async fn close_safe(&self, token: &TokenValue, service: &str) -> SaTokenResult<()> {
        let login_type = self.config.wire.default_login_type.clone();
        self.close_safe_with_type(&login_type, token, service).await
    }

    /// Close secondary auth for a login type.
    /// 按登录类型关闭二级认证。
    pub async fn close_safe_with_type(
        &self,
        login_type: &str,
        token: &TokenValue,
        service: &str,
    ) -> SaTokenResult<()> {
        self.dao
            .delete(&self.safe_key_with_type(login_type, token.as_str(), service))
            .await?;

        self.event_bus
            .publish(crate::event::SaTokenEvent::close_safe(
                token.as_str(),
                service,
            ))
            .await;

        Ok(())
    }

    /// 获取二级认证剩余有效时间（秒）；未认证返回 `None`
    pub async fn get_safe_time(
        &self,
        token: &TokenValue,
        service: &str,
    ) -> SaTokenResult<Option<i64>> {
        let login_type = self.config.wire.default_login_type.clone();
        self.get_safe_time_with_type(&login_type, token, service)
            .await
    }

    /// Remaining secondary-auth seconds for a login type.
    /// 按登录类型读取二级认证剩余秒数。
    pub async fn get_safe_time_with_type(
        &self,
        login_type: &str,
        token: &TokenValue,
        service: &str,
    ) -> SaTokenResult<Option<i64>> {
        match self
            .dao
            .ttl(&self.safe_key_with_type(login_type, token.as_str(), service))
            .await
        {
            Ok(Some(d)) => Ok(Some(d.as_secs() as i64)),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaTokenConfig;
    use sa_token_storage_memory::MemoryStorage;
    use std::sync::Arc;

    fn manager() -> SaTokenManager {
        SaTokenManager::new(Arc::new(MemoryStorage::new()), SaTokenConfig::default())
    }

    fn java_manager() -> SaTokenManager {
        SaTokenManager::new(
            Arc::new(MemoryStorage::new()),
            SaTokenConfig::java_compatible(),
        )
    }

    #[tokio::test]
    async fn open_check_close_safe() {
        let mgr = manager();
        let token = mgr.login("u1").await.unwrap();
        assert!(!mgr.is_safe(&token, DEFAULT_SAFE_SERVICE).await.unwrap());
        mgr.open_safe(&token, "pay", 120).await.unwrap();
        assert!(mgr.is_safe(&token, "pay").await.unwrap());
        mgr.check_safe(&token, "pay").await.unwrap();
        mgr.close_safe(&token, "pay").await.unwrap();
        assert!(!mgr.is_safe(&token, "pay").await.unwrap());
    }

    #[tokio::test]
    async fn native_writes_ok_and_empty_service() {
        let mgr = manager();
        let token = mgr.login("u1").await.unwrap();
        mgr.open_safe(&token, DEFAULT_SAFE_SERVICE, 120)
            .await
            .unwrap();
        let key = mgr.safe_key(token.as_str(), DEFAULT_SAFE_SERVICE);
        assert_eq!(
            mgr.dao().get_string(&key).await.unwrap().as_deref(),
            Some(SAFE_AUTH_VALUE)
        );
        assert!(mgr.is_safe(&token, DEFAULT_SAFE_SERVICE).await.unwrap());
    }

    #[tokio::test]
    async fn java_writes_safe_auth_save_value_and_important_key() {
        let mgr = java_manager();
        let token = mgr.login("10001").await.unwrap();
        let service = mgr.config.wire.default_safe_service.clone();
        assert_eq!(service, "important");
        mgr.open_safe(&token, &service, 0).await.unwrap();

        let key = mgr
            .keys()
            .safe_with_type("login", token.as_str(), "important");
        assert_eq!(
            key,
            format!("satoken:login:safe:important:{}", token.as_str())
        );
        assert_eq!(
            mgr.dao().get_string(&key).await.unwrap().as_deref(),
            Some(JAVA_SAFE_AUTH_VALUE)
        );
        assert!(mgr.is_safe(&token, "important").await.unwrap());
    }

    #[tokio::test]
    async fn reads_both_ok_and_java_safe_value() {
        let mgr = manager();
        let token = mgr.login("u1").await.unwrap();
        let key = mgr.safe_key(token.as_str(), "pay");

        mgr.dao()
            .set_string(&key, JAVA_SAFE_AUTH_VALUE, None)
            .await
            .unwrap();
        assert!(mgr.is_safe(&token, "pay").await.unwrap());

        mgr.dao()
            .set_string(&key, SAFE_AUTH_VALUE, None)
            .await
            .unwrap();
        assert!(mgr.is_safe(&token, "pay").await.unwrap());
    }
}
