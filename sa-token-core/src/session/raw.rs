//! Raw Session / Custom Session (Java `SaRawSessionUtil` / `SaSessionCustomUtil`).
//! 任意类型 Session 读写；Custom Session 原生 type=`custom`，Java type=`Custom-Session`。

use crate::compat::SessionFormat;
use crate::compat::java_session::TYPE_CUSTOM_SESSION;
use crate::config::SaTokenConfig;
use crate::error::SaTokenResult;
use crate::keys::SaKeyLayout;
use crate::manager::SaTokenManager;
use crate::session::SaSession;
use crate::util::StpUtil;

/// Session type used by [`SaSessionCustom`] on the native three-segment layout.
/// 原生三段布局下 Custom Session 使用的类型名。
pub const CUSTOM_SESSION_TYPE: &str = "custom";

fn custom_type_of(config: &SaTokenConfig) -> &'static str {
    if config.key_layout == SaKeyLayout::JavaFourSegment
        || config.wire.session_format == SessionFormat::Jackson3Typed
    {
        TYPE_CUSTOM_SESSION
    } else {
        CUSTOM_SESSION_TYPE
    }
}

/// Raw Session 读写（Java `SaRawSessionUtil`）。
#[derive(Debug)]
pub struct RawSession;

impl RawSession {
    /// Storage key / session id for `(type, value_id)`.
    /// 拼接存储键（同时作为 session id）。
    pub fn session_id(session_type: &str, value_id: &str) -> SaTokenResult<String> {
        let manager = StpUtil::try_get_manager()?;
        Ok(manager.keys().raw_session(session_type, value_id))
    }

    fn session_id_on(manager: &SaTokenManager, session_type: &str, value_id: &str) -> String {
        manager.keys().raw_session(session_type, value_id)
    }

    /// Whether the Raw Session exists in storage.
    /// 指定 Raw Session 是否已落盘。
    pub async fn is_exists(session_type: &str, value_id: &str) -> SaTokenResult<bool> {
        Self::is_exists_on(StpUtil::try_get_manager()?, session_type, value_id).await
    }

    async fn is_exists_on(
        manager: &SaTokenManager,
        session_type: &str,
        value_id: &str,
    ) -> SaTokenResult<bool> {
        let key = Self::session_id_on(manager, session_type, value_id);
        manager.dao().exists(&key).await
    }

    /// Load a Raw Session; create and persist when missing and `is_create`.
    /// 读取 Raw Session；缺失且 `is_create` 时新建并落盘。
    pub async fn get(
        session_type: &str,
        value_id: &str,
        is_create: bool,
    ) -> SaTokenResult<Option<SaSession>> {
        Self::get_on(
            StpUtil::try_get_manager()?,
            session_type,
            value_id,
            is_create,
        )
        .await
    }

    async fn get_on(
        manager: &SaTokenManager,
        session_type: &str,
        value_id: &str,
        is_create: bool,
    ) -> SaTokenResult<Option<SaSession>> {
        let key = Self::session_id_on(manager, session_type, value_id);
        if let Some(session) = manager.dao().get_session(&key).await? {
            return Ok(Some(session));
        }
        if !is_create {
            return Ok(None);
        }
        let session = SaSession::new(&key).with_type(session_type);
        manager
            .dao()
            .set_session(&key, &session, manager.dao().default_ttl())
            .await?;
        Ok(Some(session))
    }

    /// Load a Raw Session, creating it when missing.
    /// 读取 Raw Session，不存在则新建。
    pub async fn get_or_create(session_type: &str, value_id: &str) -> SaTokenResult<SaSession> {
        Self::get_or_create_on(StpUtil::try_get_manager()?, session_type, value_id).await
    }

    async fn get_or_create_on(
        manager: &SaTokenManager,
        session_type: &str,
        value_id: &str,
    ) -> SaTokenResult<SaSession> {
        match Self::get_on(manager, session_type, value_id, true).await? {
            Some(session) => Ok(session),
            None => {
                let key = Self::session_id_on(manager, session_type, value_id);
                let session = SaSession::new(&key).with_type(session_type);
                Self::save_on(manager, &session).await?;
                Ok(session)
            }
        }
    }

    /// Persist a Raw Session: KEEPTTL when the key exists, else default timeout.
    /// 回写 Raw Session：键已存在 KEEPTTL，否则用默认 timeout。
    pub async fn save(session: &SaSession) -> SaTokenResult<()> {
        Self::save_on(StpUtil::try_get_manager()?, session).await
    }

    async fn save_on(manager: &SaTokenManager, session: &SaSession) -> SaTokenResult<()> {
        let dao = manager.dao();
        let key = &session.id;
        if dao.exists(key).await? {
            dao.update_session_keep_ttl(key, session).await
        } else {
            dao.set_session(key, session, dao.default_ttl()).await
        }
    }

    /// Delete a Raw Session.
    /// 删除指定 Raw Session。
    pub async fn delete(session_type: &str, value_id: &str) -> SaTokenResult<()> {
        Self::delete_on(StpUtil::try_get_manager()?, session_type, value_id).await
    }

    async fn delete_on(
        manager: &SaTokenManager,
        session_type: &str,
        value_id: &str,
    ) -> SaTokenResult<()> {
        let key = Self::session_id_on(manager, session_type, value_id);
        manager.dao().delete(&key).await
    }
}

/// Custom Session 别名（Java `SaSessionCustomUtil`）。
///
/// Native type is [`CUSTOM_SESSION_TYPE`]; Java layout / Jackson session format
/// uses `Custom-Session`. Storage key is always `keys().custom_session(id)`.
/// 原生 type 为 [`CUSTOM_SESSION_TYPE`]；Java 布局 / Jackson Session 为 `Custom-Session`。
#[derive(Debug)]
pub struct SaSessionCustom;

impl SaSessionCustom {
    fn key_on(manager: &SaTokenManager, value_id: &str) -> String {
        manager.keys().custom_session(value_id)
    }

    /// Storage key / session id for a custom session.
    /// Custom Session 存储键。
    pub fn session_id(value_id: &str) -> SaTokenResult<String> {
        let manager = StpUtil::try_get_manager()?;
        Ok(Self::key_on(manager, value_id))
    }

    /// Whether the Custom Session exists.
    /// 指定 Custom Session 是否已落盘。
    pub async fn is_exists(value_id: &str) -> SaTokenResult<bool> {
        Self::is_exists_on(StpUtil::try_get_manager()?, value_id).await
    }

    async fn is_exists_on(manager: &SaTokenManager, value_id: &str) -> SaTokenResult<bool> {
        manager.dao().exists(&Self::key_on(manager, value_id)).await
    }

    /// Load a Custom Session; create when missing and `is_create`.
    /// 读取 Custom Session；缺失且 `is_create` 时新建。
    pub async fn get(value_id: &str, is_create: bool) -> SaTokenResult<Option<SaSession>> {
        Self::get_on(StpUtil::try_get_manager()?, value_id, is_create).await
    }

    async fn get_on(
        manager: &SaTokenManager,
        value_id: &str,
        is_create: bool,
    ) -> SaTokenResult<Option<SaSession>> {
        let key = Self::key_on(manager, value_id);
        if let Some(session) = manager.dao().get_session(&key).await? {
            return Ok(Some(session));
        }
        if !is_create {
            return Ok(None);
        }
        let session = SaSession::new(&key).with_type(custom_type_of(&manager.config));
        manager
            .dao()
            .set_session(&key, &session, manager.dao().default_ttl())
            .await?;
        Ok(Some(session))
    }

    /// Load a Custom Session, creating it when missing.
    /// 读取 Custom Session，不存在则新建。
    pub async fn get_or_create(value_id: &str) -> SaTokenResult<SaSession> {
        Self::get_or_create_on(StpUtil::try_get_manager()?, value_id).await
    }

    async fn get_or_create_on(
        manager: &SaTokenManager,
        value_id: &str,
    ) -> SaTokenResult<SaSession> {
        match Self::get_on(manager, value_id, true).await? {
            Some(session) => Ok(session),
            None => {
                let key = Self::key_on(manager, value_id);
                let session = SaSession::new(key).with_type(custom_type_of(&manager.config));
                RawSession::save_on(manager, &session).await?;
                Ok(session)
            }
        }
    }

    /// Persist a Custom Session (KEEPTTL or default timeout).
    /// 回写 Custom Session。
    pub async fn save(session: &SaSession) -> SaTokenResult<()> {
        RawSession::save(session).await
    }

    /// Delete a Custom Session.
    /// 删除指定 Custom Session。
    pub async fn delete(value_id: &str) -> SaTokenResult<()> {
        Self::delete_on(StpUtil::try_get_manager()?, value_id).await
    }

    async fn delete_on(manager: &SaTokenManager, value_id: &str) -> SaTokenResult<()> {
        manager.dao().delete(&Self::key_on(manager, value_id)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaTokenConfig;
    use sa_token_storage_memory::MemoryStorage;
    use std::sync::Arc;

    fn native_mgr() -> SaTokenManager {
        SaTokenManager::new(Arc::new(MemoryStorage::new()), SaTokenConfig::default())
    }

    fn java_mgr() -> SaTokenManager {
        let mut cfg = SaTokenConfig::java_compatible();
        cfg.timeout = -1;
        SaTokenManager::new(Arc::new(MemoryStorage::new()), cfg)
    }

    #[tokio::test]
    async fn native_raw_type_is_namespace() {
        let mgr = native_mgr();
        let mut session = RawSession::get_or_create_on(&mgr, "role", "1001")
            .await
            .unwrap();
        assert_eq!(session.session_type, "role");
        session.set("count", 1_i32).unwrap();
        RawSession::save_on(&mgr, &session).await.unwrap();
        let loaded = RawSession::get_on(&mgr, "role", "1001", false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.get::<i32>("count"), Some(1));
        assert_eq!(loaded.session_type, "role");
    }

    #[tokio::test]
    async fn native_custom_keeps_type_custom() {
        let mgr = native_mgr();
        let session = SaSessionCustom::get_or_create_on(&mgr, "role-1001")
            .await
            .unwrap();
        assert_eq!(session.session_type, CUSTOM_SESSION_TYPE);
        assert_eq!(session.id, mgr.keys().custom_session("role-1001"));
        assert!(
            SaSessionCustom::is_exists_on(&mgr, "role-1001")
                .await
                .unwrap()
        );
        assert!(
            !RawSession::is_exists_on(&mgr, CUSTOM_SESSION_TYPE, "role-1001")
                .await
                .unwrap(),
            "custom session must not land on the raw-session key"
        );
    }

    #[tokio::test]
    async fn java_raw_type_is_namespace_and_jackson() {
        let mgr = java_mgr();
        let mut session = RawSession::get_or_create_on(&mgr, "user", "10001")
            .await
            .unwrap();
        session.set("flag", "raw").unwrap();
        RawSession::save_on(&mgr, &session).await.unwrap();
        let key = mgr.keys().raw_session("user", "10001");
        assert_eq!(key, "satoken:raw-session:user:10001");
        let raw = mgr.dao().get_string(&key).await.unwrap().unwrap();
        assert!(raw.contains("\"type\":\"user\""));
        assert!(raw.contains("@class"));
        let loaded = RawSession::get_on(&mgr, "user", "10001", false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.session_type, "user");
        assert_eq!(loaded.get::<String>("flag").as_deref(), Some("raw"));
    }

    #[tokio::test]
    async fn java_custom_session_type_and_key() {
        let mgr = java_mgr();
        let mut session = SaSessionCustom::get_or_create_on(&mgr, "role-1001")
            .await
            .unwrap();
        assert_eq!(session.session_type, TYPE_CUSTOM_SESSION);
        session.set("count", 1_i32).unwrap();
        RawSession::save_on(&mgr, &session).await.unwrap();
        let key = mgr.keys().custom_session("role-1001");
        assert_eq!(key, "satoken:custom:session:role-1001");
        let raw = mgr.dao().get_string(&key).await.unwrap().unwrap();
        assert!(raw.contains("\"type\":\"Custom-Session\""));
        let loaded = SaSessionCustom::get_on(&mgr, "role-1001", false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.session_type, "Custom-Session");
        assert_eq!(loaded.get::<i32>("count"), Some(1));
    }
}
