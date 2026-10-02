//! Raw Session / Custom Session (Java `SaRawSessionUtil` / `SaSessionCustomUtil`).
//! 任意类型 Session 读写；Custom Session 固定 type=`custom`。

use crate::error::SaTokenResult;
use crate::session::SaSession;
use crate::util::StpUtil;

/// Session type used by [`SaSessionCustom`].
/// Custom Session 使用的类型名。
pub const CUSTOM_SESSION_TYPE: &str = "custom";

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

    /// Whether the Raw Session exists in storage.
    /// 指定 Raw Session 是否已落盘。
    pub async fn is_exists(session_type: &str, value_id: &str) -> SaTokenResult<bool> {
        let manager = StpUtil::try_get_manager()?;
        let key = manager.keys().raw_session(session_type, value_id);
        manager.dao().exists(&key).await
    }

    /// Load a Raw Session; create and persist when missing and `is_create`.
    /// 读取 Raw Session；缺失且 `is_create` 时新建并落盘。
    pub async fn get(
        session_type: &str,
        value_id: &str,
        is_create: bool,
    ) -> SaTokenResult<Option<SaSession>> {
        let manager = StpUtil::try_get_manager()?;
        let key = manager.keys().raw_session(session_type, value_id);
        if let Some(session) = manager.dao().get_object::<SaSession>(&key).await? {
            return Ok(Some(session));
        }
        if !is_create {
            return Ok(None);
        }
        let session = SaSession::new(&key).with_type(session_type);
        manager
            .dao()
            .set_object(&key, &session, manager.dao().default_ttl())
            .await?;
        Ok(Some(session))
    }

    /// Load a Raw Session, creating it when missing.
    /// 读取 Raw Session，不存在则新建。
    pub async fn get_or_create(session_type: &str, value_id: &str) -> SaTokenResult<SaSession> {
        match Self::get(session_type, value_id, true).await? {
            Some(session) => Ok(session),
            None => {
                let id = Self::session_id(session_type, value_id)?;
                let session = SaSession::new(id).with_type(session_type);
                Self::save(&session).await?;
                Ok(session)
            }
        }
    }

    /// Persist a Raw Session: KEEPTTL when the key exists, else default timeout.
    /// 回写 Raw Session：键已存在 KEEPTTL，否则用默认 timeout。
    pub async fn save(session: &SaSession) -> SaTokenResult<()> {
        let manager = StpUtil::try_get_manager()?;
        let dao = manager.dao();
        let key = &session.id;
        if dao.exists(key).await? {
            dao.set_object_keep_ttl(key, session).await
        } else {
            dao.set_object(key, session, dao.default_ttl()).await
        }
    }

    /// Delete a Raw Session.
    /// 删除指定 Raw Session。
    pub async fn delete(session_type: &str, value_id: &str) -> SaTokenResult<()> {
        let manager = StpUtil::try_get_manager()?;
        let key = manager.keys().raw_session(session_type, value_id);
        manager.dao().delete(&key).await
    }
}

/// Custom Session 别名（Java `SaSessionCustomUtil`）；type 固定为 [`CUSTOM_SESSION_TYPE`]。
#[derive(Debug)]
pub struct SaSessionCustom;

impl SaSessionCustom {
    /// Storage key / session id for a custom session.
    /// Custom Session 存储键。
    pub fn session_id(value_id: &str) -> SaTokenResult<String> {
        RawSession::session_id(CUSTOM_SESSION_TYPE, value_id)
    }

    /// Whether the Custom Session exists.
    /// 指定 Custom Session 是否已落盘。
    pub async fn is_exists(value_id: &str) -> SaTokenResult<bool> {
        RawSession::is_exists(CUSTOM_SESSION_TYPE, value_id).await
    }

    /// Load a Custom Session; create when missing and `is_create`.
    /// 读取 Custom Session；缺失且 `is_create` 时新建。
    pub async fn get(value_id: &str, is_create: bool) -> SaTokenResult<Option<SaSession>> {
        RawSession::get(CUSTOM_SESSION_TYPE, value_id, is_create).await
    }

    /// Load a Custom Session, creating it when missing.
    /// 读取 Custom Session，不存在则新建。
    pub async fn get_or_create(value_id: &str) -> SaTokenResult<SaSession> {
        RawSession::get_or_create(CUSTOM_SESSION_TYPE, value_id).await
    }

    /// Persist a Custom Session (KEEPTTL or default timeout).
    /// 回写 Custom Session。
    pub async fn save(session: &SaSession) -> SaTokenResult<()> {
        RawSession::save(session).await
    }

    /// Delete a Custom Session.
    /// 删除指定 Custom Session。
    pub async fn delete(value_id: &str) -> SaTokenResult<()> {
        RawSession::delete(CUSTOM_SESSION_TYPE, value_id).await
    }
}
