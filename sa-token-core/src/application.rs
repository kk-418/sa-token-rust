//! Application-scope KV (Java `SaApplication`).
//! 应用全局作用域存取值。

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::compat::ApplicationValue;
use crate::error::SaTokenResult;
use crate::manager::SaTokenManager;
use crate::util::StpUtil;

/// Application-scope variable store (Java `SaApplication`).
/// 应用全局变量（对齐 Java `SaApplication`）。
#[derive(Debug)]
pub struct SaApplication;

impl SaApplication {
    /// Write a value. `ttl_secs < 0` means never expire.
    /// 写入；`ttl_secs < 0` 表示永久。
    pub async fn set(key: &str, value: impl Serialize, ttl_secs: i64) -> SaTokenResult<()> {
        Self::set_on(StpUtil::try_get_manager()?, key, value, ttl_secs).await
    }

    async fn set_on(
        manager: &SaTokenManager,
        key: &str,
        value: impl Serialize,
        ttl_secs: i64,
    ) -> SaTokenResult<()> {
        let storage_key = manager.keys().application_var(key);
        let ttl = if ttl_secs < 0 {
            None
        } else {
            Some(Duration::from_secs(ttl_secs as u64))
        };
        match manager.config.wire.application_value {
            ApplicationValue::Serde => manager.dao().set_object(&storage_key, &value, ttl).await,
            ApplicationValue::JavaRoot => {
                let v = serde_json::to_value(&value)?;
                let raw = manager.dao().wire().encode_root(&v)?;
                manager.dao().set_string(&storage_key, &raw, ttl).await
            }
        }
    }

    /// Read and deserialize a value.
    /// 读取并反序列化。
    pub async fn get<T: DeserializeOwned>(key: &str) -> SaTokenResult<Option<T>> {
        Self::get_on(StpUtil::try_get_manager()?, key).await
    }

    async fn get_on<T: DeserializeOwned>(
        manager: &SaTokenManager,
        key: &str,
    ) -> SaTokenResult<Option<T>> {
        let storage_key = manager.keys().application_var(key);
        match manager.config.wire.application_value {
            ApplicationValue::Serde => manager.dao().get_object(&storage_key).await,
            ApplicationValue::JavaRoot => match manager.dao().get_string(&storage_key).await? {
                Some(raw) => {
                    let v = manager.dao().wire().decode_root(&raw)?;
                    Ok(Some(serde_json::from_value(v)?))
                }
                None => Ok(None),
            },
        }
    }

    /// Delete a value.
    /// 删除。
    pub async fn delete(key: &str) -> SaTokenResult<()> {
        Self::delete_on(StpUtil::try_get_manager()?, key).await
    }

    async fn delete_on(manager: &SaTokenManager, key: &str) -> SaTokenResult<()> {
        let storage_key = manager.keys().application_var(key);
        manager.dao().delete(&storage_key).await
    }

    /// Whether the key exists.
    /// 键是否存在。
    pub async fn exists(key: &str) -> SaTokenResult<bool> {
        Self::exists_on(StpUtil::try_get_manager()?, key).await
    }

    async fn exists_on(manager: &SaTokenManager, key: &str) -> SaTokenResult<bool> {
        let storage_key = manager.keys().application_var(key);
        manager.dao().exists(&storage_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SaTokenConfig;
    use sa_token_storage_memory::MemoryStorage;
    use serde_json::json;
    use std::collections::HashMap;
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
    async fn serde_set_get_roundtrip() {
        let mgr = native_mgr();
        SaApplication::set_on(&mgr, "k", "hello", 3600)
            .await
            .unwrap();
        let got: Option<String> = SaApplication::get_on(&mgr, "k").await.unwrap();
        assert_eq!(got.as_deref(), Some("hello"));
        assert!(SaApplication::exists_on(&mgr, "k").await.unwrap());
        SaApplication::delete_on(&mgr, "k").await.unwrap();
        assert!(!SaApplication::exists_on(&mgr, "k").await.unwrap());
    }

    #[tokio::test]
    async fn java_root_writes_bare_json_without_class() {
        let mgr = java_mgr();
        SaApplication::set_on(&mgr, "foo", "bar", -1).await.unwrap();
        SaApplication::set_on(&mgr, "num", 10001_i64, -1)
            .await
            .unwrap();
        let mut map = HashMap::new();
        map.insert("k", "v");
        SaApplication::set_on(&mgr, "map", map, -1).await.unwrap();

        let dao = mgr.dao();
        assert_eq!(
            dao.get_string(&mgr.keys().application_var("foo"))
                .await
                .unwrap()
                .as_deref(),
            Some("\"bar\"")
        );
        assert_eq!(
            dao.get_string(&mgr.keys().application_var("num"))
                .await
                .unwrap()
                .as_deref(),
            Some("10001")
        );
        let map_raw = dao
            .get_string(&mgr.keys().application_var("map"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(map_raw, r#"{"k":"v"}"#);
        assert!(!map_raw.contains("@class"));

        let foo: Option<String> = SaApplication::get_on(&mgr, "foo").await.unwrap();
        assert_eq!(foo.as_deref(), Some("bar"));
        let num: Option<i64> = SaApplication::get_on(&mgr, "num").await.unwrap();
        assert_eq!(num, Some(10001));
        let decoded: Option<serde_json::Value> = SaApplication::get_on(&mgr, "map").await.unwrap();
        assert_eq!(decoded, Some(json!({"k": "v"})));
    }
}
