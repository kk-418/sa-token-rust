//! Application-scope KV (Java `SaApplication`).
//! 应用全局作用域存取值。

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::SaTokenResult;
use crate::util::StpUtil;

/// Application-scope variable store (Java `SaApplication`).
/// 应用全局变量（对齐 Java `SaApplication`）。
#[derive(Debug)]
pub struct SaApplication;

impl SaApplication {
    /// Write a value. `ttl_secs < 0` means never expire.
    /// 写入；`ttl_secs < 0` 表示永久。
    pub async fn set(key: &str, value: impl Serialize, ttl_secs: i64) -> SaTokenResult<()> {
        let manager = StpUtil::try_get_manager()?;
        let storage_key = manager.keys().application_var(key);
        let ttl = if ttl_secs < 0 {
            None
        } else {
            Some(Duration::from_secs(ttl_secs as u64))
        };
        manager.dao().set_object(&storage_key, &value, ttl).await
    }

    /// Read and deserialize a value.
    /// 读取并反序列化。
    pub async fn get<T: DeserializeOwned>(key: &str) -> SaTokenResult<Option<T>> {
        let manager = StpUtil::try_get_manager()?;
        let storage_key = manager.keys().application_var(key);
        manager.dao().get_object(&storage_key).await
    }

    /// Delete a value.
    /// 删除。
    pub async fn delete(key: &str) -> SaTokenResult<()> {
        let manager = StpUtil::try_get_manager()?;
        let storage_key = manager.keys().application_var(key);
        manager.dao().delete(&storage_key).await
    }

    /// Whether the key exists.
    /// 键是否存在。
    pub async fn exists(key: &str) -> SaTokenResult<bool> {
        let manager = StpUtil::try_get_manager()?;
        let storage_key = manager.keys().application_var(key);
        manager.dao().exists(&storage_key).await
    }
}
