//! Java 金样加载、注入与 dump helper。
//! 注入走 `storage.set` 原始字符串，不经 Rust encode。
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sa_token_adapter::storage::{TtlState, scan_all_keys_dedup};
use sa_token_core::config::TokenStyle;
use sa_token_core::{SaTokenConfig, SaTokenManager, TokenValue};
use sa_token_storage_memory::MemoryStorage;
use serde_json::{Value, json};

/// 与 Java harness / 金样共用的 JWT 密钥。
pub(crate) const JWT_SECRET: &str = "java-interop-secret-key-32bytes!!";
/// Rust dump 输出目录环境变量（供 `scripts/java-interop.sh` Verify）。
pub(crate) const DUMP_ENV: &str = "SA_INTEROP_DUMP_DIR";

/// `sa-token-integration-tests/fixtures/java-1.46.0`
pub(crate) fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/java-1.46.0")
}

/// 读取金样 JSON。
pub(crate) fn load_fixture(name: &str) -> Value {
    let path = fixture_dir().join(format!("{name}.json"));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse fixture {}: {e}", path.display()))
}

/// 金样 `tokens.<name>`。
pub(crate) fn fixture_token(fixture: &Value, name: &str) -> TokenValue {
    let s = fixture["tokens"][name]
        .as_str()
        .unwrap_or_else(|| panic!("fixture tokens.{name} missing"));
    TokenValue::new(s)
}

/// 计划约定的 Java 预设配置。
pub(crate) fn java_config() -> SaTokenConfig {
    SaTokenConfig::builder()
        .java_compatible()
        .timeout(-1)
        .jwt_secret_key(JWT_SECRET)
        .build_config()
}

fn cfg_i64(fixture: &Value, field: &str, default: i64) -> i64 {
    fixture["config"][field].as_i64().unwrap_or(default)
}

fn cfg_bool(fixture: &Value, field: &str, default: bool) -> bool {
    fixture["config"][field].as_bool().unwrap_or(default)
}

fn cfg_str<'a>(fixture: &'a Value, field: &str, default: &'a str) -> &'a str {
    fixture["config"][field].as_str().unwrap_or(default)
}

/// 按金样 `config` 叠在 `java_compatible()` 上（jwtMode / timeout / concurrent 等）。
pub(crate) fn java_config_from_fixture(fixture: &Value) -> SaTokenConfig {
    let mut builder = SaTokenConfig::builder()
        .java_compatible()
        .timeout(cfg_i64(fixture, "timeout", -1))
        .active_timeout(cfg_i64(fixture, "activeTimeout", -1))
        .dynamic_active_timeout(cfg_bool(fixture, "dynamicActiveTimeout", false))
        .is_concurrent(cfg_bool(fixture, "isConcurrent", true))
        .is_share(cfg_bool(fixture, "isShare", false))
        .same_token_timeout(cfg_i64(fixture, "sameTokenTimeout", -1))
        .jwt_secret_key(cfg_str(fixture, "jwtSecretKey", JWT_SECRET));
    builder = match fixture["config"]["jwtMode"].as_str() {
        Some("simple") => builder.token_style(TokenStyle::Jwt),
        Some("mixin") => builder.token_style(TokenStyle::JwtMixin),
        Some("stateless") => builder.token_style(TokenStyle::JwtStateless),
        _ => builder,
    };
    builder.build_config()
}

/// 独立 MemoryStorage + manager（不用 `shared_manager`）。
pub(crate) fn fresh_manager(config: SaTokenConfig) -> Arc<SaTokenManager> {
    let storage = Arc::new(MemoryStorage::new());
    Arc::new(SaTokenManager::new(storage, config))
}

/// 把金样 kv 原样灌进 manager 的存储。
pub(crate) async fn inject_kv(mgr: &SaTokenManager, fixture: &Value) {
    let Some(arr) = fixture["kv"].as_array() else {
        return;
    };
    for item in arr {
        let key = item["key"]
            .as_str()
            .unwrap_or_else(|| panic!("kv.key missing: {item}"));
        let value = item["value"]
            .as_str()
            .unwrap_or_else(|| panic!("kv.value missing for {key}"));
        let ttl = match item["ttl"].as_i64().unwrap_or(-1) {
            n if n < 0 => None,
            n => Some(Duration::from_secs(n as u64)),
        };
        mgr.storage()
            .set(key, value, ttl)
            .await
            .unwrap_or_else(|e| panic!("inject {key}: {e}"));
    }
}

/// 加载金样并注入，返回 manager + 根 JSON。
pub(crate) async fn load_and_inject(name: &str) -> (Arc<SaTokenManager>, Value) {
    let fixture = load_fixture(name);
    let mgr = fresh_manager(java_config_from_fixture(&fixture));
    inject_kv(&mgr, &fixture).await;
    (mgr, fixture)
}

/// 扫描全部键并用 `ttl_state` 生成金样 kv 数组。永久 ttl 为 `-1`。
pub(crate) async fn dump_kv(mgr: &SaTokenManager) -> Vec<Value> {
    let keys = scan_all_keys_dedup(mgr.storage().as_ref(), "*", 256)
        .await
        .expect("scan_all_keys_dedup");
    let mut out = Vec::new();
    for key in keys {
        let Some(value) = mgr
            .storage()
            .get(&key)
            .await
            .unwrap_or_else(|e| panic!("dump get {key}: {e}"))
        else {
            continue;
        };
        let ttl = match mgr
            .storage()
            .ttl_state(&key)
            .await
            .unwrap_or_else(|e| panic!("dump ttl_state {key}: {e}"))
        {
            TtlState::Missing => continue,
            TtlState::Persistent => -1,
            TtlState::Expires { remaining } => remaining.as_secs() as i64,
        };
        out.push(json!({ "key": key, "value": value, "ttl": ttl }));
    }
    out.sort_by(|a, b| a["key"].as_str().cmp(&b["key"].as_str()));
    out
}

/// 默认 dump `config` 块（与金样字段对齐）。
pub(crate) fn dump_config(jwt_mode: &str, login_type: &str, extra: &[(&str, Value)]) -> Value {
    let mut map = json!({
        "tokenName": "satoken",
        "timeout": -1,
        "activeTimeout": -1,
        "dynamicActiveTimeout": false,
        "isConcurrent": true,
        "isShare": false,
        "jwtSecretKey": JWT_SECRET,
        "sameTokenTimeout": -1,
        "jwtMode": jwt_mode,
        "loginType": login_type,
    });
    if let Some(obj) = map.as_object_mut() {
        for (k, v) in extra {
            obj.insert((*k).to_string(), v.clone());
        }
    }
    map
}

/// 若 `SA_INTEROP_DUMP_DIR` 已设置则写出 dump JSON。
pub(crate) async fn maybe_dump(
    mgr: &SaTokenManager,
    scenario: &str,
    notes: &str,
    config: Value,
    inputs: Value,
    tokens: Value,
) {
    let Some(dir) = std::env::var_os(DUMP_ENV).map(PathBuf::from) else {
        return;
    };
    write_dump_to(
        &dir,
        scenario,
        notes,
        config,
        inputs,
        tokens,
        dump_kv(mgr).await,
    );
}

/// 写出与金样相同 schema 的 dump 文件。
pub(crate) fn write_dump_to(
    dir: &Path,
    scenario: &str,
    notes: &str,
    config: Value,
    inputs: Value,
    tokens: Value,
    kv: Vec<Value>,
) {
    std::fs::create_dir_all(dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
    let body = json!({
        "scenario": scenario,
        "notes": notes,
        "config": config,
        "inputs": inputs,
        "tokens": tokens,
        "kv": kv,
    });
    let path = dir.join(format!("{scenario}.json"));
    let raw = serde_json::to_string_pretty(&body).expect("serialize dump");
    std::fs::write(&path, raw).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// Java last-active：`^\d{13}$` 或 `^\d{13},\d+$`。
pub(crate) fn is_last_active_format(s: &str) -> bool {
    let (ms, rest) = match s.split_once(',') {
        Some((ms, secs)) => {
            if secs.is_empty() || !secs.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            (ms, true)
        }
        None => (s, false),
    };
    let _ = rest;
    ms.len() == 13 && ms.bytes().all(|b| b.is_ascii_digit())
}

/// Java 布局下不应出现的 Rust 独有反查键。
///
/// Java token 键是 `{tn}:login:token:{uuid}`，不要当成 `login:token` 索引。
/// 索引在四段布局下是 `{tn}:login:login:token:{id}` / `{tn}:login:login:tokens:{id}`。
pub(crate) fn assert_no_rust_index_keys(keys: &[String]) {
    for key in keys {
        assert!(
            !key.contains(":token-id:"),
            "unexpected token-id key: {key}"
        );
        assert!(
            !key.contains(":login:login:token:") && !key.contains(":login:login:tokens:"),
            "unexpected rust login:token(s) index key: {key}"
        );
    }
}

/// 列出当前存储全部键。
pub(crate) async fn all_keys(mgr: &SaTokenManager) -> Vec<String> {
    let mut keys = scan_all_keys_dedup(mgr.storage().as_ref(), "*", 256)
        .await
        .expect("scan keys");
    keys.sort();
    keys
}

/// 读存储原始字符串。
pub(crate) async fn get_raw(mgr: &SaTokenManager, key: &str) -> Option<String> {
    mgr.storage()
        .get(key)
        .await
        .unwrap_or_else(|e| panic!("get {key}: {e}"))
}
