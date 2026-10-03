//! Jackson3 mapping for Java `SaSession` / `SaTerminalInfo`.
//! Java `SaSession` / `SaTerminalInfo` 的 Jackson3 字段映射。
//!
//! Native `Serialize`/`Deserialize` of [`SaSession`] is unchanged
//! (`snake_case` / flatten `data` / RFC3339 `create_time`). This module
//! hand-builds Jackson camelCase JSON and never goes through serde rename.
//! [`SaSession`] 的原生 serde 形态不变。本模块手写 Jackson camelCase JSON。

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use crate::error::SaTokenResult;
use crate::session::{SaSession, SaTerminalInfo};

use super::WireConfig;
use super::jackson::{
    CLASS_CONCURRENT_HASH_MAP, CLASS_SESSION, CLASS_TERMINAL, CLASS_VECTOR, decode_object_slot,
    encode_login_id, encode_object_slot, login_id_from_value,
};

/// Java `SaSession` type: account session.
pub const TYPE_ACCOUNT_SESSION: &str = "Account-Session";
/// Java `SaSession` type: token session.
pub const TYPE_TOKEN_SESSION: &str = "Token-Session";
/// Java `SaSession` type: anonymous token session.
pub const TYPE_ANON_TOKEN_SESSION: &str = "Anon-Token-Session";
/// Java `SaSession` type: custom session.
pub const TYPE_CUSTOM_SESSION: &str = "Custom-Session";

/// Java-only session metadata kept off the native serde shape.
/// 不进入原生 serde 形态的 Java Session 元数据。
#[derive(Debug, Clone, Default)]
pub struct JavaSessionExt {
    /// Decoded loginId string (`None` = JSON null).
    /// 解码后的 loginId 字符串（`None` 对应 JSON null）。
    pub login_id: Option<String>,
    /// Decoded loginType (`None` = JSON null).
    pub login_type: Option<String>,
    /// Token-session token value (`None` = JSON null).
    pub token: Option<String>,
    /// Original typed loginId node, used to round-trip Long wrappers.
    /// 原始 loginId 类型化节点，用于原样回写 Long 包装。
    pub login_id_typed: Option<Value>,
    /// Original typed dataMap nodes, keyed like [`SaSession::data`].
    /// 原始 dataMap 类型化节点，键与 [`SaSession::data`] 对应。
    pub data_map_typed: HashMap<String, Value>,
    /// Unknown Jackson fields preserved on write-back.
    /// 回写时保留的未知 Jackson 字段。
    pub extra: Map<String, Value>,
}

/// Encode [`SaSession`] as Jackson3 typed JSON.
/// 将 [`SaSession`] 编码为 Jackson3 类型化 JSON。
pub fn encode_session(session: &SaSession, cfg: &WireConfig) -> SaTokenResult<String> {
    let mut obj = Map::new();
    obj.insert("@class".into(), json!(CLASS_SESSION));
    obj.insert(
        "createTime".into(),
        json!(session.create_time.timestamp_millis()),
    );
    obj.insert("dataMap".into(), encode_data_map(session));
    obj.insert(
        "historyTerminalCount".into(),
        json!(session.history_terminal_count),
    );
    obj.insert("id".into(), json!(session.id));
    obj.insert("loginId".into(), encode_session_login_id(session, cfg));
    obj.insert(
        "loginType".into(),
        encode_opt_string(session_login_type(session)),
    );
    obj.insert("terminalList".into(), encode_terminal_list(session));
    obj.insert("token".into(), encode_opt_string(session_token(session)));
    obj.insert("type".into(), json!(session.session_type));
    if let Some(ext) = session.wire_ext.as_deref() {
        for (k, v) in &ext.extra {
            obj.entry(k.clone()).or_insert(v.clone());
        }
    }
    Ok(serde_json::to_string(&Value::Object(obj))?)
}

/// Decode Jackson3 or native serde session JSON.
/// 解码 Jackson3 或原生 serde Session JSON。
pub fn decode_session(raw: &str) -> SaTokenResult<SaSession> {
    let value: Value = serde_json::from_str(raw)?;
    if is_jackson_session(&value) {
        decode_jackson_session(&value)
    } else {
        Ok(serde_json::from_value(value)?)
    }
}

/// True when the JSON looks like Java Jackson3 `SaSession`.
/// JSON 是否像 Java Jackson3 `SaSession`。
pub fn is_jackson_session(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.contains_key("@class") || o.contains_key("createTime") || o.contains_key("dataMap")
    })
}

fn session_login_type(session: &SaSession) -> Option<&str> {
    session
        .wire_ext
        .as_deref()
        .and_then(|e| e.login_type.as_deref())
}

fn session_token(session: &SaSession) -> Option<&str> {
    session.wire_ext.as_deref().and_then(|e| e.token.as_deref())
}

fn encode_opt_string(v: Option<&str>) -> Value {
    match v {
        Some(s) => json!(s),
        None => Value::Null,
    }
}

fn encode_session_login_id(session: &SaSession, cfg: &WireConfig) -> Value {
    let Some(ext) = session.wire_ext.as_deref() else {
        return Value::Null;
    };
    let Some(id) = ext.login_id.as_deref() else {
        return Value::Null;
    };
    if let Some(typed) = &ext.login_id_typed
        && login_id_from_value(typed).as_deref() == Some(id)
    {
        return typed.clone();
    }
    encode_login_id(id, cfg.login_id_json)
}

fn encode_data_map(session: &SaSession) -> Value {
    let mut map = Map::new();
    map.insert("@class".into(), json!(CLASS_CONCURRENT_HASH_MAP));
    let typed = session.wire_ext.as_ref().map(|e| &e.data_map_typed);
    for (k, v) in &session.data {
        if v.is_null() {
            continue;
        }
        let encoded = match typed.and_then(|t| t.get(k)) {
            Some(orig) if decode_object_slot(orig) == *v => orig.clone(),
            _ => encode_object_slot(v),
        };
        map.insert(k.clone(), encoded);
    }
    Value::Object(map)
}

fn encode_terminal_list(session: &SaSession) -> Value {
    let items: Vec<Value> = session.terminal_list.iter().map(encode_terminal).collect();
    json!([CLASS_VECTOR, items])
}

fn encode_terminal(t: &SaTerminalInfo) -> Value {
    let mut m = Map::new();
    m.insert("@class".into(), json!(CLASS_TERMINAL));
    m.insert("createTime".into(), json!(t.create_time));
    m.insert(
        "deviceId".into(),
        match &t.device_id {
            Some(s) => json!(s),
            None => Value::Null,
        },
    );
    m.insert("deviceType".into(), json!(t.device_type));
    m.insert(
        "extraData".into(),
        match &t.extra_data {
            Some(v) => encode_object_slot(v),
            None => Value::Null,
        },
    );
    m.insert("index".into(), json!(t.index));
    m.insert("tokenValue".into(), json!(t.token_value));
    Value::Object(m)
}

fn decode_jackson_session(v: &Value) -> SaTokenResult<SaSession> {
    let obj = v.as_object().ok_or_else(|| {
        crate::error::SaTokenError::SerializationError(
            "jackson session must be a JSON object".into(),
        )
    })?;

    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let create_ms = value_i64(obj.get("createTime"));
    let create_time =
        DateTime::from_timestamp_millis(create_ms).unwrap_or(DateTime::<Utc>::UNIX_EPOCH);
    let session_type = string_or_empty(obj.get("type"));
    let history_terminal_count = value_i64(obj.get("historyTerminalCount")) as i32;
    let terminal_list = decode_terminal_list(obj.get("terminalList"));

    let mut data = HashMap::new();
    let mut data_map_typed = HashMap::new();
    if let Some(Value::Object(dm)) = obj.get("dataMap") {
        for (k, val) in dm {
            if k == "@class" {
                continue;
            }
            data_map_typed.insert(k.clone(), val.clone());
            data.insert(k.clone(), decode_object_slot(val));
        }
    }

    let login_id_raw = obj.get("loginId").cloned().filter(|x| !x.is_null());
    let login_id = login_id_raw.as_ref().and_then(login_id_from_value);
    let login_type = string_or_none(obj.get("loginType"));
    let token = string_or_none(obj.get("token"));

    let extra = extra_fields(obj);
    let ext = JavaSessionExt {
        login_id,
        login_type,
        token,
        login_id_typed: login_id_raw,
        data_map_typed,
        extra,
    };

    Ok(SaSession {
        id,
        create_time,
        terminal_list,
        history_terminal_count,
        session_type,
        data,
        wire_ext: Some(Box::new(ext)),
    })
}

const KNOWN_SESSION_FIELDS: &[&str] = &[
    "@class",
    "createTime",
    "dataMap",
    "historyTerminalCount",
    "id",
    "loginId",
    "loginType",
    "terminalList",
    "token",
    "type",
];

fn extra_fields(obj: &Map<String, Value>) -> Map<String, Value> {
    let mut extra = Map::new();
    for (k, v) in obj {
        if !KNOWN_SESSION_FIELDS.contains(&k.as_str()) {
            extra.insert(k.clone(), v.clone());
        }
    }
    extra
}

fn decode_terminal_list(v: Option<&Value>) -> Vec<SaTerminalInfo> {
    let Some(v) = v else {
        return Vec::new();
    };
    let decoded = decode_object_slot(v);
    let Some(arr) = decoded.as_array() else {
        return Vec::new();
    };
    arr.iter().filter_map(decode_terminal).collect()
}

fn decode_terminal(v: &Value) -> Option<SaTerminalInfo> {
    let obj = match decode_object_slot(v) {
        Value::Object(m) => m,
        _ => return None,
    };
    Some(SaTerminalInfo {
        index: value_i64(obj.get("index")) as i32,
        token_value: string_or_empty(obj.get("tokenValue")),
        device_type: string_or_empty(obj.get("deviceType")),
        device_id: string_or_none(obj.get("deviceId")),
        extra_data: obj.get("extraData").and_then(|x| {
            if x.is_null() {
                None
            } else {
                Some(decode_object_slot(x))
            }
        }),
        create_time: value_i64(obj.get("createTime")),
    })
}

fn value_i64(v: Option<&Value>) -> i64 {
    v.map(decode_object_slot)
        .and_then(|x| x.as_i64())
        .unwrap_or(0)
}

fn string_or_empty(v: Option<&Value>) -> String {
    string_or_none(v).unwrap_or_default()
}

fn string_or_none(v: Option<&Value>) -> Option<String> {
    v.and_then(|x| {
        if x.is_null() {
            None
        } else {
            x.as_str().map(str::to_owned)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::jackson::{
        CLASS_CONCURRENT_HASH_MAP, CLASS_LONG, CLASS_SESSION, CLASS_VECTOR,
    };
    use crate::compat::{LoginIdJson, WireConfig};

    const GOLD_LOGIN_LONG: &str = r#"{"@class":"cn.dev33.satoken.session.SaSession","createTime":1791000566692,"dataMap":{"@class":"java.util.concurrent.ConcurrentHashMap"},"historyTerminalCount":1,"id":"satoken:login:session:10001","loginId":["java.lang.Long",10001],"loginType":"login","terminalList":["java.util.Vector",[{"@class":"cn.dev33.satoken.session.SaTerminalInfo","createTime":1791000566713,"deviceId":null,"deviceType":"DEF","extraData":null,"index":1,"tokenValue":"8aa19928-161c-4cae-b851-0d48a98e682c"}]],"token":null,"type":"Account-Session"}"#;

    fn java_cfg() -> WireConfig {
        WireConfig::java()
    }

    #[test]
    fn gold_login_long_roundtrip() {
        let session = decode_session(GOLD_LOGIN_LONG).unwrap();
        assert_eq!(session.id, "satoken:login:session:10001");
        assert_eq!(session.session_type, TYPE_ACCOUNT_SESSION);
        assert_eq!(session.history_terminal_count, 1);
        assert_eq!(session.create_time.timestamp_millis(), 1791000566692);
        let ext = session.wire_ext.as_deref().expect("wire_ext");
        assert_eq!(ext.login_id.as_deref(), Some("10001"));
        assert_eq!(ext.login_type.as_deref(), Some("login"));
        assert!(ext.token.is_none());
        assert_eq!(session.terminal_list.len(), 1);
        assert_eq!(
            session.terminal_list[0].token_value,
            "8aa19928-161c-4cae-b851-0d48a98e682c"
        );
        assert_eq!(session.terminal_list[0].device_type, "DEF");
        assert!(session.terminal_list[0].device_id.is_none());
        assert!(session.terminal_list[0].extra_data.is_none());
        assert_eq!(session.terminal_list[0].index, 1);

        let raw = encode_session(&session, &java_cfg()).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["@class"], CLASS_SESSION);
        assert_eq!(v["loginId"], json!([CLASS_LONG, 10001]));
        assert_eq!(v["terminalList"][0], CLASS_VECTOR);
        assert_eq!(v["dataMap"]["@class"], CLASS_CONCURRENT_HASH_MAP);
        assert_eq!(v["token"], Value::Null);
        assert_eq!(v["type"], TYPE_ACCOUNT_SESSION);
        assert_eq!(v["historyTerminalCount"], 1);

        let again = decode_session(&raw).unwrap();
        assert_eq!(again.id, session.id);
        assert_eq!(again.session_type, TYPE_ACCOUNT_SESSION);
        assert_eq!(
            again
                .wire_ext
                .as_deref()
                .and_then(|e| e.login_id.as_deref()),
            Some("10001")
        );
        assert_eq!(again.terminal_list.len(), 1);
        assert_eq!(
            again.terminal_list[0].token_value,
            "8aa19928-161c-4cae-b851-0d48a98e682c"
        );
    }

    #[test]
    fn decode_session_reads_native_serde_json() {
        let mut native = SaSession::new("s1").with_type("account");
        native.set("foo", "bar").unwrap();
        let raw = serde_json::to_string(&native).unwrap();
        assert!(raw.contains("create_time"));
        assert!(!raw.contains("@class"));

        let decoded = decode_session(&raw).unwrap();
        assert_eq!(decoded.id, "s1");
        assert_eq!(decoded.session_type, "account");
        assert_eq!(decoded.get::<String>("foo").as_deref(), Some("bar"));
        assert!(decoded.wire_ext.is_none());
    }

    #[test]
    fn native_serde_shape_unchanged_with_wire_ext() {
        let mut session = SaSession::new("s1");
        session.set("foo", "bar").unwrap();
        session.java_ext_mut().login_id = Some("10001".into());
        let v = serde_json::to_value(&session).unwrap();
        assert!(v.get("create_time").is_some());
        assert!(v.get("@class").is_none());
        assert!(v.get("dataMap").is_none());
        assert!(v.get("loginId").is_none());
        assert_eq!(v["foo"], "bar");
        assert_eq!(v["id"], "s1");
        let back: SaSession = serde_json::from_value(v).unwrap();
        assert_eq!(back.id, "s1");
        assert_eq!(back.get::<String>("foo").as_deref(), Some("bar"));
        assert!(back.wire_ext.is_none());
    }

    #[test]
    fn data_map_null_dropped_token_null_written() {
        let mut session = SaSession::new("satoken:login:session:1").with_type(TYPE_ACCOUNT_SESSION);
        session.data.insert("gone".into(), Value::Null);
        session.data.insert("keep".into(), json!("ok"));
        let raw = encode_session(&session, &java_cfg()).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert!(v["dataMap"].get("gone").is_none());
        assert_eq!(v["dataMap"]["keep"], "ok");
        assert_eq!(v["token"], Value::Null);
        assert_eq!(v["loginId"], Value::Null);
    }

    #[test]
    fn set_java_typed_preserves_long_on_encode() {
        let mut session = SaSession::new("id").with_type(TYPE_CUSTOM_SESSION);
        session.set_java_typed("ttl", json!([CLASS_LONG, -1]));
        assert_eq!(session.get::<i64>("ttl"), Some(-1));
        let raw = encode_session(&session, &java_cfg()).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["dataMap"]["ttl"], json!([CLASS_LONG, -1]));
    }

    #[test]
    fn login_id_json_string_mode() {
        let mut session = SaSession::new("id").with_type(TYPE_ACCOUNT_SESSION);
        session.java_ext_mut().login_id = Some("10001".into());
        let mut cfg = java_cfg();
        cfg.login_id_json = LoginIdJson::String;
        let raw = encode_session(&session, &cfg).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["loginId"], "10001");
    }

    #[test]
    fn empty_data_map_only_class() {
        let session = SaSession::new("id").with_type(TYPE_CUSTOM_SESSION);
        let raw = encode_session(&session, &java_cfg()).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        let dm = v["dataMap"].as_object().unwrap();
        assert_eq!(dm.len(), 1);
        assert_eq!(dm["@class"], CLASS_CONCURRENT_HASH_MAP);
    }
}
