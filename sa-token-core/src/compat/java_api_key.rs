//! Jackson3 mapping for Java `ApiKeyModel`.
//! Java `ApiKeyModel` 的 Jackson3 字段映射。

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use crate::api_key::ApiKeyModel;
use crate::error::SaTokenResult;

use super::LoginIdJson;
use super::jackson::{
    CLASS_API_KEY, decode_object_slot, encode_login_id, encode_object_slot, login_id_from_value,
};

/// Encode [`ApiKeyModel`] as Jackson3 typed JSON.
/// 将 [`ApiKeyModel`] 编码为 Jackson3 类型化 JSON。
pub fn encode_api_key(model: &ApiKeyModel, login_id_json: LoginIdJson) -> SaTokenResult<String> {
    let mut obj = Map::new();
    obj.insert("@class".into(), json!(CLASS_API_KEY));
    obj.insert("apiKey".into(), json!(model.api_key));
    obj.insert("createTime".into(), json!(model.create_time));
    obj.insert("expiresTime".into(), json!(model.expires_time));
    obj.insert(
        "extraData".into(),
        encode_extra_data(model.extra_data.as_ref()),
    );
    obj.insert("intro".into(), empty_as_null(&model.intro));
    obj.insert("isValid".into(), json!(model.is_valid));
    obj.insert(
        "loginId".into(),
        if model.login_id.is_empty() {
            Value::Null
        } else {
            encode_login_id(&model.login_id, login_id_json)
        },
    );
    obj.insert("scopes".into(), encode_object_slot(&json!(model.scopes)));
    obj.insert("title".into(), empty_as_null(&model.title));
    Ok(serde_json::to_string(&Value::Object(obj))?)
}

/// Decode Jackson3 `ApiKeyModel` JSON.
/// 解码 Jackson3 `ApiKeyModel` JSON。
pub fn decode_api_key(raw: &str) -> SaTokenResult<ApiKeyModel> {
    let v: Value = serde_json::from_str(raw)?;
    let obj = v.as_object().ok_or_else(|| {
        crate::error::SaTokenError::SerializationError("api key must be a JSON object".into())
    })?;
    Ok(ApiKeyModel {
        title: string_field(obj, "title"),
        intro: string_field(obj, "intro"),
        api_key: string_field(obj, "apiKey"),
        login_id: obj
            .get("loginId")
            .and_then(login_id_from_value)
            .unwrap_or_default(),
        create_time: obj.get("createTime").and_then(Value::as_i64).unwrap_or(0),
        expires_time: obj.get("expiresTime").and_then(Value::as_i64).unwrap_or(0),
        is_valid: obj.get("isValid").and_then(Value::as_bool).unwrap_or(true),
        scopes: decode_scopes(obj.get("scopes")),
        extra_data: decode_extra_data(obj.get("extraData")),
    })
}

fn empty_as_null(s: &str) -> Value {
    if s.is_empty() { Value::Null } else { json!(s) }
}

fn encode_extra_data(extra: Option<&HashMap<String, Value>>) -> Value {
    match extra {
        Some(map) if !map.is_empty() => {
            let obj: Map<String, Value> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            encode_object_slot(&Value::Object(obj))
        }
        _ => Value::Null,
    }
}

fn decode_extra_data(v: Option<&Value>) -> Option<HashMap<String, Value>> {
    let v = v?;
    if v.is_null() {
        return None;
    }
    decode_object_slot(v)
        .as_object()
        .map(|m| m.iter().map(|(k, val)| (k.clone(), val.clone())).collect())
}

fn decode_scopes(v: Option<&Value>) -> Vec<String> {
    let Some(v) = v else {
        return Vec::new();
    };
    decode_object_slot(v)
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|i| i.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn string_field(obj: &Map<String, Value>, key: &str) -> String {
    obj.get(key)
        .and_then(|x| {
            if x.is_null() {
                None
            } else {
                x.as_str().map(str::to_owned)
            }
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::LoginIdJson;
    use crate::compat::jackson::{CLASS_ARRAY_LIST, CLASS_LONG};

    const GOLD: &str = r#"{"@class":"cn.dev33.satoken.apikey.model.ApiKeyModel","apiKey":"AK-ww2zZl3h7sbRcNis1LI4WqLsH4b1lkoUzPww","createTime":1791000566764,"expiresTime":-1,"extraData":null,"intro":null,"isValid":true,"loginId":["java.lang.Long",10001],"scopes":["java.util.ArrayList",["user.read"]],"title":"interop"}"#;

    #[test]
    fn gold_apikey_roundtrip() {
        let model = decode_api_key(GOLD).unwrap();
        assert_eq!(model.api_key, "AK-ww2zZl3h7sbRcNis1LI4WqLsH4b1lkoUzPww");
        assert_eq!(model.title, "interop");
        assert!(model.intro.is_empty());
        assert_eq!(model.login_id, "10001");
        assert_eq!(model.expires_time, -1);
        assert!(model.is_valid);
        assert_eq!(model.scopes, vec!["user.read"]);
        assert!(model.extra_data.is_none());

        let raw = encode_api_key(&model, LoginIdJson::Auto).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["@class"], CLASS_API_KEY);
        assert_eq!(v["apiKey"], model.api_key);
        assert_eq!(v["loginId"], json!([CLASS_LONG, 10001]));
        assert_eq!(v["scopes"][0], CLASS_ARRAY_LIST);
        assert_eq!(v["scopes"][1], json!(["user.read"]));
        assert_eq!(v["extraData"], Value::Null);
        assert_eq!(v["intro"], Value::Null);
        assert_eq!(v["isValid"], true);
        assert_eq!(v["expiresTime"], -1);
        assert_eq!(v["title"], "interop");

        let again = decode_api_key(&raw).unwrap();
        assert_eq!(again.api_key, model.api_key);
        assert_eq!(again.login_id, "10001");
        assert_eq!(again.scopes, model.scopes);
    }
}
