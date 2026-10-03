//! Java root-object codec (`setObject` / temp-token / application var).
//! Java 根对象编解码（`setObject` / 临时 Token / 应用变量）。
//!
//! Root maps are **plain JSON objects** (no `@class`). Long roots are bare
//! numbers. Decode still unwraps typed tuples and strips `@class` if present.
//! 根 Map 为**普通 JSON 对象**（无 `@class`）。Long 根为裸数字。
//! 解码仍解包类型二元组，并在存在时剥掉 `@class`。

use serde_json::Value;

use crate::error::SaTokenResult;

use super::jackson::decode_object_slot;

/// Encode a root value as plain JSON (maps without `@class`).
/// 编码根对象为普通 JSON（Map 不加 `@class`）。
pub fn encode_root(v: &Value) -> SaTokenResult<String> {
    Ok(serde_json::to_string(&decode_object_slot(v))?)
}

/// Decode a root JSON value, accepting typed or plain forms.
/// 解码根 JSON；可吃带类型包装或普通形态。
pub fn decode_root(raw: &str) -> SaTokenResult<Value> {
    let v: Value = serde_json::from_str(raw)?;
    Ok(decode_object_slot(&v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::jackson::{CLASS_LINKED_HASH_MAP, CLASS_LONG};
    use serde_json::json;

    #[test]
    fn encode_root_map_has_no_class() {
        let raw = encode_root(&json!({"name": "alice", "id": 10001})).unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        assert!(v.get("@class").is_none());
        assert_eq!(v["name"], "alice");
        assert_eq!(v["id"], 10001);
        assert!(!raw.contains("@class"));
    }

    #[test]
    fn encode_root_strips_class_from_input_map() {
        let raw = encode_root(&json!({"@class": CLASS_LINKED_HASH_MAP, "k": "v"})).unwrap();
        assert_eq!(raw, r#"{"k":"v"}"#);
    }

    #[test]
    fn encode_root_long_is_bare_number() {
        assert_eq!(encode_root(&json!(10001)).unwrap(), "10001");
        assert_eq!(encode_root(&json!([CLASS_LONG, 10001])).unwrap(), "10001");
    }

    #[test]
    fn encode_root_string_and_null() {
        assert_eq!(encode_root(&json!("hello")).unwrap(), r#""hello""#);
        assert_eq!(encode_root(&Value::Null).unwrap(), "null");
        assert_eq!(encode_root(&json!(true)).unwrap(), "true");
        assert_eq!(encode_root(&json!([1, 2])).unwrap(), "[1,2]");
    }

    #[test]
    fn decode_root_eats_typed_and_plain() {
        assert_eq!(decode_root("10001").unwrap(), json!(10001));
        assert_eq!(
            decode_root(r#"["java.lang.Long",10001]"#).unwrap(),
            json!(10001)
        );
        assert_eq!(decode_root(r#""hello""#).unwrap(), json!("hello"));
        assert_eq!(
            decode_root(r#"{"name":"alice","id":10001}"#).unwrap(),
            json!({"name": "alice", "id": 10001})
        );
        assert_eq!(
            decode_root(&format!(
                r#"{{"@class":"{CLASS_LINKED_HASH_MAP}","k":"v"}}"#
            ))
            .unwrap(),
            json!({"k": "v"})
        );
    }
}
