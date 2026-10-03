//! Jackson3 `NON_FINAL` typed JSON (object-slot) codec.
//! Jackson3 `NON_FINAL` 类型化 JSON（Object 槽）编解码。
//!
//! Objects use `{ "@class": FQCN, ... }`; arrays and boxed scalars use
//! `[FQCN, payload]`. Integers that fit in `i32` stay bare JSON numbers.
//! 对象用 `{ "@class": FQCN, ... }`；数组与装箱标量用 `[FQCN, payload]`。
//! 落在 `i32` 范围内的整数保持裸 JSON 数字。

use serde_json::{Map, Number, Value, json};

use super::LoginIdJson;

/// Jackson `@class` for `java.lang.Long`.
pub const CLASS_LONG: &str = "java.lang.Long";
/// Jackson `@class` for `java.math.BigInteger`.
pub const CLASS_BIG_INTEGER: &str = "java.math.BigInteger";
/// Jackson `@class` for `java.util.ArrayList`.
pub const CLASS_ARRAY_LIST: &str = "java.util.ArrayList";
/// Jackson `@class` for `java.util.Vector`.
pub const CLASS_VECTOR: &str = "java.util.Vector";
/// Jackson `@class` for `java.util.LinkedHashMap`.
pub const CLASS_LINKED_HASH_MAP: &str = "java.util.LinkedHashMap";
/// Jackson `@class` for `java.util.concurrent.ConcurrentHashMap`.
pub const CLASS_CONCURRENT_HASH_MAP: &str = "java.util.concurrent.ConcurrentHashMap";
/// Jackson `@class` for `cn.dev33.satoken.session.SaSession`.
pub const CLASS_SESSION: &str = "cn.dev33.satoken.session.SaSession";
/// Jackson `@class` for `cn.dev33.satoken.session.SaTerminalInfo`.
pub const CLASS_TERMINAL: &str = "cn.dev33.satoken.session.SaTerminalInfo";
/// Jackson `@class` for `cn.dev33.satoken.apikey.model.ApiKeyModel`.
pub const CLASS_API_KEY: &str = "cn.dev33.satoken.apikey.model.ApiKeyModel";

/// Encode a plain JSON value as a Jackson object-slot node.
/// 将普通 JSON 编码为 Jackson Object 槽节点。
pub fn encode_object_slot(v: &Value) -> Value {
    if is_already_typed(v) {
        return v.clone();
    }
    match v {
        Value::Null | Value::Bool(_) | Value::String(_) => v.clone(),
        Value::Number(n) => encode_number(n),
        Value::Array(items) => {
            let encoded: Vec<Value> = items.iter().map(encode_object_slot).collect();
            json!([CLASS_ARRAY_LIST, encoded])
        }
        Value::Object(map) => {
            let mut out = Map::new();
            out.insert("@class".into(), json!(CLASS_LINKED_HASH_MAP));
            for (k, val) in map {
                out.insert(k.clone(), encode_object_slot(val));
            }
            Value::Object(out)
        }
    }
}

/// Decode a Jackson object-slot node into plain JSON.
/// 将 Jackson Object 槽节点解码为普通 JSON。
///
/// Typed 2-tuples are unwrapped, `@class` is stripped, unknown fields kept.
/// `[类名, x]` 二元组解包；剥 `@class`；未知字段保留。
pub fn decode_object_slot(v: &Value) -> Value {
    match v {
        Value::Array(arr) if is_typed_tuple(arr) => decode_typed_tuple(arr),
        Value::Array(arr) => Value::Array(arr.iter().map(decode_object_slot).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                if k == "@class" {
                    continue;
                }
                out.insert(k.clone(), decode_object_slot(val));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Encode `loginId` per [`LoginIdJson`].
/// 按 [`LoginIdJson`] 编码 `loginId`。
pub fn encode_login_id(id: &str, mode: LoginIdJson) -> Value {
    match mode {
        LoginIdJson::String => Value::String(id.to_owned()),
        LoginIdJson::Long => encode_as_long(id),
        LoginIdJson::Auto => {
            if is_pure_decimal(id) {
                encode_as_long(id)
            } else {
                Value::String(id.to_owned())
            }
        }
    }
}

/// Unwrap a (possibly typed) loginId node to a string.
/// 将（可能带类型包装的）loginId 节点解成字符串。
pub fn login_id_from_value(v: &Value) -> Option<String> {
    if v.is_null() {
        return None;
    }
    match decode_object_slot(v) {
        Value::Null => None,
        Value::String(s) => Some(s),
        Value::Number(n) => Some(n.to_string()),
        other => Some(other.to_string()),
    }
}

/// True when `v` is already Jackson-typed (`@class` or `[FQCN, x]`).
/// `v` 是否已是 Jackson 类型化节点。
pub fn is_already_typed(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.contains_key("@class"),
        Value::Array(a) => is_typed_tuple(a),
        _ => false,
    }
}

/// True when `arr` is a Jackson `[FQCN, payload]` wrapper.
/// `arr` 是否为 Jackson `[FQCN, payload]` 包装。
pub fn is_typed_tuple(arr: &[Value]) -> bool {
    arr.len() == 2
        && arr
            .first()
            .and_then(Value::as_str)
            .is_some_and(is_java_class_name)
}

fn is_java_class_name(s: &str) -> bool {
    if s.starts_with("java.") || s.starts_with("javax.") || s.starts_with("jakarta.") {
        return true;
    }
    let Some((pkg, cls)) = s.rsplit_once('.') else {
        return false;
    };
    if pkg.is_empty() || cls.is_empty() {
        return false;
    }
    let Some(first) = cls.chars().next() else {
        return false;
    };
    first.is_ascii_uppercase()
        && cls
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && pkg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
}

fn encode_number(n: &Number) -> Value {
    if let Some(i) = n.as_i64() {
        if (i32::MIN as i64..=i32::MAX as i64).contains(&i) {
            json!(i)
        } else {
            json!([CLASS_LONG, i])
        }
    } else if let Some(u) = n.as_u64() {
        json!([CLASS_BIG_INTEGER, u.to_string()])
    } else if let Some(f) = n.as_f64() {
        json!(f)
    } else {
        json!([CLASS_BIG_INTEGER, n.to_string()])
    }
}

fn encode_as_long(id: &str) -> Value {
    match id.parse::<i64>() {
        Ok(n) => json!([CLASS_LONG, n]),
        Err(_) => Value::String(id.to_owned()),
    }
}

fn is_pure_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn decode_typed_tuple(arr: &[Value]) -> Value {
    let class = arr.first().and_then(Value::as_str).unwrap_or("");
    let Some(payload) = arr.get(1) else {
        return Value::Null;
    };
    match payload {
        Value::Array(_) | Value::Object(_) => decode_object_slot(payload),
        Value::String(s) if class == CLASS_BIG_INTEGER || class.ends_with("BigInteger") => {
            parse_number_string(s).unwrap_or_else(|| payload.clone())
        }
        other => other.clone(),
    }
}

fn parse_number_string(s: &str) -> Option<Value> {
    if let Ok(i) = s.parse::<i64>() {
        return Some(json!(i));
    }
    if let Ok(u) = s.parse::<u64>() {
        return Some(json!(u));
    }
    s.parse::<f64>().ok().map(|f| json!(f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_primitives() {
        assert_eq!(encode_object_slot(&Value::Null), Value::Null);
        assert_eq!(encode_object_slot(&json!(true)), json!(true));
        assert_eq!(encode_object_slot(&json!("hi")), json!("hi"));
        assert_eq!(encode_object_slot(&json!(1.5)), json!(1.5));
        assert_eq!(encode_object_slot(&json!(1)), json!(1));
        assert_eq!(encode_object_slot(&json!(i32::MAX)), json!(i32::MAX));
        assert_eq!(encode_object_slot(&json!(i32::MIN)), json!(i32::MIN));
    }

    #[test]
    fn encode_long_beyond_i32() {
        let n = i32::MAX as i64 + 1;
        assert_eq!(encode_object_slot(&json!(n)), json!([CLASS_LONG, n]));
        let n = i32::MIN as i64 - 1;
        assert_eq!(encode_object_slot(&json!(n)), json!([CLASS_LONG, n]));
    }

    #[test]
    fn encode_big_integer_beyond_i64() {
        let n = u64::MAX;
        assert_eq!(
            encode_object_slot(&json!(n)),
            json!([CLASS_BIG_INTEGER, n.to_string()])
        );
    }

    #[test]
    fn encode_array_and_object() {
        assert_eq!(
            encode_object_slot(&json!([1, "a"])),
            json!([CLASS_ARRAY_LIST, [1, "a"]])
        );
        let encoded = encode_object_slot(&json!({"k": 1}));
        assert_eq!(encoded["@class"], CLASS_LINKED_HASH_MAP);
        assert_eq!(encoded["k"], 1);
    }

    #[test]
    fn encode_keeps_existing_class_and_typed_tuple() {
        let bean = json!({"@class":"com.foo.Bar","n":1});
        assert_eq!(encode_object_slot(&bean), bean);
        let typed = json!([CLASS_LONG, 10001]);
        assert_eq!(encode_object_slot(&typed), typed);
    }

    #[test]
    fn decode_unwraps_tuple_strips_class_keeps_plain_array() {
        assert_eq!(
            decode_object_slot(&json!([CLASS_LONG, 10001])),
            json!(10001)
        );
        assert_eq!(
            decode_object_slot(&json!([CLASS_ARRAY_LIST, [1, 2]])),
            json!([1, 2])
        );
        assert_eq!(decode_object_slot(&json!([1, 2])), json!([1, 2]));
        let obj = json!({"@class": CLASS_LINKED_HASH_MAP, "k": [CLASS_LONG, 3], "x": 1});
        assert_eq!(decode_object_slot(&obj), json!({"k": 3, "x": 1}));
    }

    #[test]
    fn decode_big_integer_string_or_number() {
        assert_eq!(
            decode_object_slot(&json!([CLASS_BIG_INTEGER, "18446744073709551615"])),
            json!(u64::MAX)
        );
        assert_eq!(
            decode_object_slot(&json!([CLASS_BIG_INTEGER, 123])),
            json!(123)
        );
    }

    #[test]
    fn two_element_scope_array_is_not_a_typed_tuple() {
        let v = json!(["user.read", "user.write"]);
        assert!(!is_typed_tuple(v.as_array().unwrap()));
        assert_eq!(
            encode_object_slot(&v),
            json!([CLASS_ARRAY_LIST, ["user.read", "user.write"]])
        );
    }

    #[test]
    fn login_id_auto_long_vs_string() {
        assert_eq!(
            encode_login_id("10001", LoginIdJson::Auto),
            json!([CLASS_LONG, 10001])
        );
        assert_eq!(
            encode_login_id("user-a", LoginIdJson::Auto),
            json!("user-a")
        );
        assert_eq!(
            encode_login_id("10001", LoginIdJson::String),
            json!("10001")
        );
        assert_eq!(
            encode_login_id("user-a", LoginIdJson::Long),
            json!("user-a")
        );
        assert_eq!(
            login_id_from_value(&json!([CLASS_LONG, 10001])).as_deref(),
            Some("10001")
        );
        assert_eq!(
            login_id_from_value(&json!("user-a")).as_deref(),
            Some("user-a")
        );
        assert_eq!(login_id_from_value(&Value::Null), None);
    }
}
