//! Java Sa-Token JWT claims (`loginType` / `loginId` / `rnStr` / `deviceType` / `eff`).
//! Java Sa-Token JWT claims（`loginType` / `loginId` / `rnStr` / `deviceType` / `eff`）。

use chrono::Utc;
use serde_json::{Map, Value};

use crate::compat::LoginIdJson;
use crate::error::{SaTokenError, SaTokenResult};
use crate::token::{JwtManager, random_alnum};

/// Payload key: account type | 载荷键：账号类型
pub const LOGIN_TYPE: &str = "loginType";
/// Payload key: account id | 载荷键：账号 id
pub const LOGIN_ID: &str = "loginId";
/// Payload key: device type | 载荷键：设备类型
pub const DEVICE_TYPE: &str = "deviceType";
/// Payload key: expiry as epoch milliseconds, or `-1` | 载荷键：到期毫秒时间戳，或 `-1`
pub const EFF: &str = "eff";
/// Payload key: 32-char alphanumeric nonce | 载荷键：32 位字母数字乱数
pub const RN_STR: &str = "rnStr";

/// `eff == -1` means never expire (Java `SaTokenDao.NEVER_EXPIRE`).
/// `eff == -1` 表示永不过期（Java `SaTokenDao.NEVER_EXPIRE`）。
pub const NEVER_EXPIRE: i64 = -1;

const RN_STR_LEN: usize = 32;

const JAVA_RESERVED: &[&str] = &[LOGIN_TYPE, LOGIN_ID, DEVICE_TYPE, EFF, RN_STR];
const STD_RESERVED: &[&str] = &["sub", "exp", "iss", "aud", "nbf", "iat", "jti"];

/// Inputs for encoding a Java-style JWT payload.
/// 编码 Java 风格 JWT payload 的入参。
#[derive(Debug, Clone)]
pub struct JavaJwtSpec<'a> {
    /// Stp login type written as `loginType`.
    /// 写入 `loginType` 的 Stp 账号体系。
    pub login_type: &'a str,
    /// Account id; JSON type follows [`LoginIdJson`].
    /// 账号 id；JSON 类型由 [`LoginIdJson`] 决定。
    pub login_id: &'a str,
    /// How `loginId` is encoded | `loginId` 的 JSON 编码
    pub login_id_json: LoginIdJson,
    /// Extra claims flattened into the payload | 平铺进 payload 的扩展字段
    pub extra: Option<&'a Value>,
    /// Device type for Mixin / Stateless | Mixin / Stateless 的设备类型
    pub device: Option<&'a str>,
    /// Token TTL in seconds (`-1` → `eff = -1`) | Token 有效期秒（`-1` → `eff = -1`）
    pub timeout_secs: i64,
    /// Mixin / Stateless also write `deviceType` and `eff`.
    /// Mixin / Stateless 额外写入 `deviceType` 与 `eff`。
    pub include_device_and_eff: bool,
}

/// Parsed Java JWT claims | 解析后的 Java JWT claims
#[derive(Debug, Clone)]
pub struct JavaJwtClaims {
    /// `loginType` claim | `loginType`
    pub login_type: String,
    /// `loginId` as string | 字符串形式的 `loginId`
    pub login_id: String,
    /// `deviceType` if present | 若有则是 `deviceType`
    pub device_type: Option<String>,
    /// `eff` milliseconds if present | 若有则是 `eff` 毫秒
    pub eff: Option<i64>,
    /// `rnStr` if present | 若有则是 `rnStr`
    pub rn_str: Option<String>,
    /// Non-reserved payload fields | 非保留字段
    pub extra: Map<String, Value>,
}

fn is_reserved(key: &str) -> bool {
    JAVA_RESERVED.contains(&key) || STD_RESERVED.contains(&key)
}

/// Reject extra keys that collide with Java or registered JWT claims.
/// 拒绝与 Java 保留字或标准 JWT 注册声明冲突的 extra 键。
pub fn check_extra_reserved(extra: Option<&Value>) -> SaTokenResult<()> {
    let Some(Value::Object(map)) = extra else {
        return Ok(());
    };
    for key in map.keys() {
        if is_reserved(key) {
            return Err(SaTokenError::ConfigError(format!(
                "extra must not contain reserved JWT claim '{key}'"
            )));
        }
    }
    Ok(())
}

/// Encode `loginId` per [`LoginIdJson`]. Auto: all-digit → JSON number, else string.
/// 按 [`LoginIdJson`] 编码 `loginId`。Auto：纯数字 → JSON number，否则 string。
pub fn encode_login_id(login_id: &str, mode: LoginIdJson) -> SaTokenResult<Value> {
    match mode {
        LoginIdJson::String => Ok(Value::String(login_id.to_string())),
        LoginIdJson::Long => parse_login_id_number(login_id)
            .ok_or(SaTokenError::LoginIdNotNumber)
            .map(Value::from),
        LoginIdJson::Auto => Ok(parse_login_id_number(login_id)
            .map(Value::from)
            .unwrap_or_else(|| Value::String(login_id.to_string()))),
    }
}

fn parse_login_id_number(login_id: &str) -> Option<i64> {
    if login_id.is_empty() {
        return None;
    }
    let digits = if let Some(rest) = login_id.strip_prefix('-') {
        rest
    } else {
        login_id
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return None;
    }
    login_id.parse().ok()
}

fn login_id_from_value(value: &Value) -> SaTokenResult<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        other => Err(SaTokenError::InvalidToken(format!(
            "jwt loginId must be string or number, got {other}"
        ))),
    }
}

fn string_claim(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

fn i64_claim(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

/// `timeout_secs == -1` → `eff = -1`; otherwise `now_ms + timeout_secs * 1000`.
/// `timeout_secs == -1` → `eff = -1`；否则 `now_ms + timeout_secs * 1000`。
pub fn eff_millis(timeout_secs: i64, now_ms: i64) -> i64 {
    if timeout_secs == NEVER_EXPIRE {
        NEVER_EXPIRE
    } else {
        now_ms.saturating_add(timeout_secs.saturating_mul(1000))
    }
}

/// Missing / 0 → expired; `-1` → never; otherwise expire when `eff < now_ms`.
/// 缺失或 0 视为过期；`-1` 永不过期；否则 `eff < now_ms` 过期。
pub fn is_eff_expired(eff: Option<i64>, now_ms: i64) -> bool {
    match eff {
        None | Some(0) => true,
        Some(NEVER_EXPIRE) => false,
        Some(ts) => ts < now_ms,
    }
}

/// Build and sign a Java-style JWT (header `"typ":"JWT"`).
/// 构建并签发 Java 风格 JWT（header 含 `"typ":"JWT"`）。
pub fn generate(mgr: &JwtManager, spec: &JavaJwtSpec<'_>) -> SaTokenResult<String> {
    check_extra_reserved(spec.extra)?;
    let login_id = encode_login_id(spec.login_id, spec.login_id_json)?;
    let rn_str = random_alnum(RN_STR_LEN)?;
    let mut payload = Map::new();
    payload.insert(
        LOGIN_TYPE.to_string(),
        Value::String(spec.login_type.to_string()),
    );
    payload.insert(LOGIN_ID.to_string(), login_id);
    if spec.include_device_and_eff {
        let device = spec.device.unwrap_or("");
        payload.insert(DEVICE_TYPE.to_string(), Value::String(device.to_string()));
        payload.insert(
            EFF.to_string(),
            Value::from(eff_millis(spec.timeout_secs, Utc::now().timestamp_millis())),
        );
    }
    payload.insert(RN_STR.to_string(), Value::String(rn_str));
    match spec.extra {
        Some(Value::Object(map)) => {
            for (k, v) in map {
                payload.insert(k.clone(), v.clone());
            }
        }
        Some(Value::Null) | None => {}
        Some(other) => {
            payload.insert("extra".to_string(), other.clone());
        }
    }
    mgr.generate_payload(&Value::Object(payload))
}

/// Parse a verified payload into [`JavaJwtClaims`].
/// 把已验签 payload 解析为 [`JavaJwtClaims`]。
pub fn parse_payload(payload: &Value) -> SaTokenResult<JavaJwtClaims> {
    let obj = payload
        .as_object()
        .ok_or_else(|| SaTokenError::InvalidToken("jwt payload must be a JSON object".into()))?;
    let login_id_raw = obj
        .get(LOGIN_ID)
        .ok_or_else(|| SaTokenError::InvalidToken("jwt missing loginId".into()))?;
    let mut extra = Map::new();
    for (k, v) in obj {
        if !is_reserved(k) {
            extra.insert(k.clone(), v.clone());
        }
    }
    Ok(JavaJwtClaims {
        login_type: string_claim(obj.get(LOGIN_TYPE)).unwrap_or_default(),
        login_id: login_id_from_value(login_id_raw)?,
        device_type: string_claim(obj.get(DEVICE_TYPE)),
        eff: i64_claim(obj.get(EFF)),
        rn_str: string_claim(obj.get(RN_STR)),
        extra,
    })
}

/// Verify signature, `loginType`, and optionally `eff`.
/// 验签、校验 `loginType`，并按需校验 `eff`。
pub fn validate(
    mgr: &JwtManager,
    token: &str,
    expected_login_type: &str,
    check_eff: bool,
) -> SaTokenResult<JavaJwtClaims> {
    let payload = mgr.validate_payload(token)?;
    let claims = parse_payload(&payload)?;
    if claims.login_type != expected_login_type {
        return Err(SaTokenError::InvalidToken(format!(
            "jwt loginType invalid: expected '{expected_login_type}', got '{}'",
            claims.login_type
        )));
    }
    if check_eff && is_eff_expired(claims.eff, Utc::now().timestamp_millis()) {
        return Err(SaTokenError::TokenExpired);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::WireConfig;
    use crate::config::{SaTokenConfig, TokenStyle};
    use crate::token::{TokenGenContext, TokenGenerator};

    const SECRET: &str = "java-interop-secret-key-32bytes!!";
    const GOLD_SIMPLE: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpblR5cGUiOiJsb2dpbiIsImxvZ2luSWQiOjEwMDAxLCJyblN0ciI6ImJPc2g3b1VCOTcyM1N3N1NQY2hRV1hCcUIzMWcxY1E3IiwiYWdlIjoxOH0.KGkZdQc_8mA6TaSeTMfk2xnVduCHojY9Oq2YtEAHNfA";
    const GOLD_STATELESS: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpblR5cGUiOiJsb2dpbiIsImxvZ2luSWQiOjEwMDAxLCJkZXZpY2VUeXBlIjoiREVGIiwiZWZmIjotMSwicm5TdHIiOiJMZkZVZUtVWWZQaGR1cUtRM3pQNmZNOWVBUjg2cEJWVyJ9.K_8AT11-ouT4HyTQZXY3WIqyHtzIW6Lm740dBD0c0Cw";
    const GOLD_EXPIRED: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpblR5cGUiOiJsb2dpbiIsImxvZ2luSWQiOjEwMDAxLCJkZXZpY2VUeXBlIjoiREVGIiwiZWZmIjoxLCJyblN0ciI6ImV4cGlyZWRGaXh0dXJlUm5TdHIwMDAwMDAwMDAwMDEifQ.oM2YNiVFOikZbmIo1kDGi5hXcuXxSP6jtoavbg8AbhY";

    fn mgr() -> JwtManager {
        JwtManager::new(SECRET)
    }

    fn java_cfg(style: TokenStyle) -> SaTokenConfig {
        SaTokenConfig {
            token_style: style,
            jwt_secret_key: Some(SECRET.to_string()),
            timeout: -1,
            wire: WireConfig::java(),
            ..SaTokenConfig::default()
        }
    }

    fn decode_payload(token: &str) -> Value {
        jsonwebtoken::dangerous::insecure_decode::<Value>(token)
            .expect("decode")
            .claims
    }

    fn is_alnum32(s: &str) -> bool {
        s.len() == 32 && s.bytes().all(|b| b.is_ascii_alphanumeric())
    }

    #[test]
    fn generate_simple_java_claims_shape() {
        let cfg = java_cfg(TokenStyle::Jwt);
        let ctx = TokenGenContext {
            login_id: "10001".into(),
            login_type: "login".into(),
            device: Some("DEF".into()),
            timeout_secs: -1,
            extra: Some(serde_json::json!({"age": 18})),
        };
        let token = TokenGenerator::generate_for(&cfg, &ctx).unwrap();
        let header = jsonwebtoken::decode_header(token.as_str()).unwrap();
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        let payload = decode_payload(token.as_str());
        let obj = payload.as_object().unwrap();
        assert_eq!(obj.get(LOGIN_TYPE), Some(&Value::String("login".into())));
        assert_eq!(obj.get(LOGIN_ID), Some(&serde_json::json!(10001)));
        assert_eq!(obj.get("age"), Some(&serde_json::json!(18)));
        let rn = obj.get(RN_STR).and_then(Value::as_str).unwrap();
        assert!(is_alnum32(rn), "rnStr={rn}");
        assert!(!obj.contains_key(EFF));
        assert!(!obj.contains_key(DEVICE_TYPE));
    }

    #[test]
    fn validate_gold_simple_token() {
        let claims = validate(&mgr(), GOLD_SIMPLE, "login", false).unwrap();
        assert_eq!(claims.login_type, "login");
        assert_eq!(claims.login_id, "10001");
        assert!(claims.eff.is_none());
        assert!(claims.device_type.is_none());
        assert_eq!(claims.extra.get("age"), Some(&serde_json::json!(18)));
        assert!(is_alnum32(claims.rn_str.as_deref().unwrap_or("")));
    }

    #[test]
    fn extra_reserved_key_is_rejected() {
        let cfg = java_cfg(TokenStyle::Jwt);
        let ctx = TokenGenContext {
            login_id: "10001".into(),
            login_type: "login".into(),
            device: None,
            timeout_secs: -1,
            extra: Some(serde_json::json!({"loginId": 1})),
        };
        let err = TokenGenerator::generate_for(&cfg, &ctx).unwrap_err();
        assert!(
            err.to_string().contains("loginId"),
            "unexpected error: {err}"
        );

        let ctx = TokenGenContext {
            extra: Some(serde_json::json!({"sub": "x"})),
            ..ctx
        };
        let err = TokenGenerator::generate_for(&cfg, &ctx).unwrap_err();
        assert!(err.to_string().contains("sub"), "unexpected error: {err}");
    }

    #[test]
    fn stateless_java_eff_minus_one_not_expired() {
        let cfg = java_cfg(TokenStyle::JwtStateless);
        let ctx = TokenGenContext {
            login_id: "10001".into(),
            login_type: "login".into(),
            device: Some("DEF".into()),
            timeout_secs: -1,
            extra: None,
        };
        let token = TokenGenerator::generate_for(&cfg, &ctx).unwrap();
        let payload = decode_payload(token.as_str());
        assert_eq!(payload.get(DEVICE_TYPE), Some(&Value::String("DEF".into())));
        assert_eq!(payload.get(EFF), Some(&serde_json::json!(-1)));
        let claims = validate(&mgr(), token.as_str(), "login", true).unwrap();
        assert_eq!(claims.login_id, "10001");
        assert_eq!(claims.eff, Some(NEVER_EXPIRE));
        assert!(!is_eff_expired(claims.eff, Utc::now().timestamp_millis()));
    }

    #[test]
    fn validate_gold_stateless_and_expired() {
        let claims = validate(&mgr(), GOLD_STATELESS, "login", true).unwrap();
        assert_eq!(claims.login_id, "10001");
        assert_eq!(claims.device_type.as_deref(), Some("DEF"));
        assert_eq!(claims.eff, Some(NEVER_EXPIRE));

        let err = validate(&mgr(), GOLD_EXPIRED, "login", true).unwrap_err();
        assert!(
            matches!(err, SaTokenError::TokenExpired),
            "expected TokenExpired, got {err:?}"
        );
    }

    #[test]
    fn encode_login_id_auto() {
        assert_eq!(
            encode_login_id("10001", LoginIdJson::Auto).unwrap(),
            serde_json::json!(10001)
        );
        assert_eq!(
            encode_login_id("user-a", LoginIdJson::Auto).unwrap(),
            serde_json::json!("user-a")
        );
        assert_eq!(
            encode_login_id("01001", LoginIdJson::Auto).unwrap(),
            serde_json::json!("01001")
        );
    }
}
