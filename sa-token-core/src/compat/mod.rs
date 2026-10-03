//! Java / native wire-format compatibility.
//! Java / 原生值格式互通。
//!
//! [`WireConfig`] holds independently switchable format knobs. Native defaults
//! keep current Rust behaviour; [`WireConfig::java`] matches Sa-Token v1.46.0.
//! [`WireConfig`] 按项配置值格式。原生默认保持现有 Rust 行为；
//! [`WireConfig::java`] 对齐 Sa-Token v1.46.0。

pub mod jackson;
pub mod java_api_key;
pub mod java_jwt;
pub mod java_session;
pub mod java_value;

pub use java_session::JavaSessionExt;

use sa_token_adapter::serializer::SharedSerializer;
use serde::{Deserialize, Deserializer, Serialize, de::Error as DeError};

use crate::codec::{decode_value, encode_value};
use crate::config::SaTokenConfig;
use crate::error::{SaTokenError, SaTokenResult};
use crate::session::SaSession;

/// Token value stored at the token key.
/// Token 键内存放的值格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenValueFormat {
    /// Full `TokenInfo` JSON (Rust default).
    /// 完整 `TokenInfo` JSON（Rust 默认）。
    #[serde(alias = "info-json")]
    InfoJson,
    /// Bare loginId string (Java default).
    /// 纯 loginId 字符串（Java 默认）。
    #[serde(alias = "login-id")]
    LoginId,
}

/// Where last-active timestamps are stored.
/// 最后活跃时间的存放位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LastActiveStore {
    /// Embedded in `TokenInfo` (Rust default).
    /// 写在 `TokenInfo` 内（Rust 默认）。
    #[serde(alias = "in-token-info")]
    InTokenInfo,
    /// Separate `{tn}:{type}:last-active:{token}` key (Java).
    /// 独立 `{tn}:{type}:last-active:{token}` 键（Java）。
    #[serde(alias = "separate-key")]
    SeparateKey,
}

/// How an account's online tokens are indexed.
/// 账号在线 token 的反查索引方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountIndex {
    /// Rust `login:token` / `login:tokens` keys.
    /// Rust `login:token` / `login:tokens` 键。
    #[serde(alias = "rust-index-keys")]
    RustIndexKeys,
    /// Java Account-Session `terminalList`.
    /// Java Account-Session `terminalList`。
    #[serde(alias = "session-terminals")]
    SessionTerminals,
}

/// Account / token session JSON format.
/// Account / Token Session 的 JSON 格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionFormat {
    /// Native serde (`snake_case` / RFC3339).
    /// 原生 serde（`snake_case` / RFC3339）。
    #[serde(alias = "serde")]
    Serde,
    /// Jackson3 typed JSON (`@class` / camelCase / ms).
    /// Jackson3 类型化 JSON（`@class` / camelCase / ms）。
    #[serde(alias = "jackson3-typed")]
    Jackson3Typed,
}

/// How loginId is encoded inside JSON values.
/// JSON 中 loginId 的编码方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginIdJson {
    /// Infer from the written value.
    /// 按写入值推断。
    #[serde(alias = "auto")]
    Auto,
    /// Always a JSON string.
    /// 始终为 JSON 字符串。
    #[serde(alias = "string")]
    String,
    /// Always a JSON number (Java `Long`).
    /// 始终为 JSON 数字（Java `Long`）。
    #[serde(alias = "long")]
    Long,
}

/// Temp-token payload format.
/// 临时 Token 的值格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TempTokenFormat {
    /// Wrapped native record.
    /// 原生包装记录。
    #[serde(alias = "wrapped")]
    Wrapped,
    /// Java raw root object.
    /// Java 裸根对象。
    #[serde(alias = "java-raw")]
    JavaRaw,
}

/// API-key model format.
/// API Key 模型格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiKeyFormat {
    /// Native serde model.
    /// 原生 serde 模型。
    #[serde(alias = "serde")]
    Serde,
    /// Java `ApiKeyModel`.
    /// Java `ApiKeyModel`。
    #[serde(alias = "java-model")]
    JavaModel,
}

/// Application / root-object JSON format.
/// 应用变量 / 根对象 JSON 格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplicationValue {
    /// Native serde JSON.
    /// 原生 serde JSON。
    #[serde(alias = "serde")]
    Serde,
    /// Java root object (`@class` map).
    /// Java 根对象（`@class` map）。
    #[serde(alias = "java-root")]
    JavaRoot,
}

/// JWT claims layout.
/// JWT claims 布局。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwtClaimsFormat {
    /// Standard `sub` / `exp` claims.
    /// 标准 `sub` / `exp` claims。
    #[serde(alias = "standard")]
    Standard,
    /// Java `loginType` / `loginId` / `eff` claims.
    /// Java `loginType` / `loginId` / `eff` claims。
    #[serde(alias = "java")]
    Java,
}

/// Request-sign nonce occupancy format.
/// 请求签名 nonce 占位格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignNonceFormat {
    /// Native nonce record.
    /// 原生 nonce 记录。
    #[serde(alias = "rust")]
    Rust,
    /// Java nonce occupancy (value = nonce).
    /// Java nonce 占位（值为 nonce 本身）。
    #[serde(alias = "java")]
    Java,
}

/// Request-sign algorithm.
/// 请求签名算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignAlgorithm {
    /// HMAC-SHA256 over seconds (Rust default).
    /// HMAC-SHA256，秒级时间戳（Rust 默认）。
    #[serde(alias = "hmac-sha256")]
    HmacSha256,
    /// Java `SaSignTemplate` MD5 (`k=v&...&key=secret`, ms timestamp).
    /// Java `SaSignTemplate` MD5（`k=v&...&key=secret`，毫秒时间戳）。
    #[serde(alias = "md5")]
    Md5,
}

/// Same-Token past-key TTL policy.
/// Same-Token 旧键 TTL 策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SameTokenPastTtl {
    /// Copy the full timeout.
    /// 使用完整 timeout。
    #[serde(alias = "full")]
    Full,
    /// Remaining lifetime of the previous token (Java).
    /// 沿用上一枚 token 的剩余寿命（Java）。
    #[serde(alias = "remaining")]
    Remaining,
}

/// Opaque token string algorithm (Random / Tik / Same-Token / API Key suffix).
/// 不透明 token 字符串算法（Random / Tik / Same-Token / API Key 后缀）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpaqueGen {
    /// Native: Random hex; Tik 8-char alnum; Same-Token 32 hex; API Key suffix 36 hex.
    /// 原生：Random 为 hex；Tik 8 位字母数字；Same-Token 32 位 hex；API Key 后缀 36 位 hex。
    #[serde(alias = "native")]
    Native,
    /// Java 1.46.0: Random `[A-Za-z0-9]`; Tik `{2}_{14}_{16}__`; Same-Token 64 alnum; API Key suffix 36 alnum.
    /// Java 1.46.0：Random 为 `[A-Za-z0-9]`；Tik 为 `{2}_{14}_{16}__`；Same-Token 64 位字母数字；API Key 后缀 36 位字母数字。
    #[serde(alias = "java")]
    Java,
}

/// Independently switchable wire-format knobs.
/// 可逐项切换的值格式配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WireConfig {
    /// Default account-system id used when a login type is omitted.
    /// 省略 login_type 时使用的默认账号体系。
    pub default_login_type: String,
    /// Token-key value format | Token 键值格式
    pub token_value: TokenValueFormat,
    /// Last-active storage | 最后活跃存放位置
    pub last_active: LastActiveStore,
    /// Account token index | 账号 token 反查索引
    pub account_index: AccountIndex,
    /// Session JSON format | Session JSON 格式
    pub session_format: SessionFormat,
    /// loginId JSON encoding | loginId JSON 编码
    pub login_id_json: LoginIdJson,
    /// Whether `login_id` may contain `:`.
    /// `login_id` 是否允许包含 `:`。
    pub allow_login_id_colon: bool,
    /// Default device type when login omits device (`None` = empty).
    /// 登录未指定设备时的默认设备类型（`None` 表示空）。
    pub default_device_type: Option<String>,
    /// Secondary-auth occupancy value | 二级认证占位值
    pub safe_value: String,
    /// Default secondary-auth service name | 默认二级认证服务名
    pub default_safe_service: String,
    /// Default disable service name | 默认封禁服务名
    pub default_disable_service: String,
    /// Temp-token payload format | 临时 Token 值格式
    pub temp_token_format: TempTokenFormat,
    /// Temp-token key namespace | 临时 Token 键命名空间
    pub temp_token_namespace: String,
    /// API-key model format | API Key 模型格式
    pub api_key_format: ApiKeyFormat,
    /// API-key key namespace | API Key 键命名空间
    pub api_key_namespace: String,
    /// Application / root-object format | 应用变量 / 根对象格式
    pub application_value: ApplicationValue,
    /// JWT claims layout | JWT claims 布局
    pub jwt_claims: JwtClaimsFormat,
    /// Sign nonce occupancy format | 签名 nonce 占位格式
    pub sign_nonce: SignNonceFormat,
    /// Request-sign algorithm | 请求签名算法
    pub sign_algorithm: SignAlgorithm,
    /// Same-Token past-key TTL | Same-Token 旧键 TTL
    pub same_token_past_ttl: SameTokenPastTtl,
    /// Opaque token string algorithm | 不透明 token 字符串算法
    pub opaque_gen: OpaqueGen,
}

impl Default for WireConfig {
    fn default() -> Self {
        Self::native()
    }
}

impl WireConfig {
    /// Native Rust defaults. Same as [`Default`].
    /// 原生 Rust 默认值，等同 [`Default`]。
    pub fn native() -> Self {
        Self {
            default_login_type: "default".into(),
            token_value: TokenValueFormat::InfoJson,
            last_active: LastActiveStore::InTokenInfo,
            account_index: AccountIndex::RustIndexKeys,
            session_format: SessionFormat::Serde,
            login_id_json: LoginIdJson::Auto,
            allow_login_id_colon: true,
            default_device_type: None,
            safe_value: "ok".into(),
            default_safe_service: String::new(),
            default_disable_service: "login".into(),
            temp_token_format: TempTokenFormat::Wrapped,
            temp_token_namespace: "default".into(),
            api_key_format: ApiKeyFormat::Serde,
            api_key_namespace: "apikey".into(),
            application_value: ApplicationValue::Serde,
            jwt_claims: JwtClaimsFormat::Standard,
            sign_nonce: SignNonceFormat::Rust,
            sign_algorithm: SignAlgorithm::HmacSha256,
            same_token_past_ttl: SameTokenPastTtl::Full,
            opaque_gen: OpaqueGen::Native,
        }
    }

    /// Java Sa-Token v1.46.0 defaults.
    /// Java Sa-Token v1.46.0 默认值。
    pub fn java() -> Self {
        Self {
            default_login_type: "login".into(),
            token_value: TokenValueFormat::LoginId,
            last_active: LastActiveStore::SeparateKey,
            account_index: AccountIndex::SessionTerminals,
            session_format: SessionFormat::Jackson3Typed,
            login_id_json: LoginIdJson::Auto,
            allow_login_id_colon: false,
            default_device_type: Some("DEF".into()),
            safe_value: "SAFE_AUTH_SAVE_VALUE".into(),
            default_safe_service: "important".into(),
            default_disable_service: "login".into(),
            temp_token_format: TempTokenFormat::JavaRaw,
            temp_token_namespace: "temp-token".into(),
            api_key_format: ApiKeyFormat::JavaModel,
            api_key_namespace: "apikey".into(),
            application_value: ApplicationValue::JavaRoot,
            jwt_claims: JwtClaimsFormat::Java,
            sign_nonce: SignNonceFormat::Java,
            sign_algorithm: SignAlgorithm::Md5,
            same_token_past_ttl: SameTokenPastTtl::Remaining,
            opaque_gen: OpaqueGen::Java,
        }
    }
}

#[derive(Deserialize)]
struct WireConfigOverlay {
    #[serde(default)]
    preset: Option<String>,
    #[serde(default)]
    default_login_type: Option<String>,
    #[serde(default)]
    token_value: Option<TokenValueFormat>,
    #[serde(default)]
    last_active: Option<LastActiveStore>,
    #[serde(default)]
    account_index: Option<AccountIndex>,
    #[serde(default)]
    session_format: Option<SessionFormat>,
    #[serde(default)]
    login_id_json: Option<LoginIdJson>,
    #[serde(default)]
    allow_login_id_colon: Option<bool>,
    #[serde(default)]
    default_device_type: Option<String>,
    #[serde(default)]
    safe_value: Option<String>,
    #[serde(default)]
    default_safe_service: Option<String>,
    #[serde(default)]
    default_disable_service: Option<String>,
    #[serde(default)]
    temp_token_format: Option<TempTokenFormat>,
    #[serde(default)]
    temp_token_namespace: Option<String>,
    #[serde(default)]
    api_key_format: Option<ApiKeyFormat>,
    #[serde(default)]
    api_key_namespace: Option<String>,
    #[serde(default)]
    application_value: Option<ApplicationValue>,
    #[serde(default)]
    jwt_claims: Option<JwtClaimsFormat>,
    #[serde(default)]
    sign_nonce: Option<SignNonceFormat>,
    #[serde(default)]
    sign_algorithm: Option<SignAlgorithm>,
    #[serde(default)]
    same_token_past_ttl: Option<SameTokenPastTtl>,
    #[serde(default)]
    opaque_gen: Option<OpaqueGen>,
}

fn parse_wire_preset(s: &str) -> Result<WireConfig, String> {
    match s.trim() {
        v if v.eq_ignore_ascii_case("java") => Ok(WireConfig::java()),
        v if v.eq_ignore_ascii_case("native") => Ok(WireConfig::native()),
        other => Err(format!(
            "unknown wire preset '{other}', expected \"native\" or \"java\""
        )),
    }
}

impl WireConfigOverlay {
    fn into_config(self) -> Result<WireConfig, String> {
        let mut cfg = match self.preset.as_deref() {
            None | Some("") => WireConfig::native(),
            Some(s) => parse_wire_preset(s)?,
        };
        if let Some(v) = self.default_login_type {
            cfg.default_login_type = v;
        }
        if let Some(v) = self.token_value {
            cfg.token_value = v;
        }
        if let Some(v) = self.last_active {
            cfg.last_active = v;
        }
        if let Some(v) = self.account_index {
            cfg.account_index = v;
        }
        if let Some(v) = self.session_format {
            cfg.session_format = v;
        }
        if let Some(v) = self.login_id_json {
            cfg.login_id_json = v;
        }
        if let Some(v) = self.allow_login_id_colon {
            cfg.allow_login_id_colon = v;
        }
        if let Some(v) = self.default_device_type {
            cfg.default_device_type = Some(v);
        }
        if let Some(v) = self.safe_value {
            cfg.safe_value = v;
        }
        if let Some(v) = self.default_safe_service {
            cfg.default_safe_service = v;
        }
        if let Some(v) = self.default_disable_service {
            cfg.default_disable_service = v;
        }
        if let Some(v) = self.temp_token_format {
            cfg.temp_token_format = v;
        }
        if let Some(v) = self.temp_token_namespace {
            cfg.temp_token_namespace = v;
        }
        if let Some(v) = self.api_key_format {
            cfg.api_key_format = v;
        }
        if let Some(v) = self.api_key_namespace {
            cfg.api_key_namespace = v;
        }
        if let Some(v) = self.application_value {
            cfg.application_value = v;
        }
        if let Some(v) = self.jwt_claims {
            cfg.jwt_claims = v;
        }
        if let Some(v) = self.sign_nonce {
            cfg.sign_nonce = v;
        }
        if let Some(v) = self.sign_algorithm {
            cfg.sign_algorithm = v;
        }
        if let Some(v) = self.same_token_past_ttl {
            cfg.same_token_past_ttl = v;
        }
        if let Some(v) = self.opaque_gen {
            cfg.opaque_gen = v;
        }
        Ok(cfg)
    }
}

impl<'de> Deserialize<'de> for WireConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum WireConfigDe {
            Preset(String),
            Map(WireConfigOverlay),
        }
        match WireConfigDe::deserialize(deserializer)? {
            WireConfigDe::Preset(s) => parse_wire_preset(&s).map_err(D::Error::custom),
            WireConfigDe::Map(overlay) => overlay.into_config().map_err(D::Error::custom),
        }
    }
}

/// Value codec selected by [`WireConfig`].
/// 由 [`WireConfig`] 选择的值编解码器。
#[derive(Clone)]
pub struct WireCodec {
    config: WireConfig,
    serializer: SharedSerializer,
}

impl std::fmt::Debug for WireCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireCodec")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl WireCodec {
    /// Build from a full [`SaTokenConfig`].
    /// 从完整 [`SaTokenConfig`] 构建。
    pub fn from_config(cfg: &SaTokenConfig) -> Self {
        Self {
            config: cfg.wire.clone(),
            serializer: cfg.serializer.clone(),
        }
    }

    /// Active wire knobs | 当前值格式配置
    pub fn config(&self) -> &WireConfig {
        &self.config
    }

    /// Encode an account / token session.
    /// 编码 Account / Token Session。
    pub fn encode_session(&self, s: &SaSession) -> SaTokenResult<String> {
        match self.config.session_format {
            SessionFormat::Serde => encode_value(&self.serializer, s),
            SessionFormat::Jackson3Typed => java_session::encode_session(s, &self.config),
        }
    }

    /// Decode an account / token session.
    /// 解码 Account / Token Session。
    ///
    /// Jackson3 path auto-detects native serde JSON (`create_time`) vs
    /// Jackson (`@class` / `createTime`).
    /// Jackson3 路径自动识别原生 serde JSON 与 Jackson JSON。
    pub fn decode_session(&self, raw: &str) -> SaTokenResult<SaSession> {
        match self.config.session_format {
            SessionFormat::Serde => decode_value(&self.serializer, raw),
            SessionFormat::Jackson3Typed => java_session::decode_session(raw),
        }
    }

    /// Encode an application / temp-token root value.
    /// 编码应用变量 / 临时 Token 根对象。
    pub fn encode_root(&self, v: &serde_json::Value) -> SaTokenResult<String> {
        match self.config.application_value {
            ApplicationValue::Serde => serde_json::to_string(v)
                .map_err(|e| SaTokenError::ConfigError(format!("encode root json failed: {e}"))),
            ApplicationValue::JavaRoot => java_value::encode_root(v),
        }
    }

    /// Decode an application / temp-token root value.
    /// 解码应用变量 / 临时 Token 根对象。
    pub fn decode_root(&self, raw: &str) -> SaTokenResult<serde_json::Value> {
        match self.config.application_value {
            ApplicationValue::Serde => serde_json::from_str(raw)
                .map_err(|e| SaTokenError::ConfigError(format!("decode root json failed: {e}"))),
            ApplicationValue::JavaRoot => java_value::decode_root(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokenStyle;
    use crate::keys::SaKeyLayout;

    #[derive(Deserialize)]
    struct Wrap {
        wire: WireConfig,
    }

    #[test]
    fn native_is_default() {
        assert_eq!(WireConfig::native(), WireConfig::default());
        assert_eq!(WireConfig::native().default_login_type, "default");
        assert_eq!(WireConfig::native().token_value, TokenValueFormat::InfoJson);
        assert_eq!(
            WireConfig::native().last_active,
            LastActiveStore::InTokenInfo
        );
        assert!(WireConfig::native().allow_login_id_colon);
        assert_eq!(WireConfig::native().default_device_type, None);
        assert_eq!(WireConfig::native().safe_value, "ok");
        assert_eq!(WireConfig::native().temp_token_namespace, "default");
        assert_eq!(WireConfig::native().opaque_gen, OpaqueGen::Native);
    }

    #[test]
    fn java_preset_fields() {
        let j = WireConfig::java();
        assert_eq!(j.default_login_type, "login");
        assert_eq!(j.token_value, TokenValueFormat::LoginId);
        assert_eq!(j.last_active, LastActiveStore::SeparateKey);
        assert_eq!(j.account_index, AccountIndex::SessionTerminals);
        assert_eq!(j.session_format, SessionFormat::Jackson3Typed);
        assert!(!j.allow_login_id_colon);
        assert_eq!(j.default_device_type.as_deref(), Some("DEF"));
        assert_eq!(j.safe_value, "SAFE_AUTH_SAVE_VALUE");
        assert_eq!(j.default_safe_service, "important");
        assert_eq!(j.temp_token_format, TempTokenFormat::JavaRaw);
        assert_eq!(j.temp_token_namespace, "temp-token");
        assert_eq!(j.api_key_format, ApiKeyFormat::JavaModel);
        assert_eq!(j.application_value, ApplicationValue::JavaRoot);
        assert_eq!(j.jwt_claims, JwtClaimsFormat::Java);
        assert_eq!(j.sign_nonce, SignNonceFormat::Java);
        assert_eq!(j.sign_algorithm, SignAlgorithm::Md5);
        assert_eq!(j.same_token_past_ttl, SameTokenPastTtl::Remaining);
        assert_eq!(j.opaque_gen, OpaqueGen::Java);
    }

    #[test]
    fn java_compatible_config_fields() {
        let cfg = SaTokenConfig::java_compatible();
        assert_eq!(cfg.token_name, "satoken");
        assert_eq!(cfg.key_layout, SaKeyLayout::JavaFourSegment);
        assert_eq!(cfg.wire, WireConfig::java());
        assert_eq!(cfg.max_login_count, 12);
        assert!(!cfg.auto_renew);
        assert!(cfg.active_refresh);
        assert_eq!(cfg.max_try_times, 12);
    }

    #[test]
    fn deserialize_wire_preset_string() {
        let wrap: Wrap = serde_json::from_str(r#"{"wire":"java"}"#).unwrap();
        assert_eq!(wrap.wire, WireConfig::java());
        let wrap: Wrap = serde_json::from_str(r#"{"wire":"native"}"#).unwrap();
        assert_eq!(wrap.wire, WireConfig::native());
    }

    #[test]
    fn deserialize_wire_map_preset_with_override() {
        let wrap: Wrap = serde_json::from_str(
            r#"{"wire":{"preset":"java","allow_login_id_colon":true,"token_value":"LoginId"}}"#,
        )
        .unwrap();
        assert_eq!(wrap.wire.token_value, TokenValueFormat::LoginId);
        assert!(wrap.wire.allow_login_id_colon);
        assert_eq!(wrap.wire.default_login_type, "login");
        assert_eq!(wrap.wire.last_active, LastActiveStore::SeparateKey);
        assert_eq!(wrap.wire.opaque_gen, OpaqueGen::Java);
    }

    #[test]
    fn deserialize_opaque_gen_override() {
        let wrap: Wrap =
            serde_json::from_str(r#"{"wire":{"preset":"java","opaque_gen":"native"}}"#).unwrap();
        assert_eq!(wrap.wire.opaque_gen, OpaqueGen::Native);
        assert_eq!(wrap.wire.token_value, TokenValueFormat::LoginId);
    }

    #[test]
    fn validate_wire_login_id_requires_separate_key() {
        let cfg = SaTokenConfig {
            wire: WireConfig {
                token_value: TokenValueFormat::LoginId,
                last_active: LastActiveStore::InTokenInfo,
                ..WireConfig::native()
            },
            ..SaTokenConfig::default()
        };
        let err = cfg.validate_wire().expect_err("must fail");
        assert!(err.to_string().contains("SeparateKey"));
    }

    #[test]
    fn validate_wire_jwt_mixin_rejects_non_concurrent() {
        let cfg = SaTokenConfig {
            token_style: TokenStyle::JwtMixin,
            is_concurrent: false,
            wire: WireConfig {
                last_active: LastActiveStore::SeparateKey,
                ..WireConfig::native()
            },
            ..SaTokenConfig::default()
        };
        let err = cfg.validate_wire().expect_err("must fail");
        assert!(err.to_string().contains("is_concurrent"));
    }

    #[test]
    fn builder_java_compatible_token_name_override() {
        let cfg = SaTokenConfig::builder()
            .java_compatible()
            .token_name("foo")
            .build_config();
        assert_eq!(cfg.token_name, "foo");
        assert_eq!(cfg.key_layout, SaKeyLayout::JavaFourSegment);
        assert_eq!(cfg.wire, WireConfig::java());
        assert!(cfg.active_refresh);
    }

    #[test]
    fn serde_session_codec_roundtrip() {
        let codec = WireCodec::from_config(&SaTokenConfig::default());
        let session = SaSession::new("s1");
        let raw = codec.encode_session(&session).unwrap();
        let decoded = codec.decode_session(&raw).unwrap();
        assert_eq!(decoded.id, "s1");
    }

    #[test]
    fn jackson_session_codec_roundtrip_and_reads_native() {
        let cfg = SaTokenConfig {
            wire: WireConfig {
                session_format: SessionFormat::Jackson3Typed,
                application_value: ApplicationValue::JavaRoot,
                ..WireConfig::native()
            },
            ..SaTokenConfig::default()
        };
        let codec = WireCodec::from_config(&cfg);

        let mut session = SaSession::new("satoken:login:session:10001")
            .with_type(java_session::TYPE_ACCOUNT_SESSION);
        session.java_ext_mut().login_id = Some("10001".into());
        session.java_ext_mut().login_type = Some("login".into());
        let raw = codec.encode_session(&session).unwrap();
        assert!(raw.contains("@class"));
        assert!(raw.contains("java.lang.Long"));
        let decoded = codec.decode_session(&raw).unwrap();
        assert_eq!(decoded.id, session.id);
        assert_eq!(
            decoded.java_ext().and_then(|e| e.login_id.as_deref()),
            Some("10001")
        );

        let native = SaSession::new("s1");
        let native_raw = serde_json::to_string(&native).unwrap();
        let from_native = codec.decode_session(&native_raw).unwrap();
        assert_eq!(from_native.id, "s1");
        assert!(from_native.wire_ext.is_none());

        let root = codec.encode_root(&serde_json::json!({"k": "v"})).unwrap();
        assert!(!root.contains("@class"));
        assert_eq!(
            codec.encode_root(&serde_json::json!(10001)).unwrap(),
            "10001"
        );
        assert_eq!(
            codec.decode_root(r#"["java.lang.Long",10001]"#).unwrap(),
            serde_json::json!(10001)
        );
    }
}
