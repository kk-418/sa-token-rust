// Author: 金书记 | Author: Jin Shuji
//! Token Generator | Token 生成器
//!
//! Supports multiple token styles including UUID, Random, and JWT
//! 支持多种 Token 风格，包括 UUID、随机字符串和 JWT

use crate::compat::{JwtClaimsFormat, java_jwt};
use crate::config::{SaTokenConfig, TokenStyle};
use crate::error::{SaTokenError, SaTokenResult};
use crate::token::TokenValue;
use crate::token::csprng::{fill_bytes, random_hex, random_tik};
use crate::token::jwt::{JwtAlgorithm, JwtClaims, JwtManager};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Inputs for [`TokenGenerator::generate_for`].
/// JWT Java claims 需要 login_type / device / timeout / extra。
#[derive(Debug, Clone)]
pub struct TokenGenContext {
    /// Account id | 账号 id
    pub login_id: String,
    /// Stp login type | 账号体系
    pub login_type: String,
    /// Device type | 设备类型
    pub device: Option<String>,
    /// Token TTL in seconds | Token 有效期（秒）
    pub timeout_secs: i64,
    /// Extra claims (JWT) | 扩展 claims（JWT）
    pub extra: Option<serde_json::Value>,
}

/// Token value generator | Token 值生成器
pub struct TokenGenerator;

impl TokenGenerator {
    fn wrap_login_id(
        config: &SaTokenConfig,
        login_id: &str,
        extra: Option<serde_json::Value>,
    ) -> TokenGenContext {
        let login_type = if config.wire.default_login_type.is_empty() {
            "default".to_string()
        } else {
            config.wire.default_login_type.clone()
        };
        TokenGenContext {
            login_id: login_id.to_string(),
            login_type,
            device: None,
            timeout_secs: config.timeout,
            extra,
        }
    }

    /// Generate token from a full context | 按完整上下文生成 token
    pub fn generate_for(
        config: &SaTokenConfig,
        ctx: &TokenGenContext,
    ) -> SaTokenResult<TokenValue> {
        match config.token_style {
            TokenStyle::Uuid => Ok(Self::generate_uuid()),
            TokenStyle::SimpleUuid => Ok(Self::generate_simple_uuid()),
            TokenStyle::Random32 => Self::generate_random_csprng(32),
            TokenStyle::Random64 => Self::generate_random_csprng(64),
            TokenStyle::Random128 => Self::generate_random_csprng(128),
            TokenStyle::Jwt | TokenStyle::JwtStateless | TokenStyle::JwtMixin => {
                Self::generate_jwt_for(config, ctx)
            }
            TokenStyle::Hash => Self::generate_hash(&ctx.login_id),
            TokenStyle::Timestamp => Self::generate_timestamp(),
            TokenStyle::Tik => Self::generate_tik(),
        }
    }

    /// Generate token based on configuration | 根据配置生成 token
    pub fn generate_with_login_id(
        config: &SaTokenConfig,
        login_id: &str,
    ) -> SaTokenResult<TokenValue> {
        Self::generate_for(config, &Self::wrap_login_id(config, login_id, None))
    }

    /// Generate token with login_id and extra data | 根据配置生成带有额外数据的 token
    pub fn generate_with_login_id_and_extra(
        config: &SaTokenConfig,
        login_id: &str,
        extra_data: &serde_json::Value,
    ) -> SaTokenResult<TokenValue> {
        match config.token_style {
            TokenStyle::Jwt | TokenStyle::JwtStateless | TokenStyle::JwtMixin => {
                Self::generate_for(
                    config,
                    &Self::wrap_login_id(config, login_id, Some(extra_data.clone())),
                )
            }
            _ => Self::generate_with_login_id(config, login_id),
        }
    }

    /// Generate token (backward compatible) | 根据配置生成 token（向后兼容）
    pub fn generate(config: &SaTokenConfig) -> SaTokenResult<TokenValue> {
        Self::generate_with_login_id(config, "")
    }

    /// 生成 UUID 风格的 token
    pub fn generate_uuid() -> TokenValue {
        TokenValue::new(Uuid::new_v4().to_string())
    }

    /// 生成简化的 UUID（去掉横杠）
    pub fn generate_simple_uuid() -> TokenValue {
        TokenValue::new(Uuid::new_v4().simple().to_string())
    }

    /// Hex token whose entropy is `length/2` bytes of OS CSPRNG (not a hash of a UUID).
    /// hex token，熵来自 `length/2` 字节操作系统随机数（不是 UUID 的哈希）。
    pub fn generate_random_csprng(length: usize) -> SaTokenResult<TokenValue> {
        Ok(TokenValue::new(random_hex(length)?))
    }

    /// Old name kept as a wrapper so call sites can migrate in one commit.
    /// 保留旧名作为包装，便于调用点一次改完。
    pub fn generate_random(length: usize) -> SaTokenResult<TokenValue> {
        Self::generate_random_csprng(length)
    }

    /// Generate JWT token | 生成 JWT token
    pub fn generate_jwt(config: &SaTokenConfig, login_id: &str) -> SaTokenResult<TokenValue> {
        Self::generate_jwt_for(config, &Self::wrap_login_id(config, login_id, None))
    }

    /// Generate JWT token with extra data signed into claims | 生成带有额外数据签名的 JWT token
    pub fn generate_jwt_with_extra(
        config: &SaTokenConfig,
        login_id: &str,
        extra_data: &serde_json::Value,
    ) -> SaTokenResult<TokenValue> {
        Self::generate_jwt_for(
            config,
            &Self::wrap_login_id(config, login_id, Some(extra_data.clone())),
        )
    }

    fn generate_jwt_for(
        config: &SaTokenConfig,
        ctx: &TokenGenContext,
    ) -> SaTokenResult<TokenValue> {
        let secret = require_jwt_secret(config)?;
        let effective_login_id = if ctx.login_id.is_empty() {
            Utc::now().timestamp_millis().to_string()
        } else {
            ctx.login_id.clone()
        };
        let algorithm = config
            .jwt_algorithm
            .as_ref()
            .and_then(|alg| Self::parse_jwt_algorithm(alg))
            .unwrap_or(JwtAlgorithm::HS256);
        let mut jwt_manager = JwtManager::with_algorithm(secret, algorithm);
        if let Some(ref issuer) = config.jwt_issuer {
            jwt_manager = jwt_manager.set_issuer(issuer);
        }
        if let Some(ref audience) = config.jwt_audience {
            jwt_manager = jwt_manager.set_audience(audience);
        }
        let token = if config.wire.jwt_claims == JwtClaimsFormat::Java {
            let include_device_and_eff = matches!(
                config.token_style,
                TokenStyle::JwtMixin | TokenStyle::JwtStateless
            );
            let device = ctx
                .device
                .as_deref()
                .or(config.wire.default_device_type.as_deref());
            java_jwt::generate(
                &jwt_manager,
                &java_jwt::JavaJwtSpec {
                    login_type: &ctx.login_type,
                    login_id: &effective_login_id,
                    login_id_json: config.wire.login_id_json,
                    extra: ctx.extra.as_ref(),
                    device,
                    timeout_secs: ctx.timeout_secs,
                    include_device_and_eff,
                },
            )
        } else {
            Self::generate_standard_jwt(&jwt_manager, ctx, effective_login_id)
        };
        match token {
            Ok(token) => Ok(TokenValue::new(token)),
            Err(e) if config.jwt_fallback_on_error => {
                tracing::warn!(error = %e, "JWT generation failed, falling back to UUID");
                Ok(Self::generate_uuid())
            }
            Err(e) => Err(SaTokenError::ConfigError(format!(
                "JWT generation failed: {e}"
            ))),
        }
    }

    fn generate_standard_jwt(
        jwt_manager: &JwtManager,
        ctx: &TokenGenContext,
        login_id: String,
    ) -> SaTokenResult<String> {
        let mut claims = JwtClaims::new(login_id);
        if !ctx.login_type.is_empty() {
            claims.set_login_type(&ctx.login_type);
        }
        if ctx.timeout_secs > 0 {
            claims.set_expiration(ctx.timeout_secs);
        }
        if let Some(ref device) = ctx.device {
            claims.set_device(device);
        }
        match ctx.extra.as_ref() {
            Some(serde_json::Value::Object(map)) => {
                for (key, value) in map {
                    claims.add_claim(key.clone(), value.clone());
                }
            }
            Some(serde_json::Value::Null) | None => {}
            Some(other) => {
                claims.add_claim("extra", other.clone());
            }
        }
        jwt_manager.generate(&claims)
    }

    /// Generate Hash style token | 生成 Hash 风格 token
    pub fn generate_hash(login_id: &str) -> SaTokenResult<TokenValue> {
        let login_id_value = if login_id.is_empty() {
            Utc::now().timestamp_millis().to_string()
        } else {
            login_id.to_string()
        };
        let mut salt = [0u8; 16];
        fill_bytes(&mut salt)?;
        let data = format!(
            "{}{}{}",
            login_id_value,
            Utc::now().timestamp_millis(),
            hex::encode(salt)
        );
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        Ok(TokenValue::new(hex::encode(hasher.finalize())))
    }

    /// Generate Timestamp style token | 生成时间戳风格 token
    pub fn generate_timestamp() -> SaTokenResult<TokenValue> {
        let timestamp = Utc::now().timestamp_millis();
        let suffix = random_hex(16)?;
        Ok(TokenValue::new(format!("{timestamp}_{suffix}")))
    }

    /// Generate Tik style token | 生成 Tik 风格 token
    pub fn generate_tik() -> SaTokenResult<TokenValue> {
        Ok(TokenValue::new(random_tik(8)?))
    }

    fn parse_jwt_algorithm(alg: &str) -> Option<JwtAlgorithm> {
        match alg.to_uppercase().as_str() {
            "HS256" => Some(JwtAlgorithm::HS256),
            "HS384" => Some(JwtAlgorithm::HS384),
            "HS512" => Some(JwtAlgorithm::HS512),
            "RS256" => Some(JwtAlgorithm::RS256),
            "RS384" => Some(JwtAlgorithm::RS384),
            "RS512" => Some(JwtAlgorithm::RS512),
            "ES256" => Some(JwtAlgorithm::ES256),
            "ES384" => Some(JwtAlgorithm::ES384),
            _ => None,
        }
    }
}

impl std::fmt::Debug for TokenGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenGenerator { .. }")
    }
}

fn require_jwt_secret(config: &SaTokenConfig) -> SaTokenResult<&str> {
    match config.jwt_secret_key.as_deref() {
        Some(s) if !s.trim().is_empty() => Ok(s),
        _ => Err(SaTokenError::ConfigError(
            "jwt_secret_key is required when token_style=Jwt".into(),
        )),
    }
}

/// Generate until `occupied` is false, or until `max_try_times` is exhausted.
/// `max_try_times < 0`：create once and return (no uniqueness probe).
/// `max_try_times == 0`：treated as `-1`.
///
/// 直到 `occupied` 为 false 或次数用尽。
/// `max_try_times < 0`：只生成一次、不做占用探测。
/// `max_try_times == 0`：与 `-1` 相同。
pub async fn generate_unique<C, F, Fut>(
    max_try_times: i32,
    mut create: C,
    mut occupied: F,
) -> SaTokenResult<TokenValue>
where
    C: FnMut() -> SaTokenResult<TokenValue>,
    F: FnMut(&str) -> Fut,
    Fut: Future<Output = SaTokenResult<bool>>,
{
    if max_try_times <= 0 {
        return create();
    }
    let mut last = create()?;
    for _ in 0..max_try_times {
        if !occupied(last.as_str()).await? {
            return Ok(last);
        }
        last = create()?;
    }
    if !occupied(last.as_str()).await? {
        return Ok(last);
    }
    Err(SaTokenError::ConfigError(format!(
        "failed to generate a unique token after {max_try_times} attempts"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SaTokenConfig, TokenStyle};
    use crate::token::jwt::JwtManager;

    fn jwt_config() -> SaTokenConfig {
        SaTokenConfig {
            token_style: TokenStyle::Jwt,
            jwt_secret_key: Some("test-secret-key-for-jwt".to_string()),
            timeout: 3600,
            ..SaTokenConfig::default()
        }
    }

    #[test]
    fn test_generate_jwt_with_extra_object() {
        let config = jwt_config();
        let extra = serde_json::json!({
            "role": "admin",
            "tenant_id": 42,
            "permissions": ["read", "write"]
        });

        let token = TokenGenerator::generate_jwt_with_extra(&config, "user_123", &extra).unwrap();
        assert!(!token.as_str().is_empty());

        let jwt_manager = JwtManager::new("test-secret-key-for-jwt");
        let claims = jwt_manager.validate(token.as_str()).unwrap();

        assert_eq!(claims.login_id, "user_123");
        assert_eq!(claims.get_claim("role"), Some(&serde_json::json!("admin")));
        assert_eq!(claims.get_claim("tenant_id"), Some(&serde_json::json!(42)));
        assert_eq!(
            claims.get_claim("permissions"),
            Some(&serde_json::json!(["read", "write"]))
        );
    }

    #[test]
    fn test_generate_jwt_with_extra_non_object() {
        let config = jwt_config();
        let extra = serde_json::json!("simple_string_value");

        let token = TokenGenerator::generate_jwt_with_extra(&config, "user_456", &extra).unwrap();

        let jwt_manager = JwtManager::new("test-secret-key-for-jwt");
        let claims = jwt_manager.validate(token.as_str()).unwrap();

        assert_eq!(claims.login_id, "user_456");
        assert_eq!(
            claims.get_claim("extra"),
            Some(&serde_json::json!("simple_string_value"))
        );
    }

    #[test]
    fn test_generate_jwt_with_extra_null() {
        let config = jwt_config();
        let extra = serde_json::Value::Null;

        let token = TokenGenerator::generate_jwt_with_extra(&config, "user_789", &extra).unwrap();

        let jwt_manager = JwtManager::new("test-secret-key-for-jwt");
        let claims = jwt_manager.validate(token.as_str()).unwrap();

        assert_eq!(claims.login_id, "user_789");
        assert!(claims.extra.is_empty());
    }

    #[test]
    fn test_generate_with_login_id_and_extra_jwt_style() {
        let config = jwt_config();
        let extra = serde_json::json!({"key": "value"});

        let token =
            TokenGenerator::generate_with_login_id_and_extra(&config, "user_jwt", &extra).unwrap();

        assert!(token.as_str().contains('.'));

        let jwt_manager = JwtManager::new("test-secret-key-for-jwt");
        let claims = jwt_manager.validate(token.as_str()).unwrap();
        assert_eq!(claims.get_claim("key"), Some(&serde_json::json!("value")));
    }

    #[test]
    fn test_generate_with_login_id_and_extra_non_jwt_style() {
        let config = SaTokenConfig {
            token_style: TokenStyle::Uuid,
            ..SaTokenConfig::default()
        };
        let extra = serde_json::json!({"key": "value"});

        let token =
            TokenGenerator::generate_with_login_id_and_extra(&config, "user_uuid", &extra).unwrap();
        assert!(!token.as_str().is_empty());
        assert!(!token.as_str().contains('.'));
    }

    #[test]
    fn test_random_32_length() {
        let config = SaTokenConfig {
            token_style: TokenStyle::Random32,
            ..SaTokenConfig::default()
        };
        let token = TokenGenerator::generate_with_login_id(&config, "user_random").unwrap();
        assert!(!token.as_str().is_empty());
        assert_eq!(token.as_str().len(), 32);
    }

    #[test]
    fn test_random_64_length() {
        let config = SaTokenConfig {
            token_style: TokenStyle::Random64,
            ..SaTokenConfig::default()
        };
        let token = TokenGenerator::generate_with_login_id(&config, "user_random").unwrap();
        assert!(!token.as_str().is_empty());
        assert_eq!(token.as_str().len(), 64);
    }

    #[test]
    fn test_random_128_length() {
        let config = SaTokenConfig {
            token_style: TokenStyle::Random128,
            ..SaTokenConfig::default()
        };
        let token = TokenGenerator::generate_with_login_id(&config, "user_random").unwrap();
        assert!(!token.as_str().is_empty());
        assert_eq!(token.as_str().len(), 128);
    }
}
