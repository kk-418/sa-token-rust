// Author: 金书记 | Author: Jin Shuji
//! Unified token read/write helpers for HTTP adapters.
//! HTTP 适配器用的统一 token 读写助手。

use sa_token_adapter::context::{CookieOptions, SaRequest, SaResponse, SameSite};
use sa_token_adapter::utils::extract_bearer_or_value;

use crate::config::{SaTokenConfig, TokenCookieConfig};
use crate::token::TokenValue;

/// Read a token using the manager config flags.
/// 按 Manager 配置开关读取 token。
///
/// When `is_read_body` is true, only `get_param` (query / mapped form fields) is
/// read — never consume the HTTP body in middleware.
/// `is_read_body` 为 true 时只读 `get_param`（query / 已映射表单字段），绝不在中间件里消耗 HTTP body。
pub fn read_token<R: SaRequest>(req: &R, config: &SaTokenConfig) -> Option<String> {
    let name = config.token_name.as_str();
    let mut raw: Option<String> = None;

    if config.is_read_header {
        if let Some(v) = req.get_header(name) {
            if !v.trim().is_empty() {
                raw = Some(v);
            }
        }
        if raw.is_none() && !name.eq_ignore_ascii_case("authorization") {
            if let Some(v) = req.get_header("Authorization") {
                if !v.trim().is_empty() {
                    raw = Some(v);
                }
            }
        }
    }

    let mut from_cookie = false;
    if raw.is_none() && config.is_read_cookie {
        if let Some(v) = req.get_cookie(name) {
            if !v.trim().is_empty() {
                raw = Some(v);
                from_cookie = true;
            }
        }
    }

    // Param/query only — never consume the HTTP body in middleware.
    // 只读 param/query，绝不在中间件里消耗 HTTP body。
    if raw.is_none() && config.is_read_body {
        if let Some(v) = req.get_param(name) {
            if !v.trim().is_empty() {
                raw = Some(v);
            }
        }
    }

    let raw = raw?;
    let filled = if from_cookie {
        fill_cookie_prefix(raw.trim(), config)
    } else {
        raw.trim().to_string()
    };
    apply_token_prefix(filled.trim(), config.token_prefix.as_deref())
}

/// Prepend `token_prefix` to a bare cookie token when `cookie_auto_fill_prefix` is on.
/// `cookie_auto_fill_prefix` 开启时，给 Cookie 里的裸 token 补上 `token_prefix`。
fn fill_cookie_prefix(raw: &str, config: &SaTokenConfig) -> String {
    if !config.cookie_auto_fill_prefix {
        return raw.to_string();
    }
    let Some(prefix) = config.token_prefix.as_deref().filter(|p| !p.is_empty()) else {
        return raw.to_string();
    };
    if raw.starts_with(prefix) {
        return raw.to_string();
    }
    if prefix.ends_with(' ') {
        format!("{prefix}{raw}")
    } else {
        format!("{prefix} {raw}")
    }
}

/// Apply prefix rules. `None` keeps historical Bearer stripping.
/// 应用前缀规则。`None` 保持历史上的 Bearer 剥离。
pub fn apply_token_prefix(raw: &str, prefix: Option<&str>) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    match prefix {
        None => {
            let s = extract_bearer_or_value(raw);
            if s.is_empty() { None } else { Some(s) }
        }
        Some(p) => {
            if let Some(rest) = raw.strip_prefix(p) {
                let rest = rest.trim();
                if rest.is_empty() {
                    None
                } else {
                    Some(rest.to_string())
                }
            } else {
                None
            }
        }
    }
}

/// Maps + config, for WebSocket extractors that are not `SaRequest`.
/// 给不是 `SaRequest` 的 WebSocket 提取器使用。
pub fn read_token_from_maps(
    headers: &std::collections::HashMap<String, String>,
    query: &std::collections::HashMap<String, String>,
    config: &SaTokenConfig,
) -> Option<String> {
    let name = config.token_name.as_str();
    let mut raw: Option<String> = None;
    if config.is_read_header {
        if let Some(v) = headers.get(name).filter(|s| !s.trim().is_empty()) {
            raw = Some(v.clone());
        }
        if raw.is_none() && !name.eq_ignore_ascii_case("authorization") {
            if let Some(v) = headers
                .get("Authorization")
                .or_else(|| headers.get("authorization"))
                .filter(|s| !s.trim().is_empty())
            {
                raw = Some(v.clone());
            }
        }
        if raw.is_none() {
            if let Some(v) = headers
                .get("Sec-WebSocket-Protocol")
                .filter(|s| !s.trim().is_empty())
            {
                raw = Some(v.clone());
            }
        }
    }
    if raw.is_none() && config.is_read_body {
        if let Some(v) = query.get(name).filter(|s| !s.trim().is_empty()) {
            raw = Some(v.clone());
        }
        if raw.is_none() {
            if let Some(v) = query.get("token").filter(|s| !s.trim().is_empty()) {
                raw = Some(v.clone());
            }
        }
    }
    apply_token_prefix(raw?.trim(), config.token_prefix.as_deref())
}

/// Write the token cookie when `is_write_cookie` is true.
/// 仅当 `is_write_cookie` 为 true 时写入 token Cookie。
pub fn write_token_cookie<R: SaResponse>(res: &mut R, token: &TokenValue, config: &SaTokenConfig) {
    if !config.cookie.is_write_cookie {
        return;
    }
    let opts = cookie_options(&config.cookie, config.timeout);
    res.set_cookie(config.token_name.as_str(), token.as_str(), opts);
}

/// Clear the token cookie (same guard as write).
/// 清除 token Cookie（与写入同一开关）。
pub fn delete_token_cookie<R: SaResponse>(res: &mut R, config: &SaTokenConfig) {
    if !config.cookie.is_write_cookie {
        return;
    }
    let mut opts = cookie_options(&config.cookie, 0);
    opts.max_age = Some(0);
    res.set_cookie(config.token_name.as_str(), "", opts);
}

fn cookie_options(cookie: &TokenCookieConfig, max_age_secs: i64) -> CookieOptions {
    CookieOptions {
        domain: cookie.domain.clone(),
        path: cookie.path.clone().or_else(|| Some("/".into())),
        max_age: if max_age_secs < 0 {
            None
        } else {
            Some(max_age_secs)
        },
        http_only: cookie.http_only,
        secure: cookie.secure,
        same_site: cookie.same_site.or(Some(SameSite::Lax)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockRequest {
        headers: HashMap<String, String>,
        cookies: HashMap<String, String>,
        params: HashMap<String, String>,
    }

    impl MockRequest {
        fn with_header(name: &str, value: &str) -> Self {
            let mut headers = HashMap::new();
            headers.insert(name.to_string(), value.to_string());
            Self {
                headers,
                cookies: HashMap::new(),
                params: HashMap::new(),
            }
        }

        fn with_cookie(name: &str, value: &str) -> Self {
            let mut cookies = HashMap::new();
            cookies.insert(name.to_string(), value.to_string());
            Self {
                headers: HashMap::new(),
                cookies,
                params: HashMap::new(),
            }
        }
    }

    impl SaRequest for MockRequest {
        fn get_header(&self, name: &str) -> Option<String> {
            self.headers.get(name).cloned()
        }

        fn get_cookie(&self, name: &str) -> Option<String> {
            self.cookies.get(name).cloned()
        }

        fn get_param(&self, name: &str) -> Option<String> {
            self.params.get(name).cloned()
        }

        fn get_path(&self) -> String {
            "/".to_string()
        }

        fn get_method(&self) -> String {
            "GET".to_string()
        }
    }

    fn cfg(
        token_name: &str,
        prefix: Option<&str>,
        cookie_auto_fill_prefix: bool,
        is_read_header: bool,
    ) -> SaTokenConfig {
        SaTokenConfig {
            token_name: token_name.to_string(),
            token_prefix: prefix.map(str::to_string),
            cookie_auto_fill_prefix,
            is_read_header,
            ..SaTokenConfig::default()
        }
    }

    #[test]
    fn read_token_from_authorization_bearer_header() {
        let req = MockRequest::with_header("Authorization", "Bearer eyJabc");
        let config = cfg("Authorization", Some("Bearer"), false, true);
        assert_eq!(read_token(&req, &config).as_deref(), Some("eyJabc"));
    }

    #[test]
    fn read_token_from_cookie_auto_fill_prefix() {
        let req = MockRequest::with_cookie("sa-token", "eyJabc");
        let config = cfg("sa-token", Some("Bearer"), true, false);
        assert_eq!(read_token(&req, &config).as_deref(), Some("eyJabc"));
    }

    #[test]
    fn read_token_from_cookie_without_auto_fill_returns_none() {
        let req = MockRequest::with_cookie("sa-token", "eyJabc");
        let config = cfg("sa-token", Some("Bearer"), false, false);
        assert_eq!(read_token(&req, &config), None);
    }

    #[test]
    fn read_token_from_cookie_auto_fill_prefix_with_trailing_space() {
        let req = MockRequest::with_cookie("sa-token", "eyJabc");
        let config = cfg("sa-token", Some("Bearer "), true, false);
        assert_eq!(read_token(&req, &config).as_deref(), Some("eyJabc"));
    }

    #[test]
    fn apply_token_prefix_none_strips_bearer_some_requires_prefix() {
        assert_eq!(
            apply_token_prefix("Bearer eyJabc", None).as_deref(),
            Some("eyJabc")
        );
        assert_eq!(apply_token_prefix("eyJabc", Some("Bearer")), None);
    }
}
