// Author: 金书记 | Author: Jin Shuji
//! Unified token read/write helpers for HTTP adapters.
//! HTTP 适配器用的统一 token 读写助手。

use sa_token_adapter::context::{CookieOptions, SaRequest, SaResponse, SameSite};
use sa_token_adapter::utils::extract_bearer_or_value;

use crate::config::{SaTokenConfig, TokenCookieConfig};
use crate::token::{TokenInfo, TokenValue};

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
///
/// Max-Age follows `config.timeout` (same as a default login).
/// Max-Age 跟随 `config.timeout`（与默认登录一致）。
pub fn write_token_cookie<R: SaResponse>(res: &mut R, token: &TokenValue, config: &SaTokenConfig) {
    write_token_cookie_with_max_age(res, token, config, config.timeout);
}

/// Write the token cookie with an explicit Max-Age (this login's timeout).
/// 按指定 Max-Age 写入 token Cookie（本次登录 timeout）。
///
/// `is_write_cookie` is still the gate. `max_age_secs < 0` writes a session
/// cookie (Max-Age omitted).
/// `is_write_cookie` 仍为门闩。`max_age_secs < 0` 时写入会话 Cookie（不设 Max-Age）。
pub fn write_token_cookie_with_max_age<R: SaResponse>(
    res: &mut R,
    token: &TokenValue,
    config: &SaTokenConfig,
    max_age_secs: i64,
) {
    if !config.cookie.is_write_cookie {
        return;
    }
    let opts = cookie_options(&config.cookie, max_age_secs);
    res.set_cookie(config.token_name.as_str(), token.as_str(), opts);
}

/// Write the token cookie using remaining lifetime from `TokenInfo.expire_time`.
/// 按 `TokenInfo.expire_time` 的剩余秒数写入 token Cookie。
///
/// `expire_time == None` falls back to `config.timeout`.
/// `expire_time` 为空时回退到 `config.timeout`。
pub fn write_token_cookie_for_token<R: SaResponse>(
    res: &mut R,
    token_info: &TokenInfo,
    config: &SaTokenConfig,
) {
    let max_age_secs = match token_info.expire_time {
        Some(t) => (t - chrono::Utc::now()).num_seconds().max(0),
        None => config.timeout,
    };
    write_token_cookie_with_max_age(res, &token_info.token, config, max_age_secs);
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

    struct MockResponse {
        cookies: Vec<(String, String, CookieOptions)>,
    }

    impl MockResponse {
        fn new() -> Self {
            Self {
                cookies: Vec::new(),
            }
        }
    }

    impl SaResponse for MockResponse {
        fn set_header(&mut self, _name: &str, _value: &str) {}

        fn set_cookie(&mut self, name: &str, value: &str, options: CookieOptions) {
            self.cookies
                .push((name.to_string(), value.to_string(), options));
        }

        fn set_status(&mut self, _status: u16) {}

        fn set_json_body<T: serde::Serialize>(
            &mut self,
            _body: T,
        ) -> Result<(), serde_json::Error> {
            Ok(())
        }
    }

    fn write_cfg(is_write_cookie: bool, timeout: i64) -> SaTokenConfig {
        SaTokenConfig {
            timeout,
            cookie: TokenCookieConfig {
                is_write_cookie,
                ..TokenCookieConfig::default()
            },
            ..SaTokenConfig::default()
        }
    }

    #[test]
    fn write_token_cookie_skipped_when_is_write_cookie_false() {
        let mut res = MockResponse::new();
        let token = TokenValue::new("tok");
        let config = write_cfg(false, 86400);
        write_token_cookie(&mut res, &token, &config);
        write_token_cookie_with_max_age(&mut res, &token, &config, 604800);
        delete_token_cookie(&mut res, &config);
        assert!(res.cookies.is_empty());
    }

    #[test]
    fn write_token_cookie_default_max_age_equals_config_timeout() {
        let mut res = MockResponse::new();
        let token = TokenValue::new("tok");
        let config = write_cfg(true, 86400);
        write_token_cookie(&mut res, &token, &config);
        assert_eq!(res.cookies.len(), 1);
        assert_eq!(res.cookies[0].0, "sa-token");
        assert_eq!(res.cookies[0].1, "tok");
        assert_eq!(res.cookies[0].2.max_age, Some(config.timeout));
        assert_eq!(res.cookies[0].2.max_age, Some(86400));
    }

    #[test]
    fn write_token_cookie_with_max_age_remember_me() {
        let mut res = MockResponse::new();
        let token = TokenValue::new("tok");
        let config = write_cfg(true, 86400);
        write_token_cookie_with_max_age(&mut res, &token, &config, 7 * 24 * 3600);
        assert_eq!(res.cookies.len(), 1);
        assert_eq!(res.cookies[0].2.max_age, Some(604800));
    }

    #[test]
    fn write_token_cookie_with_max_age_session_cookie() {
        let mut res = MockResponse::new();
        let token = TokenValue::new("tok");
        let config = write_cfg(true, 86400);
        write_token_cookie_with_max_age(&mut res, &token, &config, -1);
        assert_eq!(res.cookies.len(), 1);
        assert_eq!(res.cookies[0].2.max_age, None);
    }

    #[test]
    fn write_token_cookie_delete_sets_max_age_zero() {
        let mut res = MockResponse::new();
        let config = write_cfg(true, 86400);
        delete_token_cookie(&mut res, &config);
        assert_eq!(res.cookies.len(), 1);
        assert_eq!(res.cookies[0].1, "");
        assert_eq!(res.cookies[0].2.max_age, Some(0));
    }
}
