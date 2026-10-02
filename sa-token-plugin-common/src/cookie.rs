// Author: 金书记
//
//! Apply `StpUtil` pending cookie writes onto a framework `SaResponse`.

use sa_token_adapter::context::SaResponse;
use sa_token_core::{PendingCookie, SaTokenConfig, SaTokenContext};

/// Drain `ctx.pending_cookie` and write or delete the token cookie on `res`.
///
/// `write_token_cookie_with_max_age` / `delete_token_cookie` still honor
/// `config.cookie.is_write_cookie`.
pub fn apply_pending_cookie<R: SaResponse>(
    ctx: &SaTokenContext,
    res: &mut R,
    config: &SaTokenConfig,
) {
    match ctx.take_pending_cookie() {
        Some(PendingCookie::Write { token, max_age }) => {
            sa_token_core::token_io::write_token_cookie_with_max_age(res, &token, config, max_age);
        }
        Some(PendingCookie::Delete) => {
            sa_token_core::token_io::delete_token_cookie(res, config);
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sa_token_adapter::context::{CookieOptions, SaResponse};
    use sa_token_core::config::TokenCookieConfig;
    use sa_token_core::token::TokenValue;

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

    fn write_cfg() -> SaTokenConfig {
        SaTokenConfig {
            token_name: "Authorization".into(),
            cookie: TokenCookieConfig {
                is_write_cookie: true,
                ..TokenCookieConfig::default()
            },
            ..SaTokenConfig::default()
        }
    }

    fn context_with_pending(pending: PendingCookie) -> SaTokenContext {
        let ctx = SaTokenContext::new();
        SaTokenContext::set_current(ctx.clone());
        let _ = SaTokenContext::with_current_mut(|inner| {
            inner.pending_cookie = Some(pending);
        });
        ctx
    }

    #[test]
    fn apply_pending_cookie_write() {
        let ctx = context_with_pending(PendingCookie::Write {
            token: TokenValue::new("tok"),
            max_age: 86400,
        });
        let mut res = MockResponse::new();
        apply_pending_cookie(&ctx, &mut res, &write_cfg());
        assert_eq!(res.cookies.len(), 1);
        assert_eq!(res.cookies[0].0, "Authorization");
        assert_eq!(res.cookies[0].1, "tok");
        assert_eq!(res.cookies[0].2.max_age, Some(86400));
        SaTokenContext::clear();
    }

    #[test]
    fn apply_pending_cookie_delete() {
        let ctx = context_with_pending(PendingCookie::Delete);
        let mut res = MockResponse::new();
        apply_pending_cookie(&ctx, &mut res, &write_cfg());
        assert_eq!(res.cookies.len(), 1);
        assert_eq!(res.cookies[0].1, "");
        assert_eq!(res.cookies[0].2.max_age, Some(0));
        SaTokenContext::clear();
    }

    #[test]
    fn apply_pending_cookie_none_is_noop() {
        let ctx = SaTokenContext::new();
        let mut res = MockResponse::new();
        apply_pending_cookie(&ctx, &mut res, &write_cfg());
        assert!(res.cookies.is_empty());
    }
}
