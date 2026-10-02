// Author: 金书记 | Author: Jin Shuji
//
//! HTTP Digest (Java `SaHttpDigestTemplate` / `SaHttpDigestUtil`).
//! HTTP Digest 认证，对齐 Java `SaHttpDigestTemplate`。
//!
//! Does not implement nonce replay protection, `nc` counters, or `qop=auth-int`.
//! 不实现 nonce 防重放、nc 计数、`qop=auth-int`。

use md5::{Digest, Md5};

use crate::context::SaTokenContext;
use crate::error::{SaTokenError, SaTokenResult};
use crate::http_basic::ct_eq;

/// Default realm (Java `SaHttpDigestModel.DEFAULT_REALM`).
/// 默认 realm。
pub const DEFAULT_REALM: &str = "Sa-Token";
/// Default qop (Java `SaHttpDigestModel.DEFAULT_QOP`).
/// 默认 qop。
pub const DEFAULT_QOP: &str = "auth";

/// Digest request / hope parameters (Java `SaHttpDigestModel`).
/// Digest 请求 / 期望参数。
#[derive(Debug, Clone)]
pub struct SaHttpDigestModel {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// Auth realm. Default `Sa-Token`.
    pub realm: String,
    /// Server nonce.
    pub nonce: String,
    /// Request URI.
    pub uri: String,
    /// HTTP method.
    pub method: String,
    /// Quality of protection. Default `auth`.
    pub qop: String,
    /// Nonce count (`nc`).
    pub nc: String,
    /// Client nonce.
    pub cnonce: String,
    /// Opaque server value.
    pub opaque: String,
    /// Client response digest.
    pub response: String,
}

impl Default for SaHttpDigestModel {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            realm: DEFAULT_REALM.to_string(),
            nonce: String::new(),
            uri: String::new(),
            method: String::new(),
            qop: DEFAULT_QOP.to_string(),
            nc: String::new(),
            cnonce: String::new(),
            opaque: String::new(),
            response: String::new(),
        }
    }
}

impl SaHttpDigestModel {
    /// Construct with username and password (Java 2-arg ctor).
    /// 使用用户名与密码构造。
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            ..Self::default()
        }
    }

    /// Construct with username, password, and realm (Java 3-arg ctor).
    /// 使用用户名、密码与 realm 构造。
    pub fn with_realm(
        username: impl Into<String>,
        password: impl Into<String>,
        realm: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            realm: realm.into(),
            ..Self::default()
        }
    }
}

/// Compute Digest `response` (Java `calcResponse`).
///
/// `md5( md5(user:realm:pass) : nonce:nc:cnonce:qop : md5(method:uri) )`
pub fn calc_response(model: &SaHttpDigestModel) -> String {
    let frag1 = md5_hex(&format!(
        "{}:{}:{}",
        model.username, model.realm, model.password
    ));
    let frag2 = format!(
        "{}:{}:{}:{}",
        model.nonce, model.nc, model.cnonce, model.qop
    );
    let frag3 = md5_hex(&format!("{}:{}", model.method, model.uri));
    md5_hex(&format!("{frag1}:{frag2}:{frag3}"))
}

/// Check Digest against the current request `Authorization` header.
/// 用当前请求 `Authorization` 头校验 Digest。
pub fn check(hope: &SaHttpDigestModel) -> SaTokenResult<()> {
    let Some(mut req) = authorization_to_model() else {
        return Err(digest_fail(hope));
    };
    copy_hope_to_req(hope, &mut req);
    let computed = calc_response(&req);
    if ct_eq(computed.as_bytes(), req.response.as_bytes()) {
        Ok(())
    } else {
        Err(digest_fail(hope))
    }
}

/// Check with username and password (Java `check(username, password)`).
/// 使用用户名与密码校验。
pub fn check_user(username: &str, password: &str) -> SaTokenResult<()> {
    check(&SaHttpDigestModel::new(username, password))
}

/// Check with username, password, and realm (Java `check(username, password, realm)`).
/// 使用用户名、密码与 realm 校验。
pub fn check_user_realm(username: &str, password: &str, realm: &str) -> SaTokenResult<()> {
    check(&SaHttpDigestModel::with_realm(username, password, realm))
}

fn md5_hex(input: &str) -> String {
    hex::encode(Md5::digest(input.as_bytes()))
}

fn authorization_to_model() -> Option<SaHttpDigestModel> {
    let ctx = SaTokenContext::try_current()?;
    let meta = ctx.auth_meta();
    let header = meta.authorization.as_deref()?;
    let body = header.strip_prefix("Digest ")?;

    let mut model = SaHttpDigestModel {
        method: meta.method.clone().unwrap_or_default(),
        uri: meta.path.clone().unwrap_or_default(),
        ..SaHttpDigestModel::default()
    };

    for part in body.split(',') {
        let part = part.trim();
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().replace('"', "");
        match key {
            "username" => model.username = value,
            "realm" => model.realm = value,
            "nonce" => model.nonce = value,
            "uri" => model.uri = value,
            "qop" => model.qop = value,
            "nc" => model.nc = value,
            "cnonce" => model.cnonce = value,
            "opaque" => model.opaque = value,
            "response" => model.response = value,
            "method" => model.method = value,
            _ => {}
        }
    }
    Some(model)
}

fn copy_hope_to_req(hope: &SaHttpDigestModel, req: &mut SaHttpDigestModel) {
    req.username.clone_from(&hope.username);
    req.password.clone_from(&hope.password);
    if !hope.realm.is_empty() {
        req.realm.clone_from(&hope.realm);
    }
    if !hope.nonce.is_empty() {
        req.nonce.clone_from(&hope.nonce);
    }
    if !hope.uri.is_empty() {
        req.uri.clone_from(&hope.uri);
    }
    if !hope.method.is_empty() {
        req.method.clone_from(&hope.method);
    }
    if !hope.qop.is_empty() {
        req.qop.clone_from(&hope.qop);
    }
    if !hope.nc.is_empty() {
        req.nc.clone_from(&hope.nc);
    }
    if !hope.opaque.is_empty() {
        req.opaque.clone_from(&hope.opaque);
    }
}

fn digest_fail(hope: &SaHttpDigestModel) -> SaTokenError {
    SaTokenError::DigestAuthFailed {
        www_authenticate: build_www_authenticate(hope),
    }
}

fn build_www_authenticate(model: &SaHttpDigestModel) -> String {
    let realm = if model.realm.is_empty() {
        DEFAULT_REALM
    } else {
        model.realm.as_str()
    };
    let qop = if model.qop.is_empty() {
        DEFAULT_QOP
    } else {
        model.qop.as_str()
    };
    let nonce = if model.nonce.is_empty() {
        random_alnum(32)
    } else {
        model.nonce.clone()
    };
    let opaque = if model.opaque.is_empty() {
        random_alnum(32)
    } else {
        model.opaque.clone()
    };
    let nc = if model.nc.is_empty() {
        "00000001"
    } else {
        model.nc.as_str()
    };
    format!(r#"Digest realm="{realm}", qop="{qop}", nonce="{nonce}", nc={nc}, opaque="{opaque}""#)
}

fn random_alnum(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; len];
    if getrandom::getrandom(&mut bytes).is_err() {
        return "0".repeat(len);
    }
    bytes
        .iter()
        .map(|b| {
            CHARSET
                .get((*b as usize) % CHARSET.len())
                .copied()
                .unwrap_or(b'0') as char
        })
        .collect()
}
