//! HTTP Digest 公开 API 集成测试（对齐 Java `SaHttpDigestUtil`）。

mod common;

use sa_token_core::http_digest::{self, SaHttpDigestModel, calc_response};
use sa_token_core::{RequestAuthMeta, SaTokenContext, SaTokenError};

fn hope_model() -> SaHttpDigestModel {
    SaHttpDigestModel {
        username: "sa".into(),
        password: "123456".into(),
        realm: "Sa-Token".into(),
        nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".into(),
        uri: "/test/testDigest".into(),
        method: "GET".into(),
        qop: "auth".into(),
        nc: "00000001".into(),
        cnonce: "f3ca6bfc0b2f59c4".into(),
        opaque: "5ccc069c403ebaf9f0171e9517f40e41".into(),
        response: String::new(),
    }
}

fn bind_digest_header(hope: &SaHttpDigestModel, response: &str) {
    let header = format!(
        r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}", qop={}, nc={}, cnonce="{}", opaque="{}""#,
        hope.username,
        hope.realm,
        hope.nonce,
        hope.uri,
        response,
        hope.qop,
        hope.nc,
        hope.cnonce,
        hope.opaque
    );
    let ctx = SaTokenContext::builder()
        .auth_meta(RequestAuthMeta {
            authorization: Some(header),
            method: Some(hope.method.clone()),
            path: Some(hope.uri.clone()),
            ..Default::default()
        })
        .build();
    SaTokenContext::set_current(ctx);
}

#[test]
fn digest_check_succeeds_with_calc_response() {
    SaTokenContext::clear();
    let hope = hope_model();
    let response = calc_response(&hope);
    assert_eq!(
        response.len(),
        32,
        "MD5 hex must be 32 chars, got {response}"
    );
    assert!(
        response.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "response must be lowercase hex, got {response}"
    );
    bind_digest_header(&hope, &response);
    http_digest::check(&hope).expect("digest check should succeed");
    SaTokenContext::clear();
}

#[test]
fn digest_check_wrong_password_returns_digest_auth_failed() {
    SaTokenContext::clear();
    let hope = hope_model();
    let response = calc_response(&hope);
    bind_digest_header(&hope, &response);

    let mut bad = hope.clone();
    bad.password = "wrong-password".into();
    let err = http_digest::check(&bad);
    match err {
        Err(SaTokenError::DigestAuthFailed { www_authenticate }) => {
            assert!(
                www_authenticate.contains("Digest"),
                "www_authenticate must contain Digest, got {www_authenticate}"
            );
            assert!(
                www_authenticate.contains("realm="),
                "www_authenticate must contain realm=, got {www_authenticate}"
            );
        }
        other => panic!("expected DigestAuthFailed, got {other:?}"),
    }
    SaTokenContext::clear();
}
