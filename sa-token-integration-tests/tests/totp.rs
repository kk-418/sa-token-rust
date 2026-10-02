//! TOTP 公开 API 集成测试（对齐 Java `SaTotpUtil`）。

mod common;

use sa_token_core::{
    SaTokenError, SaTotpTemplate, check_totp, generate_google_secret_key,
    generate_google_secret_key_with_issuer, generate_google_secret_key_with_secret,
    generate_secret_key, generate_totp, validate_totp,
};

#[test]
fn generate_secret_key_is_nonempty_base32() {
    let secret = generate_secret_key();
    assert!(!secret.is_empty(), "secret must be non-empty");
    assert!(
        secret.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')),
        "secret must be RFC4648 Base32 without padding, got {secret}"
    );
    assert!(
        !secret.contains('='),
        "secret must not contain padding, got {secret}"
    );
}

#[test]
fn generate_totp_is_six_digits_and_validates() {
    let secret = generate_secret_key();
    let code = generate_totp(&secret);
    assert_eq!(code.len(), 6, "TOTP must be 6 digits, got {code}");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "TOTP must be numeric, got {code}"
    );
    assert!(
        validate_totp(&secret, &code, 0),
        "fresh TOTP must validate in the current window"
    );
}

#[test]
fn validate_totp_rejects_wrong_code() {
    let secret = generate_secret_key();
    let code = generate_totp(&secret);
    let wrong = if code == "000000" { "000001" } else { "000000" };
    assert!(
        !validate_totp(&secret, wrong, 0),
        "wrong code must not validate"
    );
}

#[test]
fn check_totp_wrong_code_returns_totp_auth_failed() {
    let secret = generate_secret_key();
    let code = generate_totp(&secret);
    let wrong = if code == "000000" { "000001" } else { "000000" };
    let err = check_totp(&secret, wrong, 0);
    assert!(
        matches!(err, Err(SaTokenError::TotpAuthFailed)),
        "check_totp wrong code, got {err:?}"
    );
}

#[test]
fn google_secret_key_starts_with_otpauth_and_contains_secret() {
    let uri = generate_google_secret_key("alice");
    assert!(
        uri.starts_with("otpauth://totp/"),
        "google uri must start with otpauth://totp/, got {uri}"
    );
    assert!(uri.contains("secret="), "google uri must contain secret=");

    let secret = generate_secret_key();
    let uri2 = generate_google_secret_key_with_secret("alice", &secret);
    assert!(uri2.starts_with("otpauth://totp/"));
    assert!(
        uri2.contains(&secret),
        "google uri must contain the given secret, got {uri2}"
    );

    let uri3 = generate_google_secret_key_with_issuer("alice", "Example", &secret);
    assert!(uri3.starts_with("otpauth://totp/"));
    assert!(uri3.contains("Example:alice"));
    assert!(uri3.contains(&format!("secret={secret}")));
    assert!(uri3.contains("issuer=Example"));
}

#[test]
fn template_api_matches_free_functions() {
    let tpl = SaTotpTemplate::default();
    let secret = tpl.generate_secret_key();
    let code = tpl.generate_totp(&secret);
    assert!(tpl.validate_totp(&secret, &code, 0));
    tpl.check_totp(&secret, &code, 0)
        .expect("template check_totp");
    assert!(validate_totp(&secret, &code, 0));
}
