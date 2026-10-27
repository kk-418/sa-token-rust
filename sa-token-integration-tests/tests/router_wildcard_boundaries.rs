//! Segment boundaries for path-auth wildcards, including real Axum layer checks.
mod common;

use axum_08::{Router, body::Body};
use common::setup;
use http::{Request, StatusCode};
use sa_token_core::router::{PathAuthConfig, match_path};
use sa_token_plugin_axum::{SaTokenLayer, SaTokenState};
use tower_08::ServiceExt;

#[test]
fn double_star_requires_segment_boundary() {
    for (path, expected) in [
        ("/api", true),
        ("/api/", true),
        ("/api/a", true),
        ("/api/a/b", true),
        ("/api//a", true),
        ("/api-other", false),
        ("/api-other/a", false),
        ("/apis", false),
    ] {
        assert_eq!(match_path(path, "/api/**"), expected, "{path}");
    }
}

#[test]
fn single_star_requires_separator_and_preserves_empty_segments() {
    for (path, expected) in [
        ("/api", false),
        ("/api/", true),
        ("/api/a", true),
        ("/api/a/", false),
        ("/api/a/b", false),
        ("/api//", false),
        ("/api//a", false),
        ("/api-other", false),
        ("/api-other/a", false),
    ] {
        assert_eq!(match_path(path, "/api/*"), expected, "{path}");
    }
}

#[test]
fn root_wildcards_only_match_rooted_paths() {
    for (path, double, single) in [
        ("", true, false),
        ("/", true, true),
        ("/a", true, true),
        ("/a/b", true, false),
        ("//", true, false),
        ("relative", false, false),
    ] {
        assert_eq!(match_path(path, "/**"), double, "double: {path}");
        assert_eq!(match_path(path, "/*"), single, "single: {path}");
    }
}

async fn check_layer(exclude: &str, paths: &[(&str, bool)]) {
    let state = SaTokenState {
        manager: setup::shared_manager(),
    };
    let login = setup::unique_login_id("segment_boundary");
    let token = state.manager.login(&login).await.expect("login");
    let config = PathAuthConfig::new()
        .include(vec!["/**".into()])
        .exclude(vec![exclude.into()]);
    let app = Router::new()
        .fallback(|| async { "ok" })
        .layer(SaTokenLayer::with_path_auth(state, config));
    for (path, public) in paths {
        let req = Request::builder()
            .uri(*path)
            .body(Body::empty())
            .expect("request");
        let response = app.clone().oneshot(req).await.expect("response");
        assert_eq!(
            response.status(),
            if *public {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            },
            "anonymous: {path}"
        );
        let req = Request::builder()
            .uri(*path)
            .header("sa-token", token.as_str())
            .body(Body::empty())
            .expect("authenticated request");
        let response = app
            .clone()
            .oneshot(req)
            .await
            .expect("authenticated response");
        assert_eq!(response.status(), StatusCode::OK, "authenticated: {path}");
    }
}

#[tokio::test]
async fn double_star_exclusion_does_not_bypass_similar_prefix_login() {
    check_layer(
        "/public/**",
        &[
            ("/public", true),
            ("/public/", true),
            ("/public/a/b", true),
            ("/public-other", false),
            ("/public-other/a", false),
        ],
    )
    .await;
}

#[tokio::test]
async fn single_star_exclusion_does_not_bypass_root_or_repeated_separator_login() {
    check_layer(
        "/public/*",
        &[
            ("/public/", true),
            ("/public/a", true),
            ("/public", false),
            ("/public//", false),
            ("/public//a", false),
            ("/public/a/b", false),
            ("/public-other", false),
        ],
    )
    .await;
}
