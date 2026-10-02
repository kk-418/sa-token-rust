//! Axum Layer：login/logout 自动写/清 Cookie。独立二进制，避免与 `plugin_axum.rs` 的 shared_manager 冲突。

mod common;

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use axum::body::{Body, to_bytes};
use axum_08 as axum;
use common::setup;
use http::{Request, Response, StatusCode, header};
use sa_token_core::{SaTokenConfig, SaTokenManager, StpUtil, config::TokenStyle};
use sa_token_plugin_axum::{SaTokenLayer, SaTokenState as AxumState};
use tower::{Layer, Service, ServiceExt};
use tower_08 as tower;

fn cookie_state() -> AxumState {
    static STATE: OnceLock<AxumState> = OnceLock::new();
    STATE
        .get_or_init(|| {
            let storage = setup::memory_storage();
            let config = SaTokenConfig::builder()
                .token_name("Authorization")
                .timeout(86400)
                .token_style(TokenStyle::Uuid)
                .is_read_cookie(true)
                .is_write_cookie(true)
                .is_concurrent(true)
                .build_config();
            let manager = SaTokenManager::new(storage, config);
            let _ = StpUtil::try_init_manager(manager.clone());
            AxumState {
                manager: Arc::new(manager),
            }
        })
        .clone()
}

#[derive(Clone)]
struct LoginSvc {
    login_id: String,
}

impl Service<Request<Body>> for LoginSvc {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        let id = self.login_id.clone();
        Box::pin(async move {
            let token = StpUtil::login_with_timeout(&id, 86400)
                .await
                .expect("login");
            Ok(Response::new(Body::from(token.to_string())))
        })
    }
}

#[derive(Clone)]
struct LogoutSvc;

impl Service<Request<Body>> for LogoutSvc {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        Box::pin(async move {
            StpUtil::logout_current().await.expect("logout_current");
            Ok(Response::new(Body::from("ok")))
        })
    }
}

#[derive(Clone)]
struct NoopSvc;

impl Service<Request<Body>> for NoopSvc {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        Box::pin(async move { Ok(Response::new(Body::from("ok"))) })
    }
}

async fn body_str(res: Response<Body>) -> String {
    let bytes = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

fn set_cookie_header(res: &Response<Body>) -> String {
    res.headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie")
        .to_str()
        .expect("utf8 Set-Cookie")
        .to_string()
}

#[tokio::test]
async fn test_login_with_timeout_sets_cookie() {
    let state = cookie_state();
    let id = setup::unique_login_id("axum_cookie_login");
    let mut svc = SaTokenLayer::new(state).layer(LoginSvc { login_id: id });

    let req = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .expect("request");
    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(req)
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);

    let set_cookie = set_cookie_header(&res);
    assert!(
        set_cookie.contains("Authorization="),
        "missing Authorization=: {set_cookie}"
    );
    assert!(
        set_cookie.contains("Max-Age=86400"),
        "missing Max-Age=86400: {set_cookie}"
    );
    assert!(
        set_cookie.contains("HttpOnly"),
        "missing HttpOnly: {set_cookie}"
    );
    assert!(
        set_cookie.contains("SameSite=Lax"),
        "missing SameSite=Lax: {set_cookie}"
    );
    assert!(
        set_cookie.contains("Path=/"),
        "missing Path=/: {set_cookie}"
    );

    let body = body_str(res).await;
    assert!(
        set_cookie.contains(&format!("Authorization={body}")),
        "cookie token should match body: cookie={set_cookie} body={body}"
    );
}

#[tokio::test]
async fn test_logout_current_clears_cookie() {
    let state = cookie_state();
    let id = setup::unique_login_id("axum_cookie_logout");
    let token = StpUtil::login_with_timeout(&id, 86400)
        .await
        .expect("login");

    let mut svc = SaTokenLayer::new(state).layer(LogoutSvc);
    let req = Request::builder()
        .uri("/logout")
        .header("Authorization", token.as_str())
        .body(Body::empty())
        .expect("request");
    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(req)
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);

    let set_cookie = set_cookie_header(&res);
    assert!(
        set_cookie.contains("Max-Age=0"),
        "missing Max-Age=0: {set_cookie}"
    );
}

#[tokio::test]
async fn test_layer_does_not_set_cookie_without_pending() {
    let state = cookie_state();
    let mut svc = SaTokenLayer::new(state).layer(NoopSvc);
    let req = Request::builder()
        .uri("/ok")
        .body(Body::empty())
        .expect("request");
    let res = svc
        .ready()
        .await
        .expect("ready")
        .call(req)
        .await
        .expect("call");
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get(header::SET_COOKIE).is_none(),
        "unexpected Set-Cookie: {:?}",
        res.headers().get(header::SET_COOKIE)
    );
}
