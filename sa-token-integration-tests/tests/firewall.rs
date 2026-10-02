//! Java `SaFirewallStrategy` parity: default hooks + `run_auth_flow` integration.
//! 对齐 Java 防火墙默认 hook，以及 `run_auth_flow` 接入。

mod common;

use std::collections::HashMap;

use common::setup;
use sa_token_adapter::context::SaRequest;
use sa_token_core::{
    BlackPathHook, SaFirewallStrategy, SaTokenError, WhitePathHook, router::run_auth_flow,
};
use serial_test::serial;

struct MockRequest {
    headers: HashMap<String, String>,
    cookies: HashMap<String, String>,
    params: HashMap<String, String>,
    path: String,
    method: String,
}

impl MockRequest {
    fn new(path: &str) -> Self {
        Self {
            headers: HashMap::new(),
            cookies: HashMap::new(),
            params: HashMap::new(),
            path: path.to_string(),
            method: "GET".to_string(),
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
        self.path.clone()
    }

    fn get_method(&self) -> String {
        self.method.clone()
    }
}

struct RestoreFirewallLists;

impl Drop for RestoreFirewallLists {
    fn drop(&mut self) {
        WhitePathHook::instance().reset_config(Vec::<String>::new());
        BlackPathHook::instance().reset_config(Vec::<String>::new());
    }
}

fn assert_path_invalid(result: Result<(), SaTokenError>, path: &str) {
    match result {
        Err(SaTokenError::RequestPathInvalid { path: p, .. }) => {
            assert_eq!(p, path);
        }
        Err(other) => panic!("expected RequestPathInvalid, got {other:?}"),
        Ok(()) => panic!("expected reject for path {path}"),
    }
}

#[test]
#[serial]
fn double_slash_path_rejected() {
    let path = "//foo";
    assert_path_invalid(SaFirewallStrategy::check(&MockRequest::new(path)), path);
}

#[test]
#[serial]
fn directory_traversal_rejected() {
    let path = "/user/../admin";
    assert_path_invalid(SaFirewallStrategy::check(&MockRequest::new(path)), path);
}

#[test]
#[serial]
fn white_path_skips_danger_characters() {
    let _restore = RestoreFirewallLists;
    let path = "//whitelisted";
    WhitePathHook::instance().reset_config([path]);
    SaFirewallStrategy::check(&MockRequest::new(path)).expect("white path must skip later hooks");
}

#[test]
#[serial]
fn black_path_rejected() {
    let _restore = RestoreFirewallLists;
    let path = "/blocked";
    BlackPathHook::instance().reset_config([path]);
    assert_path_invalid(SaFirewallStrategy::check(&MockRequest::new(path)), path);
    SaFirewallStrategy::check(&MockRequest::new("/"))
        .expect("root must still pass while blacklist is set");
}

#[test]
#[serial]
fn root_path_allowed() {
    SaFirewallStrategy::check(&MockRequest::new("/")).expect("root must pass");
}

#[tokio::test]
#[serial]
async fn run_auth_flow_double_slash_sets_firewall_error() {
    let mgr = setup::fresh_manager();
    let flow = run_auth_flow(&MockRequest::new("//"), &mgr, None).await;
    assert!(flow.should_reject(), "firewall fail must reject");
    assert!(
        flow.firewall_error.is_some(),
        "firewall_error must be Some for //"
    );
    assert!(matches!(
        flow.firewall_error,
        Some(SaTokenError::RequestPathInvalid { .. })
    ));
    assert!(flow.login_id.is_none());
    assert!(flow.token.is_none());
}
