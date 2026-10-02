// Author: 金书记 | Author: Jin Shuji
//! Request firewall (`SaFirewallStrategy` + default hooks).
//! 请求防火墙（对齐 Java `SaFirewallStrategy` 与默认 9 个 hook）。
//!
//! Hook order matches Java: WhitePath (skip rest) → BlackPath → danger characters
//! → banned characters → directory traversal → Host → HttpMethod → Header → Parameter.
//! hook 顺序对齐 Java：白名单（命中则跳过后续）→ 黑名单 → 危险字符 → 禁止字符
//! → 目录穿越 → Host → HttpMethod → Header → Parameter。
//!
//! `SaRequest` is not object-safe (generic `get_body_json`), so hooks take
//! [`FirewallRequest`] instead of `dyn SaRequest`.
//! `SaRequest` 因泛型 `get_body_json` 非对象安全，hook 使用 [`FirewallRequest`]。

mod hooks;

use std::sync::{Arc, PoisonError};
use std::sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use sa_token_adapter::context::SaRequest;

use crate::error::SaTokenResult;

pub use hooks::{
    BlackPathHook, DEFAULT_DANGER_CHARACTERS, DEFAULT_HTTP_METHODS, DirectoryTraversalHook,
    HeaderHook, HostHook, HttpMethodHook, ParameterHook, PathBannedCharacterHook,
    PathDangerCharacterHook, WhitePathHook,
};

pub(crate) fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) struct DefaultHooks {
    pub white_path: Arc<WhitePathHook>,
    pub black_path: Arc<BlackPathHook>,
    pub danger: Arc<PathDangerCharacterHook>,
    pub banned: Arc<PathBannedCharacterHook>,
    pub traversal: Arc<DirectoryTraversalHook>,
    pub host: Arc<HostHook>,
    pub http_method: Arc<HttpMethodHook>,
    pub header: Arc<HeaderHook>,
    pub parameter: Arc<ParameterHook>,
}

pub(crate) fn default_hooks() -> &'static DefaultHooks {
    static HOOKS: OnceLock<DefaultHooks> = OnceLock::new();
    HOOKS.get_or_init(|| DefaultHooks {
        white_path: Arc::new(WhitePathHook::new()),
        black_path: Arc::new(BlackPathHook::new()),
        danger: Arc::new(PathDangerCharacterHook::new()),
        banned: Arc::new(PathBannedCharacterHook::new()),
        traversal: Arc::new(DirectoryTraversalHook::new()),
        host: Arc::new(HostHook::new()),
        http_method: Arc::new(HttpMethodHook::new()),
        header: Arc::new(HeaderHook::new()),
        parameter: Arc::new(ParameterHook::new()),
    })
}

/// Object-safe request view used by firewall hooks.
/// 防火墙 hook 使用的对象安全请求视图。
pub trait FirewallRequest {
    /// Request path (`SaRequest::get_path`).
    /// 请求路径。
    fn get_path(&self) -> String;
    /// HTTP method (`SaRequest::get_method`).
    /// HTTP 方法。
    fn get_method(&self) -> String;
    /// Named header (`SaRequest::get_header`).
    /// 具名请求头。
    fn get_header(&self, name: &str) -> Option<String>;
    /// Named query/form parameter (`SaRequest::get_param`).
    /// 具名查询/表单参数。
    fn get_param(&self, name: &str) -> Option<String>;
    /// Host from `Host` / `host` header.
    /// 从 `Host` / `host` 头读取主机名。
    fn get_host(&self) -> Option<String> {
        self.get_header("Host").or_else(|| self.get_header("host"))
    }
}

impl<R: SaRequest> FirewallRequest for R {
    fn get_path(&self) -> String {
        SaRequest::get_path(self)
    }

    fn get_method(&self) -> String {
        SaRequest::get_method(self)
    }

    fn get_header(&self, name: &str) -> Option<String> {
        SaRequest::get_header(self, name)
    }

    fn get_param(&self, name: &str) -> Option<String> {
        SaRequest::get_param(self, name)
    }
}

/// Firewall hook (Java `SaFirewallCheckHook`).
/// 防火墙校验钩子（对齐 Java `SaFirewallCheckHook`）。
pub trait FirewallHook: Send + Sync {
    /// Stable hook name used by [`SaFirewallStrategy::remove_hook`].
    /// 稳定名称，供 [`SaFirewallStrategy::remove_hook`] 使用。
    fn name(&self) -> &'static str;

    /// Run this hook. `Err` rejects the request.
    /// 执行本 hook；返回 `Err` 则拒绝请求。
    fn execute(&self, req: &dyn FirewallRequest) -> SaTokenResult<()>;

    /// When `true`, remaining hooks are skipped and the request is allowed
    /// (Java WhitePath → `StopMatchException`).
    /// 为 `true` 时跳过后续 hook 并放行（对齐 Java 白名单 `StopMatchException`）。
    fn should_skip_rest(&self, _req: &dyn FirewallRequest) -> bool {
        false
    }
}

/// Firewall strategy holding an ordered hook list (Java `SaFirewallStrategy`).
/// 防火墙策略，持有有序 hook 列表（对齐 Java `SaFirewallStrategy`）。
pub struct SaFirewallStrategy {
    hooks: RwLock<Vec<Arc<dyn FirewallHook>>>,
}

impl std::fmt::Debug for SaFirewallStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hooks = read_lock(&self.hooks);
        let names: Vec<&str> = hooks.iter().map(|h| h.name()).collect();
        f.debug_struct("SaFirewallStrategy")
            .field("hooks", &names)
            .finish()
    }
}

impl SaFirewallStrategy {
    /// Build a strategy with the 9 default hooks (shared singleton instances).
    /// 构建装入 9 个默认 hook 的策略（共享单例实例）。
    #[must_use]
    pub fn default_strategy() -> Self {
        let h = default_hooks();
        Self {
            hooks: RwLock::new(vec![
                Arc::clone(&h.white_path) as Arc<dyn FirewallHook>,
                Arc::clone(&h.black_path) as Arc<dyn FirewallHook>,
                Arc::clone(&h.danger) as Arc<dyn FirewallHook>,
                Arc::clone(&h.banned) as Arc<dyn FirewallHook>,
                Arc::clone(&h.traversal) as Arc<dyn FirewallHook>,
                Arc::clone(&h.host) as Arc<dyn FirewallHook>,
                Arc::clone(&h.http_method) as Arc<dyn FirewallHook>,
                Arc::clone(&h.header) as Arc<dyn FirewallHook>,
                Arc::clone(&h.parameter) as Arc<dyn FirewallHook>,
            ]),
        }
    }

    /// Process-wide strategy (Java `SaFirewallStrategy.instance`).
    /// 进程级全局策略（对齐 Java `SaFirewallStrategy.instance`）。
    #[must_use]
    pub fn global() -> &'static Self {
        static GLOBAL: OnceLock<SaFirewallStrategy> = OnceLock::new();
        GLOBAL.get_or_init(Self::default_strategy)
    }

    /// Run the global strategy against `req`.
    /// 使用全局策略校验 `req`。
    pub fn check<R: SaRequest>(req: &R) -> SaTokenResult<()> {
        Self::global().check_request(req)
    }

    /// Run this strategy's hooks in order.
    /// 按顺序执行本策略的 hook。
    pub fn check_request(&self, req: &dyn FirewallRequest) -> SaTokenResult<()> {
        let hooks = read_lock(&self.hooks);
        for hook in hooks.iter() {
            if hook.should_skip_rest(req) {
                return Ok(());
            }
            hook.execute(req)?;
        }
        Ok(())
    }

    /// Append a hook (Java `registerHook`).
    /// 追加一个 hook（对齐 Java `registerHook`）。
    pub fn register_hook(&self, hook: Arc<dyn FirewallHook>) {
        tracing::info!(name = hook.name(), "firewall hook registered");
        write_lock(&self.hooks).push(hook);
    }

    /// Remove the first hook with `name` (Java `removeHook` by class).
    /// 移除第一个匹配 `name` 的 hook（对齐 Java 按类型 `removeHook`）。
    pub fn remove_hook(&self, name: &str) {
        let mut hooks = write_lock(&self.hooks);
        if let Some(idx) = hooks.iter().position(|h| h.name() == name) {
            hooks.remove(idx);
            tracing::info!(name, "firewall hook removed");
        }
    }
}

/// Java `SaFirewallCheckHookForDirectoryTraversal.isPathValid`.
/// 对齐 Java `isPathValid`：必须以 `/` 开头；`.` / `..` 组件非法；中间 `//` 非法。
///
/// Trailing empty segments from `/` are discarded like Java `String.split("/")`.
/// 末尾空段按 Java `String.split("/")` 丢弃。
#[must_use]
pub fn is_path_valid(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') {
        return false;
    }
    if path == "/" {
        return true;
    }

    let mut components: Vec<&str> = path.split('/').collect();
    while components.last() == Some(&"") {
        components.pop();
    }

    for (i, component) in components.iter().enumerate() {
        if component.is_empty() {
            if i == 0 {
                continue;
            }
            return false;
        }
        if *component == "." || *component == ".." {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SaTokenError;
    use sa_token_adapter::context::SaRequest;
    use std::collections::HashMap;

    struct MockReq {
        path: String,
        method: String,
        headers: HashMap<String, String>,
        params: HashMap<String, String>,
    }

    impl MockReq {
        fn new(path: &str) -> Self {
            Self {
                path: path.to_string(),
                method: "GET".to_string(),
                headers: HashMap::new(),
                params: HashMap::new(),
            }
        }
    }

    impl SaRequest for MockReq {
        fn get_header(&self, name: &str) -> Option<String> {
            self.headers.get(name).cloned()
        }

        fn get_cookie(&self, _name: &str) -> Option<String> {
            None
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

    #[test]
    fn firewall_is_path_valid_root_and_normal() {
        assert!(is_path_valid("/"));
        assert!(is_path_valid("/user/info"));
        assert!(is_path_valid("/.hidden"));
        assert!(is_path_valid("/file.js"));
        assert!(is_path_valid("/user/info/"));
    }

    #[test]
    fn firewall_is_path_valid_rejects_traversal() {
        assert!(!is_path_valid(""));
        assert!(!is_path_valid("user/info"));
        assert!(!is_path_valid("/user/../admin"));
        assert!(!is_path_valid("/user/info/."));
        assert!(!is_path_valid("/user/info/.."));
        assert!(!is_path_valid("/user//info"));
        assert!(!is_path_valid("//user"));
    }

    #[test]
    fn firewall_root_path_allowed() {
        SaFirewallStrategy::check(&MockReq::new("/")).expect("root must pass");
    }

    #[test]
    fn firewall_double_slash_rejected() {
        let err = SaFirewallStrategy::check(&MockReq::new("//foo")).expect_err("// must fail");
        assert!(matches!(err, SaTokenError::RequestPathInvalid { .. }));
        assert_eq!(err.code(), 12101);
    }

    #[test]
    fn firewall_dotdot_rejected() {
        let err =
            SaFirewallStrategy::check(&MockReq::new("/user/../admin")).expect_err(".. must fail");
        assert!(matches!(err, SaTokenError::RequestPathInvalid { .. }));
    }

    #[test]
    fn firewall_request_path_invalid_code() {
        let err = SaTokenError::RequestPathInvalid {
            path: "//".into(),
            reason: "danger".into(),
        };
        assert_eq!(err.code(), 12101);
        assert_eq!(SaTokenError::NotLogin.code(), 11011);
        assert_eq!(SaTokenError::TokenEmpty.code(), 11011);
        assert_eq!(SaTokenError::InvalidToken("x".into()).code(), 11012);
        assert_eq!(SaTokenError::TokenExpired.code(), 11013);
        assert_eq!(SaTokenError::AccountReplaced.code(), 11014);
        assert_eq!(SaTokenError::AccountKickedOut.code(), 11015);
        assert_eq!(SaTokenError::TokenInactive.code(), 11016);
        assert_eq!(SaTokenError::RoleDenied("r".into()).code(), 11041);
        assert_eq!(SaTokenError::PermissionDenied.code(), 11051);
        assert_eq!(SaTokenError::NotSafe("login".into()).code(), 11071);
        assert_eq!(SaTokenError::SameTokenInvalid.code(), 10301);
        assert_eq!(
            SaTokenError::BasicAuthFailed { realm: "r".into() }.code(),
            10311
        );
        assert_eq!(
            SaTokenError::DigestAuthFailed {
                www_authenticate: "x".into()
            }
            .code(),
            10312
        );
        assert_eq!(SaTokenError::InternalError("x".into()).code(), -1);
    }
}
