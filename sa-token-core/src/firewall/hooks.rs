// Author: 金书记 | Author: Jin Shuji
//! Default firewall hooks aligned with Java `SaFirewallCheckHookFor*`.
//! 默认防火墙 hook，对齐 Java `SaFirewallCheckHookFor*`。

use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{SaTokenError, SaTokenResult};
use crate::firewall::{
    FirewallHook, FirewallRequest, default_hooks, is_path_valid, read_lock, write_lock,
};
use crate::permission::{PermissionMatcher, VaguePermissionMatcher};

/// Default danger characters (Java `SaFirewallCheckHookForPathDangerCharacter`).
/// 默认危险字符列表（对齐 Java）。
pub const DEFAULT_DANGER_CHARACTERS: &[&str] = &[
    "//", "\\", "%2e", "%2E", "%2f", "%2F", "%5c", "%5C", ";", "%3b", "%3B", "%25", "\0", "%00",
    "\n", "%0a", "%0A", "\r", "%0d", "%0D", "\u{2028}", "\u{2029}",
];

/// Default allowed HTTP methods (Java `SaFirewallCheckHookForHttpMethod` constructor).
/// 默认允许的 HTTP Method（对齐 Java 构造器）。
pub const DEFAULT_HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
];

fn path_invalid(path: &str, reason: &str) -> SaTokenError {
    SaTokenError::RequestPathInvalid {
        path: path.to_string(),
        reason: reason.to_string(),
    }
}

fn replace_list<I, S>(lock: &RwLock<Vec<String>>, items: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut guard = write_lock(lock);
    guard.clear();
    guard.extend(items.into_iter().map(|s| s.as_ref().to_string()));
}

fn list_contains(lock: &RwLock<Vec<String>>, item: &str) -> bool {
    read_lock(lock).iter().any(|p| p == item)
}

/// White-path hook: exact match skips remaining hooks (Java `StopMatchException`).
/// 白名单 hook：精确命中后跳过后续 hook（对齐 Java `StopMatchException`）。
#[derive(Debug)]
pub struct WhitePathHook {
    paths: RwLock<Vec<String>>,
}

impl WhitePathHook {
    pub(crate) fn new() -> Self {
        Self {
            paths: RwLock::new(Vec::new()),
        }
    }

    /// Global singleton used by the default strategy.
    /// 默认策略使用的全局单例。
    #[must_use]
    pub fn instance() -> &'static Self {
        default_hooks().white_path.as_ref()
    }

    /// Replace the white-path list (Java `resetConfig`).
    /// 替换白名单（对齐 Java `resetConfig`）。
    pub fn reset_config<I, S>(&self, paths: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        replace_list(&self.paths, paths);
    }
}

impl FirewallHook for WhitePathHook {
    fn name(&self) -> &'static str {
        "WhitePath"
    }

    fn execute(&self, _req: &dyn FirewallRequest) -> SaTokenResult<()> {
        Ok(())
    }

    fn should_skip_rest(&self, req: &dyn FirewallRequest) -> bool {
        list_contains(&self.paths, &req.get_path())
    }
}

/// Black-path hook: exact match rejects the request.
/// 黑名单 hook：精确命中则拒绝。
#[derive(Debug)]
pub struct BlackPathHook {
    paths: RwLock<Vec<String>>,
}

impl BlackPathHook {
    pub(crate) fn new() -> Self {
        Self {
            paths: RwLock::new(Vec::new()),
        }
    }

    /// Global singleton used by the default strategy.
    /// 默认策略使用的全局单例。
    #[must_use]
    pub fn instance() -> &'static Self {
        default_hooks().black_path.as_ref()
    }

    /// Replace the black-path list (Java `resetConfig`).
    /// 替换黑名单（对齐 Java `resetConfig`）。
    pub fn reset_config<I, S>(&self, paths: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        replace_list(&self.paths, paths);
    }
}

impl FirewallHook for BlackPathHook {
    fn name(&self) -> &'static str {
        "BlackPath"
    }

    fn execute(&self, req: &dyn FirewallRequest) -> SaTokenResult<()> {
        let path = req.get_path();
        if list_contains(&self.paths, &path) {
            return Err(path_invalid(&path, "blacklisted path"));
        }
        Ok(())
    }
}

/// Danger-character hook: reject if the path contains any configured substring.
/// 危险字符 hook：路径包含任一配置子串则拒绝。
#[derive(Debug)]
pub struct PathDangerCharacterHook {
    characters: RwLock<Vec<String>>,
}

impl PathDangerCharacterHook {
    pub(crate) fn new() -> Self {
        Self {
            characters: RwLock::new(
                DEFAULT_DANGER_CHARACTERS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            ),
        }
    }

    /// Global singleton used by the default strategy.
    /// 默认策略使用的全局单例。
    #[must_use]
    pub fn instance() -> &'static Self {
        default_hooks().danger.as_ref()
    }

    /// Replace the danger-character list (Java `resetConfig`).
    /// 替换危险字符列表（对齐 Java `resetConfig`）。
    pub fn reset_config<I, S>(&self, characters: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        replace_list(&self.characters, characters);
    }
}

impl FirewallHook for PathDangerCharacterHook {
    fn name(&self) -> &'static str {
        "PathDangerCharacter"
    }

    fn execute(&self, req: &dyn FirewallRequest) -> SaTokenResult<()> {
        let path = req.get_path();
        let characters = read_lock(&self.characters);
        for item in characters.iter() {
            if path.contains(item) {
                return Err(path_invalid(&path, "danger character"));
            }
        }
        Ok(())
    }
}

/// Banned-character hook: non-printable ASCII, optional `%` (Java default).
/// 禁止字符 hook：非可打印 ASCII，可选禁止 `%`（对齐 Java 默认）。
#[derive(Debug)]
pub struct PathBannedCharacterHook {
    banned_percentage: AtomicBool,
}

impl PathBannedCharacterHook {
    pub(crate) fn new() -> Self {
        Self {
            banned_percentage: AtomicBool::new(false),
        }
    }

    /// Global singleton used by the default strategy.
    /// 默认策略使用的全局单例。
    #[must_use]
    pub fn instance() -> &'static Self {
        default_hooks().banned.as_ref()
    }

    /// Replace config (Java `resetConfig(boolean bannedPercentage)`).
    /// 重载配置（对齐 Java `resetConfig(boolean)`）。
    pub fn reset_config(&self, banned_percentage: bool) {
        self.banned_percentage
            .store(banned_percentage, Ordering::Relaxed);
    }
}

fn has_non_printable_ascii(s: &str) -> bool {
    s.chars().any(|c| {
        let u = c as u32;
        u <= 31 || u == 127
    })
}

impl FirewallHook for PathBannedCharacterHook {
    fn name(&self) -> &'static str {
        "PathBannedCharacter"
    }

    fn execute(&self, req: &dyn FirewallRequest) -> SaTokenResult<()> {
        let path = req.get_path();
        if has_non_printable_ascii(&path) {
            return Err(path_invalid(&path, "non-printable ASCII"));
        }
        if self.banned_percentage.load(Ordering::Relaxed) && path.contains('%') {
            return Err(path_invalid(&path, "banned character %"));
        }
        Ok(())
    }
}

/// Directory-traversal hook (Java `isPathValid`).
/// 目录穿越 hook（对齐 Java `isPathValid`）。
#[derive(Debug, Default)]
pub struct DirectoryTraversalHook;

impl DirectoryTraversalHook {
    pub(crate) fn new() -> Self {
        Self
    }

    /// Global singleton used by the default strategy.
    /// 默认策略使用的全局单例。
    #[must_use]
    pub fn instance() -> &'static Self {
        default_hooks().traversal.as_ref()
    }
}

impl FirewallHook for DirectoryTraversalHook {
    fn name(&self) -> &'static str {
        "DirectoryTraversal"
    }

    fn execute(&self, req: &dyn FirewallRequest) -> SaTokenResult<()> {
        let path = req.get_path();
        if is_path_valid(&path) {
            Ok(())
        } else {
            Err(path_invalid(&path, "directory traversal"))
        }
    }
}

/// Host hook: empty/disabled config does not reject (Java `isCheckHost = false`).
/// Host hook：空配置 / 关闭时不拦截（对齐 Java `isCheckHost = false`）。
#[derive(Debug)]
pub struct HostHook {
    is_check: AtomicBool,
    allow_hosts: RwLock<Vec<String>>,
}

impl HostHook {
    pub(crate) fn new() -> Self {
        Self {
            is_check: AtomicBool::new(false),
            allow_hosts: RwLock::new(Vec::new()),
        }
    }

    /// Global singleton used by the default strategy.
    /// 默认策略使用的全局单例。
    #[must_use]
    pub fn instance() -> &'static Self {
        default_hooks().host.as_ref()
    }

    /// Replace host-check config (Java `resetConfig`).
    /// 重载 Host 校验配置（对齐 Java `resetConfig`）。
    pub fn reset_config<I, S>(&self, is_check_host: bool, allow_hosts: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.is_check.store(is_check_host, Ordering::Relaxed);
        replace_list(&self.allow_hosts, allow_hosts);
    }
}

fn host_allowed(allow: &[String], host: &str) -> bool {
    if allow.iter().any(|h| h == host) {
        return true;
    }
    let matcher = VaguePermissionMatcher;
    allow.iter().any(|p| matcher.matches_one(p, host))
}

impl FirewallHook for HostHook {
    fn name(&self) -> &'static str {
        "Host"
    }

    fn execute(&self, req: &dyn FirewallRequest) -> SaTokenResult<()> {
        if !self.is_check.load(Ordering::Relaxed) {
            return Ok(());
        }
        let host = req.get_host().unwrap_or_default();
        let allow = read_lock(&self.allow_hosts);
        if host_allowed(&allow, &host) {
            Ok(())
        } else {
            Err(path_invalid(&req.get_path(), "illegal host"))
        }
    }
}

/// HTTP method hook: disabled by default so empty config does not reject.
/// HTTP Method hook：默认关闭，空配置不拦截。
#[derive(Debug)]
pub struct HttpMethodHook {
    is_check: AtomicBool,
    allow_methods: RwLock<Vec<String>>,
}

impl HttpMethodHook {
    pub(crate) fn new() -> Self {
        Self {
            is_check: AtomicBool::new(false),
            allow_methods: RwLock::new(
                DEFAULT_HTTP_METHODS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            ),
        }
    }

    /// Global singleton used by the default strategy.
    /// 默认策略使用的全局单例。
    #[must_use]
    pub fn instance() -> &'static Self {
        default_hooks().http_method.as_ref()
    }

    /// Replace method-check config (Java `resetConfig`).
    /// 重载 Method 校验配置（对齐 Java `resetConfig`）。
    pub fn reset_config<I, S>(&self, is_check_method: bool, methods: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.is_check.store(is_check_method, Ordering::Relaxed);
        replace_list(&self.allow_methods, methods);
    }
}

impl FirewallHook for HttpMethodHook {
    fn name(&self) -> &'static str {
        "HttpMethod"
    }

    fn execute(&self, req: &dyn FirewallRequest) -> SaTokenResult<()> {
        if !self.is_check.load(Ordering::Relaxed) {
            return Ok(());
        }
        let method = req.get_method();
        let allow = read_lock(&self.allow_methods);
        if allow.iter().any(|m| m == &method) {
            Ok(())
        } else {
            Err(path_invalid(&req.get_path(), "illegal method"))
        }
    }
}

/// Header hook: empty not-allow list does not reject.
/// 请求头 hook：空名单不拦截。
#[derive(Debug)]
pub struct HeaderHook {
    not_allow: RwLock<Vec<String>>,
}

impl HeaderHook {
    pub(crate) fn new() -> Self {
        Self {
            not_allow: RwLock::new(Vec::new()),
        }
    }

    /// Global singleton used by the default strategy.
    /// 默认策略使用的全局单例。
    #[must_use]
    pub fn instance() -> &'static Self {
        default_hooks().header.as_ref()
    }

    /// Replace the not-allow header list (Java `resetConfig`).
    /// 替换不允许的请求头列表（对齐 Java `resetConfig`）。
    pub fn reset_config<I, S>(&self, names: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        replace_list(&self.not_allow, names);
    }
}

impl FirewallHook for HeaderHook {
    fn name(&self) -> &'static str {
        "Header"
    }

    fn execute(&self, req: &dyn FirewallRequest) -> SaTokenResult<()> {
        let names = read_lock(&self.not_allow);
        for name in names.iter() {
            if req.get_header(name).is_some() {
                return Err(path_invalid(&req.get_path(), "illegal header"));
            }
        }
        Ok(())
    }
}

/// Parameter hook: empty not-allow list does not reject.
/// 请求参数 hook：空名单不拦截。
#[derive(Debug)]
pub struct ParameterHook {
    not_allow: RwLock<Vec<String>>,
}

impl ParameterHook {
    pub(crate) fn new() -> Self {
        Self {
            not_allow: RwLock::new(Vec::new()),
        }
    }

    /// Global singleton used by the default strategy.
    /// 默认策略使用的全局单例。
    #[must_use]
    pub fn instance() -> &'static Self {
        default_hooks().parameter.as_ref()
    }

    /// Replace the not-allow parameter list (Java `resetConfig`).
    /// 替换不允许的请求参数列表（对齐 Java `resetConfig`）。
    pub fn reset_config<I, S>(&self, names: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        replace_list(&self.not_allow, names);
    }
}

impl FirewallHook for ParameterHook {
    fn name(&self) -> &'static str {
        "Parameter"
    }

    fn execute(&self, req: &dyn FirewallRequest) -> SaTokenResult<()> {
        let names = read_lock(&self.not_allow);
        for name in names.iter() {
            if req.get_param(name).is_some() {
                return Err(path_invalid(&req.get_path(), "illegal parameter"));
            }
        }
        Ok(())
    }
}
