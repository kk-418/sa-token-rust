# 与 Java 共享 Token

[English](/guide/java-interop.md) | 中文

sa-token-rust 默认用原生键布局与 serde JSON。要与 **Java Sa-Token 1.46.0** 共享 Redis 有状态 token，或共享 JWT（Simple / Mixin / Stateless），打开 Java 预设。

不调用 `java_compatible()` 时行为不变。

## 一行预设

先调 `java_compatible()`，后续 setter 可覆盖单项。

预设会设置：`token_name="satoken"`、`key_layout=JavaFourSegment`、`wire=WireConfig::java()`、`max_login_count=12`、`auto_renew=false`、`active_refresh=true`、`max_try_times=12`。其余字段仍是默认值（例如 `timeout=2592000`）。`timeout` / `active_timeout` / `dynamic_active_timeout` / `is_concurrent` / `jwt_secret_key` 必须与 Java 端一致。

### Builder

```rust
use sa_token_core::SaTokenConfig;
use sa_token_storage_redis::RedisStorage;
use std::sync::Arc;

// Redis 存储层 prefix 必须空串，避免 sa:satoken:login:token: 双前缀
let storage = Arc::new(RedisStorage::connect("redis://127.0.0.1:6379/0").await?);

let manager = SaTokenConfig::builder()
    .storage(storage)
    .java_compatible()
    .timeout(2592000)
    .jwt_secret_key("same-as-java") // 仅 JWT 需要
    .try_build()?;
```

也可以先拿配置对象：`let config = SaTokenConfig::java_compatible();`

`config.wire` 类型是 `WireConfig`。整体替换用 `WireConfig::native()` / `WireConfig::java()`：

```rust
use sa_token_core::{SaTokenConfig, WireConfig};

SaTokenConfig::builder()
    .java_compatible()
    .wire(WireConfig::java())
    .token_name("satoken")
    .try_build()?;
```

### plugin-common

```rust
use sa_token_plugin_axum::*;
use sa_token_storage_redis::RedisStorage;
use std::sync::Arc;

let storage = Arc::new(RedisStorage::connect("redis://127.0.0.1:6379/0").await?);
let state = SaTokenState::builder()
    .storage(storage)
    .java_compatible()
    .build();
```

### TOML

`wire = "java"` 只填 `config.wire`。完整互通还要顶层字段：

```toml
token_name = "satoken"
key_layout = "JavaFourSegment"
max_login_count = 12
auto_renew = false
active_refresh = true
max_try_times = 12
wire = "java"
```

局部覆盖：

```toml
[wire]
preset = "java"
allow_login_id_colon = true
```

JWT Mixin 风格别名 `jwt-mixin`：

```toml
token_style = "jwt-mixin"
jwt_secret_key = "same-as-java"
wire = "java"
```

## 配置对照

| 字段 | 原生 | Java | 影响 |
|------|------|------|------|
| `token_name` | `sa-token` | `satoken` | Cookie / Header 名；Java 布局的键根 |
| `key_layout` | `ThreeSegment` | `JavaFourSegment` | `sa:token:{t}` vs `satoken:login:token:{t}` |
| `storage_key_prefix` | `sa:` | Java 布局改用 `token_name` | 逻辑键根；**Redis 存储层 prefix 必须 `""`** |
| `max_login_count` | `-1` | `12` | 同账号并发登录上限；`-1` 不限制 |
| `auto_renew` | `false` | `false` | 两边都不续 token TTL |
| `active_refresh` | `false` | `true` | 对应 Java `autoRenew`：只续 last-active |
| `max_try_times` | `12` | `12` | 分配唯一 token 的重试次数 |
| `default_login_type` | `default` | `login` | 省略 login_type 时的账号体系 |
| `token_value` | `InfoJson` | `LoginId` | Token 键存完整 `TokenInfo` JSON vs 纯 loginId |
| `last_active` | `InTokenInfo` | `SeparateKey` | last-active 写在 TokenInfo 内 vs 独立键 |
| `account_index` | `RustIndexKeys` | `SessionTerminals` | 反查走 `login:token` 列表 vs Account-Session `terminalList` |
| `session_format` | `Serde` | `Jackson3Typed` | snake_case / RFC3339 vs `@class` / camelCase / 毫秒 |
| `login_id_json` | `Auto` | `Auto` | 按写入值推断 String / Long |
| `allow_login_id_colon` | `true` | `false` | Java 不允许 loginId 含 `:` |
| `default_device_type` | `None` | `DEF` | 登录未指定设备时的默认值 |
| `safe_value` / `default_safe_service` | `ok` / `""` | `SAFE_AUTH_SAVE_VALUE` / `important` | 二级认证占位值与默认服务名 |
| `default_disable_service` | `login` | `login` | 默认封禁服务名 |
| `temp_token_format` / namespace | `Wrapped` / `default` | `JavaRaw` / `temp-token` | 临时 Token 值与键命名空间 |
| `api_key_format` / namespace | `Serde` / `apikey` | `JavaModel` / `apikey` | API Key 模型与键命名空间 |
| `application_value` | `Serde` | `JavaRoot` | 应用变量 / 根对象 JSON |
| `jwt_claims` | `Standard` | `Java` | `sub`/`exp` vs `loginType`/`loginId`/`eff` |
| `sign_nonce` | `Rust` | `Java` | nonce 记录 vs 值为 nonce 本身 |
| `sign_algorithm` | `HmacSha256` | `Md5` | 秒级 HMAC vs Java `k=v&...&key=secret` 毫秒 MD5 |
| `same_token_past_ttl` | `Full` | `Remaining` | 旧 Same-Token 用完整 timeout vs 剩余寿命 |
| `opaque_gen` | `Native` | `Java` | Random hex vs `[A-Za-z0-9]`；Tik 8 位 vs `{2}_{14}_{16}__`；Same-Token 32 hex vs 64 字母数字；API Key 后缀 36 hex vs 36 字母数字 |

`LoginId` 必须搭配 `SeparateKey`。`TokenStyle::JwtMixin` 必须 `SeparateKey` 且 `is_concurrent=true`。`jwt_claims=Java` 只允许 HS256。`try_build` 会校验。

## Java 端要求

- 序列化：`sa-token-jackson3`。
- 存储：`sa-token-redis-template`（`StringRedisTemplate`）**或** Redisson `StringCodec`。值必须是字符串，不能是 JDK 序列化字节。
- 对齐这些配置：`tokenName`、`jwtSecretKey`、`timeout`、`activeTimeout`、`dynamicActiveTimeout`、`isConcurrent`。
- Redis **6+**（踢人 / 顶号标记用 `SET … KEEPTTL`）。
- Session 里放自定义 Bean 时，Java 端要把类型加入 `SaJsonStrategy` 白名单。

## 注意事项

| 点 | 说明 |
|----|------|
| loginId Long vs String | Token 键值是 `String.valueOf(loginId)`：Long `10001` 与 `"10001"` 共用同一 token 键。Session 里 Long 带类型包装 `["java.lang.Long",n]`，String 是裸字符串。 |
| 冒号 | Java 不允许 loginId 含 `:`。预设 `allow_login_id_colon=false`。 |
| `-1`…`-5` | 保留作踢人 / 顶号等标记。LoginId 模式不能把它们当 loginId。 |
| 序列化栈 | 只与 jackson3 互通。jdk 序列化、fastjson、fory **不可混用**。 |
| Rust 独有键 | 原生会写 `token-id`、`login:token` 列表等，Java 会忽略。`SessionTerminals` 模式下 Rust 不再写这些键。 |
| Session 并发 | 整份 Session JSON 读写，last-writer-wins。 |
| JwtMixin | 登录写 Account-Session + last-active，不写 token 键。`kick_out` / `logout_by_login_id` / `replaced` / `renew` 不可用（`ApiDisabled`）。 |
| 根对象 Map | temp-token Map、application Map **没有** `@class`。Java `Object.class` 类型化读取会失败，用 `Map` 读取。 |
| Redis `key_prefix` | 必须空串。否则变成 `sa:satoken:login:token:`，Java 读不到。用 `RedisStorage::connect(...)` 或 `.key_prefix("")`。 |

## 相关链接

- [JWT](/zh/guide/jwt.md)
- [存储后端](/zh/guide/storage.md)
- [Token 风格](/zh/guide/token-styles.md)
- [多账号体系](/zh/guide/multi-account.md)
