# Java interop

English | [中文](/zh/guide/java-interop.md)

sa-token-rust defaults to native key layout and serde JSON. To share Redis stateful tokens, or JWTs (Simple / Mixin / Stateless), with **Java Sa-Token 1.46.0**, turn on the Java preset.

Native behaviour stays unchanged until you call `java_compatible()`.

## One-line preset

Call `java_compatible()` first. Later setters may override any field.

The preset sets `token_name="satoken"`, `key_layout=JavaFourSegment`, `wire=WireConfig::java()`, `max_login_count=12`, `auto_renew=false`, `active_refresh=true`, `max_try_times=12`. Other fields stay at their defaults (for example `timeout=2592000`). Keep `timeout` / `active_timeout` / `dynamic_active_timeout` / `is_concurrent` / `jwt_secret_key` in sync with Java.

### Builder

```rust
use sa_token_core::SaTokenConfig;
use sa_token_storage_redis::RedisStorage;
use std::sync::Arc;

// Redis storage-layer prefix must be empty, or you get sa:satoken:login:token:
let storage = Arc::new(RedisStorage::connect("redis://127.0.0.1:6379/0").await?);

let manager = SaTokenConfig::builder()
    .storage(storage)
    .java_compatible()
    .timeout(2592000)
    .jwt_secret_key("same-as-java") // JWT only
    .try_build()?;
```

Or take the config object: `let config = SaTokenConfig::java_compatible();`

`config.wire` is a `WireConfig`. Replace the whole block with `WireConfig::native()` / `WireConfig::java()`:

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

`wire = "java"` fills `config.wire` only. Full interop also needs the top-level fields:

```toml
token_name = "satoken"
key_layout = "JavaFourSegment"
max_login_count = 12
auto_renew = false
active_refresh = true
max_try_times = 12
wire = "java"
```

Partial overlay:

```toml
[wire]
preset = "java"
allow_login_id_colon = true
```

JWT Mixin style alias `jwt-mixin`:

```toml
token_style = "jwt-mixin"
jwt_secret_key = "same-as-java"
wire = "java"
```

## Config matrix

| Field | Native | Java | Effect |
|-------|--------|------|--------|
| `token_name` | `sa-token` | `satoken` | Cookie / header name; Java layout key root |
| `key_layout` | `ThreeSegment` | `JavaFourSegment` | `sa:token:{t}` vs `satoken:login:token:{t}` |
| `storage_key_prefix` | `sa:` | Java layout uses `token_name` | Logical key root; **Redis storage-layer prefix must be `""`** |
| `max_login_count` | `-1` | `12` | Concurrent logins per account; `-1` means unlimited |
| `auto_renew` | `false` | `false` | Neither side renews token TTL |
| `active_refresh` | `false` | `true` | Java `autoRenew`: refresh last-active only |
| `max_try_times` | `12` | `12` | Retries when allocating a unique token |
| `default_login_type` | `default` | `login` | Account system when login type is omitted |
| `token_value` | `InfoJson` | `LoginId` | Token key holds full `TokenInfo` JSON vs bare loginId |
| `last_active` | `InTokenInfo` | `SeparateKey` | last-active inside TokenInfo vs a separate key |
| `account_index` | `RustIndexKeys` | `SessionTerminals` | Reverse lookup via `login:token` lists vs Account-Session `terminalList` |
| `session_format` | `Serde` | `Jackson3Typed` | snake_case / RFC3339 vs `@class` / camelCase / millis |
| `login_id_json` | `Auto` | `Auto` | Infer String / Long from the written value |
| `allow_login_id_colon` | `true` | `false` | Java rejects `:` in loginId |
| `default_device_type` | `None` | `DEF` | Default device when login omits one |
| `safe_value` / `default_safe_service` | `ok` / `""` | `SAFE_AUTH_SAVE_VALUE` / `important` | Secondary-auth occupancy and default service |
| `default_disable_service` | `login` | `login` | Default disable service |
| `temp_token_format` / namespace | `Wrapped` / `default` | `JavaRaw` / `temp-token` | Temp-token payload and key namespace |
| `api_key_format` / namespace | `Serde` / `apikey` | `JavaModel` / `apikey` | API-key model and key namespace |
| `application_value` | `Serde` | `JavaRoot` | Application / root-object JSON |
| `jwt_claims` | `Standard` | `Java` | `sub`/`exp` vs `loginType`/`loginId`/`eff` |
| `sign_nonce` | `Rust` | `Java` | Native nonce record vs value = nonce |
| `sign_algorithm` | `HmacSha256` | `Md5` | Second-based HMAC vs Java `k=v&...&key=secret` millis MD5 |
| `same_token_past_ttl` | `Full` | `Remaining` | Past Same-Token uses full timeout vs remaining TTL |

`LoginId` requires `SeparateKey`. `TokenStyle::JwtMixin` requires `SeparateKey` and `is_concurrent=true`. `jwt_claims=Java` allows HS256 only. `try_build` validates this.

## Java-side requirements

- Serialization: `sa-token-jackson3`.
- Storage: `sa-token-redis-template` (`StringRedisTemplate`) **or** Redisson `StringCodec`. Values must be strings, not JDK-serialized bytes.
- Match these settings: `tokenName`, `jwtSecretKey`, `timeout`, `activeTimeout`, `dynamicActiveTimeout`, `isConcurrent`.
- Redis **6+** (kick-out / replaced markers use `SET … KEEPTTL`).
- Custom beans in Session need a `SaJsonStrategy` whitelist on the Java side.

## Pitfalls

| Topic | Note |
|-------|------|
| loginId Long vs String | The token-key value is `String.valueOf(loginId)`: Long `10001` and `"10001"` share the same token key. In Session, Long is typed `["java.lang.Long",n]`; String is a bare JSON string. |
| Colon | Java forbids `:` in loginId. The preset sets `allow_login_id_colon=false`. |
| `-1`…`-5` | Reserved for kick-out / replaced markers. LoginId mode must not use them as a loginId. |
| Serializer stack | Interop is jackson3 only. Do **not** mix JDK serialization, fastjson, or fory. |
| Rust-only keys | Native mode writes `token-id` and `login:token` lists; Java ignores them. In `SessionTerminals` mode Rust no longer writes those keys. |
| Session concurrency | Whole-session JSON read/write; last-writer-wins. |
| JwtMixin | Login writes Account-Session + last-active, not the token key. `kick_out` / `logout_by_login_id` / `replaced` / `renew` are unavailable (`ApiDisabled`). |
| Root object Map | temp-token Map and application Map have **no** `@class`. Java typed `Object.class` reads fail; read as `Map`. |
| Redis `key_prefix` | Must be `""`. Otherwise keys become `sa:satoken:login:token:` and Java cannot see them. Use `RedisStorage::connect(...)` or `.key_prefix("")`. |

## Related

- [JWT](/guide/jwt.md)
- [Storage](/guide/storage.md)
- [Token styles](/guide/token-styles.md)
- [Multi-account](/guide/multi-account.md)
