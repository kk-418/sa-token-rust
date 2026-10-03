# Java Sa-Token 1.46.0 互通金样 harness

离线编译 Java Sa-Token 1.46.0 源码，跑 `FixtureGen` 生成金样、用 `Verify` 做 roundtrip / Rust dump 校验。

**不进 cargo workspace。不要 `mvn`、不要往 `~/.m2` 写东西。**

## 环境

- JDK 21（`JAVA_HOME` 或 `PATH` 里的 `javac` / `java`）
- 本机已有 jar（默认从 `~/.m2/repository` 读，只读）：
  - Jackson 3.1.0：`jackson-databind`、`jackson-core`
  - Jackson annotations：`com.fasterxml.jackson.core:jackson-annotations:2.21`（Jackson 3.1.0 databind 的 Import-Package 要求 `[2.21,)`）
  - hutool 5.8.36：`hutool-core`、`hutool-json`、`hutool-crypto`、`hutool-jwt`
- Java Sa-Token 源码：默认 `/Users/cikenerd/program/source-code/Sa-Token`（可用 `SA_TOKEN_SRC` 覆盖）

编译模块（`javac --release 21` 直编源码）：

- `sa-token-core`
- `sa-token-plugin/sa-token-jackson3`
- `sa-token-plugin/sa-token-jwt`
- `sa-token-plugin/sa-token-apikey`
- `sa-token-plugin/sa-token-sign`

class 输出到 `interop/java/out/`（已 gitignore，不要提交）。

## 命令

仓库根目录：

```bash
# 编译 + 对已有金样做 Verify 自检
bash scripts/java-interop.sh

# 重新生成金样并自检
bash scripts/java-interop.sh gen
```

等价拆步：

```bash
bash interop/java/build.sh
java -cp interop/java/out:<jars> FixtureGen sa-token-integration-tests/fixtures/java-1.46.0
java -cp interop/java/out:<jars> Verify sa-token-integration-tests/fixtures/java-1.46.0/login_long.json
```

若设置 `SA_INTEROP_DUMP_DIR`，脚本还会对目录里每个 `*.json` 跑 `Verify`（Rust dump 闭环；G 阶段该目录可以不存在）。

## 行为要点

- 内存 DAO 实现 `SaTokenDaoByObjectFollowString`：string 存储即 object 存储（对齐 StringRedisTemplate）。
- Session / ApiKey 走 jackson3 `SaJsonTemplateForJackson3`（`DefaultTyping.NON_FINAL` + `@class`）。
- 默认 `timeout=-1`、JWT `eff=-1`，金样 TTL 稳定。`active_timeout*` / `sign_nonce` 的 ttl 可能是正数，notes 里标明不作为逐字节断言。
- 无 Spring：用 `SaTokenContextMockUtil` 注入 Mock 上下文。
- 无场景被跳过；若以后某 API 在无 Spring 下跑不起来，在本文件写明原因，不要假装生成。

## Java 实际写出形状（供 A/B/C 对齐）

| 项 | Java 1.46.0 + jackson3 实际 |
|---|---|
| token key | `satoken:{loginType}:token:{t}` |
| token 值 | `String.valueOf(loginId)`：Long → 纯 `10001`（不是 JSON number 包装） |
| Account-Session `loginId` | Long → `["java.lang.Long",10001]`；String → `"user-a"` |
| Session JSON | `@class=cn.dev33.satoken.session.SaSession`，字段大致字母序；`dataMap` 带 `@class=java.util.concurrent.ConcurrentHashMap`；`terminalList` 为 `["java.util.Vector",[SaTerminalInfo…]]` |
| 空 dataMap | `{"@class":"java.util.concurrent.ConcurrentHashMap"}`（无额外键） |
| Integer 槽（如 count=1） | 裸 `1` |
| Long 槽（loginId / 索引 expireMs） | `["java.lang.Long",n]` |
| last-active | `satoken:login:last-active:{t}` = `<ms>`；dynamic 时 `<ms>,<secs>` |
| temp-token 根 String | JSON 字符串 `"hello"`（带引号） |
| temp-token 根 Long | 裸 `10001`（根类型是 final Long，无包装） |
| temp-token 根 Map | `{"name":"alice","id":10001}` **无 @class**；`parseToken`/`getObject(Object.class)` 会失败 |
| temp 索引 | `satoken:raw-session:temp-token:{value}`，dataMap `__HD_TEMP_TOKEN_MAP` token→`["java.lang.Long",expireMs]`，-1=永不过期 |
| ApiKey | `@class=cn.dev33.satoken.apikey.model.ApiKeyModel`，`loginId` 为 Long 包装，`scopes` 为 `["java.util.ArrayList",[…]]` |
| Same-Token | `satoken:var:same-token` / `past-same-token`，值是 64 位随机串 |
| Sign nonce | `satoken:sign:nonce:{n}`，value=nonce，ttl=window*2+2（默认 1802） |
| JWT | hutool HS256，header 含 `"typ":"JWT"`；Simple 无 deviceType/eff；Mixin/Stateless 有 `deviceType`+`eff` |
| kickout / replaced | token 值 `-5` / `-4`，KEEPTTL（此处 timeout=-1） |
| logout(loginId) | 删除 token key 与 Account-Session |
| null 字段 | jackson3 默认写出 `deviceId:null`、`extraData:null`、`token:null` 等 |
