import cn.dev33.satoken.SaManager;
import cn.dev33.satoken.apikey.model.ApiKeyModel;
import cn.dev33.satoken.apikey.template.SaApiKeyUtil;
import cn.dev33.satoken.config.SaTokenConfig;
import cn.dev33.satoken.context.SaHolder;
import cn.dev33.satoken.context.mock.SaTokenContextMockUtil;
import cn.dev33.satoken.dao.SaTokenDao;
import cn.dev33.satoken.jwt.SaJwtUtil;
import cn.dev33.satoken.same.SaSameUtil;
import cn.dev33.satoken.session.SaSession;
import cn.dev33.satoken.session.SaSessionCustomUtil;
import cn.dev33.satoken.session.raw.SaRawSessionUtil;
import cn.dev33.satoken.sign.template.SaSignUtil;
import cn.dev33.satoken.stp.StpLogic;
import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.stp.parameter.SaLoginParameter;
import cn.dev33.satoken.temp.SaTempUtil;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.signers.JWTSignerUtil;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Run real Java Sa-Token APIs and dump {key,value,ttl} gold samples.
 */
public class FixtureGen {

	public static void main(String[] args) throws Exception {
		if (args.length < 1) {
			System.err.println("usage: FixtureGen <out-dir>");
			System.exit(2);
		}
		Path outDir = Path.of(args[0]);
		InteropBoot.installOnce();

		gen(outDir, "login_long", FixtureGen::loginLong);
		gen(outDir, "login_string", FixtureGen::loginString);
		gen(outDir, "login_admin_type", FixtureGen::loginAdminType);
		gen(outDir, "multi_device", FixtureGen::multiDevice);
		gen(outDir, "kickout", FixtureGen::kickout);
		gen(outDir, "replaced", FixtureGen::replaced);
		gen(outDir, "logout", FixtureGen::logout);
		gen(outDir, "disable", FixtureGen::disable);
		gen(outDir, "safe", FixtureGen::safe);
		gen(outDir, "active_timeout", FixtureGen::activeTimeout);
		gen(outDir, "active_timeout_dynamic", FixtureGen::activeTimeoutDynamic);
		gen(outDir, "token_session", FixtureGen::tokenSession);
		gen(outDir, "custom_session", FixtureGen::customSession);
		gen(outDir, "raw_session", FixtureGen::rawSession);
		gen(outDir, "temp_token_str", FixtureGen::tempTokenStr);
		gen(outDir, "temp_token_long", FixtureGen::tempTokenLong);
		gen(outDir, "temp_token_map", FixtureGen::tempTokenMap);
		gen(outDir, "apikey", FixtureGen::apikey);
		gen(outDir, "same_token", FixtureGen::sameToken);
		gen(outDir, "application_var", FixtureGen::applicationVar);
		gen(outDir, "sign_nonce", FixtureGen::signNonce);
		gen(outDir, "jwt_simple", FixtureGen::jwtSimple);
		gen(outDir, "jwt_mixin", FixtureGen::jwtMixin);
		gen(outDir, "jwt_stateless", FixtureGen::jwtStateless);
		gen(outDir, "jwt_expired", FixtureGen::jwtExpired);

		System.out.println("FixtureGen wrote " + outDir.toAbsolutePath());
	}

	interface Scene {
		Map<String, Object> run();
	}

	static void gen(Path outDir, String name, Scene scene) throws Exception {
		Map<String, Object> root = scene.run();
		Path path = outDir.resolve(name + ".json");
		InteropBoot.writeJson(path, root);
		System.out.println("  " + name + "  kv=" + ((java.util.List<?>) root.get("kv")).size());
	}

	static Map<String, Object> inputs(Object... kv) {
		return pairs(kv);
	}

	static Map<String, Object> tokens(Object... kv) {
		return pairs(kv);
	}

	static Map<String, Object> pairs(Object... kv) {
		Map<String, Object> m = new LinkedHashMap<>();
		for (int i = 0; i < kv.length; i += 2) {
			m.put(String.valueOf(kv[i]), kv[i + 1]);
		}
		return m;
	}

	static Map<String, Object> loginLong() {
		MemoryDao dao = InteropBoot.reset();
		String token = InteropBoot.login(10001L);
		return InteropBoot.fixture(
				"login_long",
				"StpUtil.login(10001L); token 值是 String.valueOf(loginId)=10001；Account-Session 为 jackson3 NON_FINAL 类型化 JSON。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("loginId", 10001L, "device", "DEF"),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> loginString() {
		MemoryDao dao = InteropBoot.reset();
		String token = InteropBoot.login("user-a");
		return InteropBoot.fixture(
				"login_string",
				"StpUtil.login(\"user-a\"); token 值是纯字符串 user-a。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("loginId", "user-a", "device", "DEF"),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> loginAdminType() {
		MemoryDao dao = InteropBoot.reset();
		StpLogic admin = SaManager.getStpLogic("admin", true);
		String token = InteropBoot.login(admin, 20001L);
		return InteropBoot.fixture(
				"login_admin_type",
				"SaManager.getStpLogic(\"admin\", true).login(20001L)；key 段为 satoken:admin:…。",
				InteropBoot.configMap(SaManager.getConfig(), "none", "admin"),
				inputs("loginId", 20001L, "loginType", "admin", "device", "DEF"),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> multiDevice() {
		MemoryDao dao = InteropBoot.reset();
		String t1 = InteropBoot.login(10001L, "PC");
		String t2 = InteropBoot.login(10001L, "APP");
		return InteropBoot.fixture(
				"multi_device",
				"同一 loginId 两设备 PC/APP；Account-Session.terminalList 两条。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("loginId", 10001L, "device1", "PC", "device2", "APP"),
				tokens("token", t1, "token2", t2),
				dao
		);
	}

	static Map<String, Object> kickout() {
		MemoryDao dao = InteropBoot.reset();
		String token = InteropBoot.login(10001L);
		StpUtil.kickout(10001L);
		return InteropBoot.fixture(
				"kickout",
				"kickout 后 token key 值变为 -5（KICK_OUT），Account-Session 终端清空后删除。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("loginId", 10001L),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> replaced() {
		SaTokenConfig cfg = InteropBoot.baseConfig().setIsConcurrent(false);
		MemoryDao dao = InteropBoot.reset(cfg);
		String oldToken = InteropBoot.login(10001L, "PC");
		String newToken = InteropBoot.login(10001L, "PC");
		return InteropBoot.fixture(
				"replaced",
				"isConcurrent=false 二次登录顶号；旧 token 值变为 -4（BE_REPLACED）。",
				InteropBoot.configMap(cfg, "none", StpUtil.TYPE),
				inputs("loginId", 10001L, "device", "PC"),
				tokens("token", newToken, "replacedToken", oldToken),
				dao
		);
	}

	static Map<String, Object> logout() {
		MemoryDao dao = InteropBoot.reset();
		String token = InteropBoot.login(10001L);
		StpUtil.logout(10001L);
		return InteropBoot.fixture(
				"logout",
				"logout(loginId) 删除 token 映射与 Account-Session（不再保留 -2 标记）。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("loginId", 10001L),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> disable() {
		MemoryDao dao = InteropBoot.reset();
		String token = InteropBoot.login(10001L);
		StpUtil.disable(10001L, SaTokenDao.NEVER_EXPIRE);
		return InteropBoot.fixture(
				"disable",
				"disable 默认 service=login，值是封禁等级 1；timeout=-1。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("loginId", 10001L, "service", "login", "level", 1),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> safe() {
		MemoryDao dao = InteropBoot.reset();
		String token = InteropBoot.login(10001L);
		StpUtil.openSafe(SaTokenDao.NEVER_EXPIRE);
		return InteropBoot.fixture(
				"safe",
				"openSafe(-1) 默认 service=important，值 SAFE_AUTH_SAVE_VALUE。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("loginId", 10001L, "service", "important"),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> activeTimeout() {
		SaTokenConfig cfg = InteropBoot.baseConfig().setActiveTimeout(1800);
		MemoryDao dao = InteropBoot.reset(cfg);
		String token = InteropBoot.login(10001L);
		return InteropBoot.fixture(
				"active_timeout",
				"timeout=-1 + activeTimeout=1800 写 last-active，值是毫秒时间戳；ttl 随 token timeout 为 -1。last-active 值会变，Rust 只断言格式。",
				InteropBoot.configMap(cfg, "none", StpUtil.TYPE),
				inputs("loginId", 10001L, "activeTimeout", 1800),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> activeTimeoutDynamic() {
		SaTokenConfig cfg = InteropBoot.baseConfig()
				.setActiveTimeout(1800)
				.setDynamicActiveTimeout(true);
		MemoryDao dao = InteropBoot.reset(cfg);
		SaTokenContextMockUtil.setMockContext();
		StpUtil.login(10001L, new SaLoginParameter().setActiveTimeout(600L));
		String token = StpUtil.getTokenValue();
		return InteropBoot.fixture(
				"active_timeout_dynamic",
				"dynamicActiveTimeout=true 时 last-active 值为 <ms>,<secs>。ttl 不作为金样断言。",
				InteropBoot.configMap(cfg, "none", StpUtil.TYPE),
				inputs("loginId", 10001L, "activeTimeout", 600),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> tokenSession() {
		MemoryDao dao = InteropBoot.reset();
		String token = InteropBoot.login(10001L);
		StpUtil.getTokenSession().set("name", "zhang");
		return InteropBoot.fixture(
				"token_session",
				"getTokenSession().set；key 为 satoken:login:token-session:{token}，JSON 含 @class。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("loginId", 10001L, "sessionKey", "name", "sessionValue", "zhang"),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> customSession() {
		MemoryDao dao = InteropBoot.reset();
		SaSession session = SaSessionCustomUtil.getSessionById("role-1001");
		session.set("count", 1);
		return InteropBoot.fixture(
				"custom_session",
				"SaSessionCustomUtil.getSessionById(\"role-1001\")；key satoken:custom:session:role-1001，type=Custom-Session。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("sessionId", "role-1001", "dataKey", "count", "dataValue", 1),
				tokens(),
				dao
		);
	}

	static Map<String, Object> rawSession() {
		MemoryDao dao = InteropBoot.reset();
		SaSession session = SaRawSessionUtil.getSessionById("user", 10001L);
		session.set("flag", "raw");
		return InteropBoot.fixture(
				"raw_session",
				"SaRawSessionUtil.getSessionById(\"user\", 10001L)；key satoken:raw-session:user:10001。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("type", "user", "valueId", 10001L, "dataKey", "flag", "dataValue", "raw"),
				tokens(),
				dao
		);
	}

	static Map<String, Object> tempTokenStr() {
		MemoryDao dao = InteropBoot.reset();
		String temp = SaTempUtil.createToken("hello", SaTokenDao.NEVER_EXPIRE, true);
		return InteropBoot.fixture(
				"temp_token_str",
				"SaTempUtil.createToken(\"hello\", -1, true)；值是 JSON 字符串 \"hello\"；索引 raw-session dataMap __HD_TEMP_TOKEN_MAP。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("value", "hello"),
				tokens("tempToken", temp),
				dao
		);
	}

	static Map<String, Object> tempTokenLong() {
		MemoryDao dao = InteropBoot.reset();
		String temp = SaTempUtil.createToken(10001L, SaTokenDao.NEVER_EXPIRE, true);
		return InteropBoot.fixture(
				"temp_token_long",
				"SaTempUtil.createToken(10001L, -1, true)；值格式以 Java 实际写出为准（Long 经 jackson3）。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("value", 10001L),
				tokens("tempToken", temp),
				dao
		);
	}

	static Map<String, Object> tempTokenMap() {
		MemoryDao dao = InteropBoot.reset();
		Map<String, Object> payload = new LinkedHashMap<>();
		payload.put("name", "alice");
		payload.put("id", 10001L);
		String temp = SaTempUtil.createToken(payload, SaTokenDao.NEVER_EXPIRE, true);
		return InteropBoot.fixture(
				"temp_token_map",
				"根对象 Map 走 jackson3 mapObjectMapper，写出 {\"name\":\"alice\",\"id\":10001}（无 @class）。parseToken(Object.class) 会因缺 @class 失败；请用 jsonToMap 读。Rust JavaRoot 应对齐「无 @class」。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("value", payload),
				tokens("tempToken", temp),
				dao
		);
	}

	static Map<String, Object> apikey() {
		MemoryDao dao = InteropBoot.reset();
		ApiKeyModel ak = SaApiKeyUtil.createApiKeyModel(10001L)
				.setTitle("interop")
				.addScope("user.read");
		SaApiKeyUtil.saveApiKey(ak);
		return InteropBoot.fixture(
				"apikey",
				"ApiKeyModel jackson3 类型化 JSON；索引 raw-session dataMap __HD_API_KEY_LIST；expiresTime=-1。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("loginId", 10001L, "title", "interop", "scope", "user.read"),
				tokens("apiKey", ak.getApiKey()),
				dao
		);
	}

	static Map<String, Object> sameToken() {
		MemoryDao dao = InteropBoot.reset();
		String t1 = SaSameUtil.getToken();
		String t2 = SaSameUtil.refreshToken();
		return InteropBoot.fixture(
				"same_token",
				"refreshToken 后当前 same-token + past-same-token；past TTL=Remaining（此处 timeout=-1 故均为 -1）。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs(),
				tokens("sameToken", t2, "pastSameToken", t1),
				dao
		);
	}

	static Map<String, Object> applicationVar() {
		MemoryDao dao = InteropBoot.reset();
		SaHolder.getApplication().set("foo", "bar");
		SaHolder.getApplication().set("num", 10001L);
		Map<String, Object> nested = new LinkedHashMap<>();
		nested.put("k", "v");
		SaHolder.getApplication().set("map", nested);
		return InteropBoot.fixture(
				"application_var",
				"SaHolder.getApplication().set → satoken:var:{k}，objectToJson。Map 走 mapObjectMapper。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("foo", "bar", "num", 10001L),
				tokens(),
				dao
		);
	}

	static Map<String, Object> signNonce() {
		MemoryDao dao = InteropBoot.reset();
		String nonce = "interop-nonce-001";
		SaSignUtil.checkNonce(nonce);
		return InteropBoot.fixture(
				"sign_nonce",
				"checkNonce 写入 satoken:sign:nonce:{n}，value=nonce，ttl=window*2+2（默认 1802s，会变，不作为金样断言）。",
				InteropBoot.configMap(SaManager.getConfig(), "none", StpUtil.TYPE),
				inputs("nonce", nonce),
				tokens("nonce", nonce),
				dao
		);
	}

	static Map<String, Object> jwtSimple() {
		MemoryDao dao = InteropBoot.reset();
		InteropBoot.applyJwtMode("simple");
		SaTokenContextMockUtil.setMockContext();
		StpUtil.login(10001L, new SaLoginParameter().setExtra("age", 18));
		String token = StpUtil.getTokenValue();
		return InteropBoot.fixture(
				"jwt_simple",
				"JWT Simple：claims loginType/loginId/rnStr + extra 平铺，无 deviceType/eff；仍写 token key + Account-Session。",
				InteropBoot.configMap(SaManager.getConfig(), "simple", StpUtil.TYPE),
				inputs("loginId", 10001L, "extraAge", 18),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> jwtMixin() {
		MemoryDao dao = InteropBoot.reset();
		InteropBoot.applyJwtMode("mixin");
		String token = InteropBoot.login(10001L);
		return InteropBoot.fixture(
				"jwt_mixin",
				"JWT Mixin：claims 含 deviceType/eff=-1；写 Account-Session+terminal，不写 token key。",
				InteropBoot.configMap(SaManager.getConfig(), "mixin", StpUtil.TYPE),
				inputs("loginId", 10001L, "device", "DEF"),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> jwtStateless() {
		MemoryDao dao = InteropBoot.reset();
		InteropBoot.applyJwtMode("stateless");
		String token = InteropBoot.login(10001L);
		return InteropBoot.fixture(
				"jwt_stateless",
				"JWT Stateless：只生成 JWT，不写 DAO。claims 含 deviceType/eff=-1。",
				InteropBoot.configMap(SaManager.getConfig(), "stateless", StpUtil.TYPE),
				inputs("loginId", 10001L, "device", "DEF"),
				tokens("token", token),
				dao
		);
	}

	static Map<String, Object> jwtExpired() {
		MemoryDao dao = InteropBoot.reset();
		InteropBoot.applyJwtMode("stateless");
		JWT jwt = JWT.create()
				.setPayload(SaJwtUtil.LOGIN_TYPE, StpUtil.TYPE)
				.setPayload(SaJwtUtil.LOGIN_ID, 10001L)
				.setPayload(SaJwtUtil.DEVICE_TYPE, "DEF")
				.setPayload(SaJwtUtil.EFF, 1L)
				.setPayload(SaJwtUtil.RN_STR, "expiredFixtureRnStr000000000001");
		String token = jwt.setSigner(JWTSignerUtil.hs256(InteropBoot.JWT_SECRET.getBytes())).sign();
		return InteropBoot.fixture(
				"jwt_expired",
				"手工签发 eff=1（1970ms）的 HS256 JWT；Verify 断言已过期。kv 为空。",
				InteropBoot.configMap(SaManager.getConfig(), "stateless", StpUtil.TYPE),
				inputs("loginId", 10001L, "eff", 1),
				tokens("token", token, "jwt", token),
				dao
		);
	}
}
