import cn.dev33.satoken.SaManager;
import cn.dev33.satoken.apikey.model.ApiKeyModel;
import cn.dev33.satoken.apikey.template.SaApiKeyUtil;
import cn.dev33.satoken.context.SaHolder;
import cn.dev33.satoken.dao.SaTokenDao;
import cn.dev33.satoken.exception.NotLoginException;
import cn.dev33.satoken.jwt.SaJwtUtil;
import cn.dev33.satoken.jwt.exception.SaJwtException;
import cn.dev33.satoken.same.SaSameUtil;
import cn.dev33.satoken.session.SaSession;
import cn.dev33.satoken.session.SaSessionCustomUtil;
import cn.dev33.satoken.session.raw.SaRawSessionUtil;
import cn.dev33.satoken.sign.template.SaSignUtil;
import cn.dev33.satoken.stp.StpLogic;
import cn.dev33.satoken.stp.StpUtil;
import cn.dev33.satoken.temp.SaTempUtil;
import cn.dev33.satoken.util.SaTokenConsts;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Load a {key,value,ttl} dump into MemoryDao and assert Java APIs.
 */
public class Verify {

	static int failures = 0;

	public static void main(String[] args) throws Exception {
		if (args.length < 1) {
			System.err.println("usage: Verify <dump.json>");
			System.exit(2);
		}
		Path path = Path.of(args[0]);
		Map<String, Object> root = InteropBoot.readJson(path);
		String scenario = InteropBoot.str(root, "scenario");
		if (scenario == null) {
			fail("missing scenario in " + path);
			System.exit(1);
		}

		InteropBoot.installOnce();
		MemoryDao dao = InteropBoot.loadFixture(root);

		@SuppressWarnings("unchecked")
		Map<String, Object> tokens = (Map<String, Object>) root.get("tokens");
		@SuppressWarnings("unchecked")
		Map<String, Object> inputs = (Map<String, Object>) root.get("inputs");
		@SuppressWarnings("unchecked")
		Map<String, Object> config = (Map<String, Object>) root.get("config");
		String loginType = config == null ? StpUtil.TYPE : String.valueOf(config.getOrDefault("loginType", StpUtil.TYPE));
		StpLogic logic = StpUtil.TYPE.equals(loginType) ? StpUtil.getStpLogic() : SaManager.getStpLogic(loginType, true);

		switch (scenario) {
			case "login_long" -> verifyLogin(logic, tokens, "10001", true);
			case "login_string" -> verifyLogin(logic, tokens, "user-a", false);
			case "login_admin_type" -> verifyLogin(logic, tokens, "20001", true);
			case "multi_device" -> verifyMultiDevice(logic, tokens);
			case "kickout" -> verifyKickout(dao, logic, tokens);
			case "replaced" -> verifyReplaced(dao, logic, tokens);
			case "logout" -> verifyLogout(logic, tokens);
			case "disable" -> verifyDisable(logic, tokens);
			case "safe" -> verifySafe(logic, tokens);
			case "active_timeout", "active_timeout_dynamic" -> verifyActiveTimeout(dao, logic, tokens);
			case "token_session" -> verifyTokenSession(logic, tokens);
			case "custom_session" -> verifyCustomSession();
			case "raw_session" -> verifyRawSession();
			case "temp_token_str" -> verifyTempStr(tokens);
			case "temp_token_long" -> verifyTempLong(tokens);
			case "temp_token_map" -> verifyTempMap(tokens);
			case "apikey" -> verifyApiKey(tokens);
			case "same_token" -> verifySameToken(tokens);
			case "application_var" -> verifyApplication();
			case "sign_nonce" -> verifySignNonce(dao, tokens);
			case "jwt_simple", "jwt_mixin", "jwt_stateless" -> verifyJwt(logic, tokens, "10001");
			case "jwt_expired" -> verifyJwtExpired(logic, tokens);
			default -> fail("unknown scenario: " + scenario);
		}

		if (failures > 0) {
			System.err.println("VERIFY FAIL " + path.getFileName() + " (" + failures + " assertion(s))");
			System.exit(1);
		}
		System.out.println("VERIFY OK " + path.getFileName());
	}

	static void verifyLogin(StpLogic logic, Map<String, Object> tokens, String expectId, boolean expectNumeric) {
		String token = InteropBoot.str(tokens, "token");
		check(token != null && !token.isEmpty(), "token present");
		Object loginId = logic.getLoginIdByToken(token);
		check(loginId != null, "getLoginIdByToken != null");
		check(expectId.equals(String.valueOf(loginId)), "loginId=" + expectId + " got " + loginId);
		check(logic.isLogin(parseLoginId(expectId, expectNumeric)), "isLogin(loginId)");
		InteropBoot.injectToken(token);
		if (logic == StpUtil.getStpLogic()) {
			check(StpUtil.isLogin(), "StpUtil.isLogin()");
		} else {
			check(logic.isLogin(), "logic.isLogin()");
		}
		SaSession session = logic.getSessionByLoginId(parseLoginId(expectId, expectNumeric), false);
		check(session != null, "Account-Session exists");
		check(!session.getTerminalList().isEmpty(), "terminalList not empty");
		String raw = SaManager.getSaTokenDao().get(logic.splicingKeyTokenValue(token));
		if (raw != null) {
			check(expectId.equals(raw), "token key value is loginId string, got " + raw);
		}
		String sessionJson = SaManager.getSaTokenDao().get(session.getId());
		check(sessionJson != null && sessionJson.contains("\"@class\""), "session JSON has @class");
		check(sessionJson.contains("cn.dev33.satoken.session.SaSession"), "session @class is SaSession");
	}

	static void verifyMultiDevice(StpLogic logic, Map<String, Object> tokens) {
		verifyLogin(logic, tokens, "10001", true);
		String t2 = InteropBoot.str(tokens, "token2");
		check(t2 != null, "token2 present");
		check("10001".equals(String.valueOf(logic.getLoginIdByToken(t2))), "token2 loginId");
		List<String> list = logic.getTokenValueListByLoginId(10001L);
		check(list.size() == 2, "two terminals, got " + list.size());
	}

	static void verifyKickout(MemoryDao dao, StpLogic logic, Map<String, Object> tokens) {
		String token = InteropBoot.str(tokens, "token");
		check(logic.getLoginIdByToken(token) == null, "kicked token getLoginIdByToken is null");
		String raw = dao.get(logic.splicingKeyTokenValue(token));
		check(NotLoginException.KICK_OUT.equals(raw), "token value is -5, got " + raw);
		check(!logic.isLogin(10001L), "isLogin(10001) false");
	}

	static void verifyReplaced(MemoryDao dao, StpLogic logic, Map<String, Object> tokens) {
		String neu = InteropBoot.str(tokens, "token");
		String old = InteropBoot.str(tokens, "replacedToken");
		check("10001".equals(String.valueOf(logic.getLoginIdByToken(neu))), "new token still login");
		check(logic.getLoginIdByToken(old) == null, "replaced token getLoginIdByToken is null");
		String raw = dao.get(logic.splicingKeyTokenValue(old));
		check(NotLoginException.BE_REPLACED.equals(raw), "old token value is -4, got " + raw);
		check(logic.isLogin(10001L), "account still online");
	}

	static void verifyLogout(StpLogic logic, Map<String, Object> tokens) {
		String token = InteropBoot.str(tokens, "token");
		check(logic.getLoginIdByToken(token) == null, "logged-out token is null");
		check(SaManager.getSaTokenDao().get(logic.splicingKeyTokenValue(token)) == null, "token key deleted");
		check(!logic.isLogin(10001L), "isLogin false");
	}

	static void verifyDisable(StpLogic logic, Map<String, Object> tokens) {
		verifyLogin(logic, tokens, "10001", true);
		check(StpUtil.isDisable(10001L), "isDisable");
	}

	static void verifySafe(StpLogic logic, Map<String, Object> tokens) {
		verifyLogin(logic, tokens, "10001", true);
		String token = InteropBoot.str(tokens, "token");
		check(StpUtil.isSafe(token, SaTokenConsts.DEFAULT_SAFE_AUTH_SERVICE), "isSafe(token, important)");
		InteropBoot.injectToken(token);
		check(StpUtil.isSafe(), "isSafe()");
	}

	static void verifyActiveTimeout(MemoryDao dao, StpLogic logic, Map<String, Object> tokens) {
		String token = InteropBoot.str(tokens, "token");
		check(token != null && !token.isEmpty(), "token present");
		String lastActive = dao.get(logic.splicingKeyLastActiveTime(token));
		check(lastActive != null && !lastActive.isEmpty(), "last-active present: " + lastActive);
		check(lastActive.matches("\\d+") || lastActive.matches("\\d+,\\d+"),
				"last-active format <ms> or <ms>,<secs>: " + lastActive);
		String tokenVal = dao.get(logic.splicingKeyTokenValue(token));
		check("10001".equals(tokenVal), "token key is loginId, got " + tokenVal);
		long ms;
		try {
			int comma = lastActive.indexOf(',');
			ms = Long.parseLong(comma < 0 ? lastActive : lastActive.substring(0, comma));
		} catch (NumberFormatException e) {
			ms = 0L;
		}
		// Gold last-active ages out after activeTimeout; identity checks only when still fresh.
		if (ms > 0 && System.currentTimeMillis() - ms < 1_800_000L) {
			Object loginId = logic.getLoginIdByToken(token);
			check("10001".equals(String.valueOf(loginId)), "loginId=10001 got " + loginId);
			check(!logic.isFreeze(token), "not frozen");
		}
	}

	static void verifyTokenSession(StpLogic logic, Map<String, Object> tokens) {
		verifyLogin(logic, tokens, "10001", true);
		String token = InteropBoot.str(tokens, "token");
		InteropBoot.injectToken(token);
		SaSession ts = StpUtil.getTokenSession();
		check(ts != null, "token-session exists");
		check("zhang".equals(String.valueOf(ts.get("name"))), "token-session name=zhang");
		String json = SaManager.getSaTokenDao().get(ts.getId());
		check(json != null && json.contains("\"@class\""), "token-session JSON has @class");
	}

	static void verifyCustomSession() {
		SaSession session = SaSessionCustomUtil.getSessionById("role-1001", false);
		check(session != null, "custom session exists");
		check(Integer.valueOf(1).equals(session.get("count")) || Long.valueOf(1).equals(session.get("count"))
						|| "1".equals(String.valueOf(session.get("count"))),
				"count=1 got " + session.get("count"));
		String json = SaManager.getSaTokenDao().get(session.getId());
		check(json != null && json.contains("Custom-Session"), "type Custom-Session");
		check(json.contains("\"@class\""), "custom session @class");
	}

	static void verifyRawSession() {
		SaSession session = SaRawSessionUtil.getSessionById("user", 10001L, false);
		check(session != null, "raw session exists");
		check("raw".equals(String.valueOf(session.get("flag"))), "flag=raw");
		String json = SaManager.getSaTokenDao().get(session.getId());
		check(json != null && json.contains("\"@class\""), "raw session @class");
	}

	static void verifyTempStr(Map<String, Object> tokens) {
		String temp = InteropBoot.str(tokens, "tempToken");
		Object v = SaTempUtil.parseToken(temp);
		check("hello".equals(String.valueOf(v)), "parseToken str=hello got " + v);
	}

	static void verifyTempLong(Map<String, Object> tokens) {
		String temp = InteropBoot.str(tokens, "tempToken");
		Object v = SaTempUtil.parseToken(temp);
		check(v != null, "parseToken long not null");
		check(10001L == Long.parseLong(String.valueOf(v)), "parseToken long=10001 got " + v);
	}

	static void verifyTempMap(Map<String, Object> tokens) {
		String temp = InteropBoot.str(tokens, "tempToken");
		String key = SaManager.getConfig().getTokenName() + ":temp-token:" + temp;
		String raw = SaManager.getSaTokenDao().get(key);
		check(raw != null && raw.startsWith("{") && !raw.contains("\"@class\""),
				"root Map JSON has no @class: " + raw);
		Map<String, Object> m = SaManager.getSaJsonTemplate().jsonToMap(raw);
		check(m != null, "jsonToMap");
		check("alice".equals(String.valueOf(m.get("name"))), "map.name=alice");
		check(10001L == Long.parseLong(String.valueOf(m.get("id"))), "map.id=10001");
		// jackson3 objectToJson(Map) uses untyped mapper; parseToken → Object.class needs @class
		boolean threw = false;
		try {
			SaTempUtil.parseToken(temp);
		} catch (Exception e) {
			threw = true;
		}
		check(threw, "parseToken(Map) fails without @class (jackson3 Object.class)");
	}

	static void verifyApiKey(Map<String, Object> tokens) {
		String apiKey = InteropBoot.str(tokens, "apiKey");
		ApiKeyModel ak = SaApiKeyUtil.checkApiKey(apiKey);
		check(ak != null, "checkApiKey");
		check("10001".equals(String.valueOf(ak.getLoginId())), "apiKey loginId");
		check(SaApiKeyUtil.hasApiKeyScope(apiKey, "user.read"), "scope user.read");
	}

	static void verifySameToken(Map<String, Object> tokens) {
		String cur = InteropBoot.str(tokens, "sameToken");
		String past = InteropBoot.str(tokens, "pastSameToken");
		check(SaSameUtil.isValid(cur), "current same-token valid");
		check(SaSameUtil.isValid(past), "past same-token valid");
	}

	static void verifyApplication() {
		check("bar".equals(String.valueOf(SaHolder.getApplication().get("foo"))), "var foo=bar");
		Object num = SaHolder.getApplication().get("num");
		check(num != null && 10001L == Long.parseLong(String.valueOf(num)), "var num=10001 got " + num);
		String mapKey = SaHolder.getApplication().splicingDataKey("map");
		String rawMap = SaManager.getSaTokenDao().get(mapKey);
		check("{\"k\":\"v\"}".equals(rawMap), "var map raw JSON has no @class: " + rawMap);
	}

	static void verifySignNonce(MemoryDao dao, Map<String, Object> tokens) {
		String nonce = InteropBoot.str(tokens, "nonce");
		String key = SaManager.getConfig().getTokenName() + ":sign:nonce:" + nonce;
		check(nonce.equals(dao.get(key)), "nonce value stored");
		check(!SaSignUtil.isValidNonce(nonce), "used nonce is no longer valid");
		check(SaSignUtil.isValidNonce("fresh-nonce-xyz"), "fresh nonce valid");
	}

	static void verifyJwt(StpLogic logic, Map<String, Object> tokens, String expectId) {
		String token = InteropBoot.str(tokens, "token");
		check(token != null && token.contains("."), "jwt-shaped token");
		Object loginId = logic.getLoginIdByToken(token);
		check(loginId != null, "JWT getLoginIdByToken");
		check(expectId.equals(String.valueOf(loginId)), "JWT loginId=" + expectId + " got " + loginId);
		InteropBoot.injectToken(token);
		check(logic.isLogin(), "JWT isLogin()");
		Object extra = null;
		try {
			extra = logic.getExtra(token, "age");
		} catch (Exception ignored) {
		}
		if (extra != null) {
			check(18 == Integer.parseInt(String.valueOf(extra)), "jwt extra age=18");
		}
	}

	static void verifyJwtExpired(StpLogic logic, Map<String, Object> tokens) {
		String token = InteropBoot.str(tokens, "token");
		if (token == null) {
			token = InteropBoot.str(tokens, "jwt");
		}
		check(token != null, "expired jwt present");
		Object loginId = logic.getLoginIdByToken(token);
		check(loginId == null, "expired jwt getLoginIdByToken is null, got " + loginId);
		boolean expired = false;
		try {
			SaJwtUtil.getLoginId(token, StpUtil.TYPE, InteropBoot.JWT_SECRET);
		} catch (SaJwtException e) {
			expired = e.getCode() == 30204 || (e.getMessage() != null && e.getMessage().contains("过期"));
		}
		check(expired, "SaJwtUtil.getLoginId throws expired");
	}

	static Object parseLoginId(String raw, boolean numeric) {
		if (numeric) {
			return Long.parseLong(raw);
		}
		return raw;
	}

	static void check(boolean cond, String msg) {
		if (!cond) {
			failures++;
			System.err.println("  FAIL: " + msg);
		}
	}

	static void fail(String msg) {
		check(false, msg);
	}
}
