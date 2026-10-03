import cn.dev33.satoken.SaManager;
import cn.dev33.satoken.apikey.SaApiKeyManager;
import cn.dev33.satoken.apikey.config.SaApiKeyConfig;
import cn.dev33.satoken.config.SaTokenConfig;
import cn.dev33.satoken.context.mock.SaRequestForMock;
import cn.dev33.satoken.context.mock.SaTokenContextMockUtil;
import cn.dev33.satoken.dao.SaTokenDao;
import cn.dev33.satoken.json.SaJsonTemplateForJackson3;
import cn.dev33.satoken.jwt.StpLogicJwtForMixin;
import cn.dev33.satoken.jwt.StpLogicJwtForSimple;
import cn.dev33.satoken.jwt.StpLogicJwtForStateless;
import cn.dev33.satoken.sign.SaSignManager;
import cn.dev33.satoken.sign.config.SaSignConfig;
import cn.dev33.satoken.stp.StpLogic;
import cn.dev33.satoken.stp.StpUtil;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared bootstrap for FixtureGen / Verify: jackson3 JSON, mock context, memory DAO.
 */
public final class InteropBoot {

	public static final String JWT_SECRET = "java-interop-secret-key-32bytes!!";
	public static final String SIGN_SECRET = "java-interop-sign-secret";
	public static final String TOKEN_NAME = "satoken";

	public static final JsonMapper JSON = JsonMapper.builder()
			.enable(SerializationFeature.INDENT_OUTPUT)
			.build();

	private static boolean installed = false;

	private InteropBoot() {
	}

	public static void installOnce() {
		if (installed) {
			return;
		}
		SaManager.setSaJsonTemplate(new SaJsonTemplateForJackson3());
		SaApiKeyManager.setConfig(new SaApiKeyConfig().setTimeout(SaTokenDao.NEVER_EXPIRE));
		SaSignManager.setConfig(new SaSignConfig(SIGN_SECRET));
		installed = true;
	}

	public static SaTokenConfig baseConfig() {
		return new SaTokenConfig()
				.setTokenName(TOKEN_NAME)
				.setTimeout(SaTokenDao.NEVER_EXPIRE)
				.setActiveTimeout(SaTokenDao.NEVER_EXPIRE)
				.setDynamicActiveTimeout(false)
				.setIsConcurrent(true)
				.setIsShare(false)
				.setIsReadCookie(false)
				.setIsWriteHeader(false)
				.setIsPrint(false)
				.setIsLog(false)
				.setJwtSecretKey(JWT_SECRET)
				.setSameTokenTimeout(SaTokenDao.NEVER_EXPIRE)
				.setDataRefreshPeriod(-1);
	}

	public static MemoryDao reset(SaTokenConfig config) {
		installOnce();
		SaManager.setConfig(config);
		StpUtil.setStpLogic(new StpLogic(StpUtil.TYPE));
		SaManager.removeStpLogic("admin");
		MemoryDao dao = new MemoryDao();
		SaManager.setSaTokenDao(dao);
		SaTokenContextMockUtil.setMockContext();
		return dao;
	}

	public static MemoryDao reset() {
		return reset(baseConfig());
	}

	public static void applyJwtMode(String mode) {
		if (mode == null || mode.isEmpty() || "none".equals(mode)) {
			return;
		}
		switch (mode) {
			case "simple" -> StpUtil.setStpLogic(new StpLogicJwtForSimple());
			case "mixin" -> StpUtil.setStpLogic(new StpLogicJwtForMixin());
			case "stateless" -> StpUtil.setStpLogic(new StpLogicJwtForStateless());
			default -> throw new IllegalArgumentException("unknown jwtMode: " + mode);
		}
	}

	public static void injectToken(String token) {
		SaTokenContextMockUtil.setMockContext();
		if (token == null) {
			return;
		}
		StpUtil.setTokenValueToStorage(token);
		SaRequestForMock req = (SaRequestForMock) cn.dev33.satoken.context.SaHolder.getRequest();
		req.headerMap.put(SaManager.getConfig().getTokenName(), token);
	}

	public static String login(Object loginId) {
		SaTokenContextMockUtil.setMockContext();
		StpUtil.login(loginId);
		return StpUtil.getTokenValue();
	}

	public static String login(Object loginId, String device) {
		SaTokenContextMockUtil.setMockContext();
		StpUtil.login(loginId, device);
		return StpUtil.getTokenValue();
	}

	public static String login(StpLogic logic, Object loginId) {
		SaTokenContextMockUtil.setMockContext();
		logic.login(loginId);
		return logic.getTokenValue();
	}

	public static Map<String, Object> configMap(SaTokenConfig cfg, String jwtMode, String loginType) {
		Map<String, Object> m = new LinkedHashMap<>();
		m.put("tokenName", cfg.getTokenName());
		m.put("timeout", cfg.getTimeout());
		m.put("activeTimeout", cfg.getActiveTimeout());
		m.put("dynamicActiveTimeout", cfg.getDynamicActiveTimeout());
		m.put("isConcurrent", cfg.getIsConcurrent());
		m.put("isShare", cfg.getIsShare());
		m.put("jwtSecretKey", cfg.getJwtSecretKey());
		m.put("sameTokenTimeout", cfg.getSameTokenTimeout());
		m.put("jwtMode", jwtMode == null ? "none" : jwtMode);
		m.put("loginType", loginType == null ? StpUtil.TYPE : loginType);
		return m;
	}

	public static Map<String, Object> fixture(
			String scenario,
			String notes,
			Map<String, Object> config,
			Map<String, Object> inputs,
			Map<String, Object> tokens,
			MemoryDao dao
	) {
		Map<String, Object> root = new LinkedHashMap<>();
		root.put("scenario", scenario);
		root.put("notes", notes);
		root.put("config", config);
		root.put("inputs", inputs);
		root.put("tokens", tokens);
		root.put("kv", dao.dump());
		return root;
	}

	public static void writeJson(Path path, Map<String, Object> root) throws IOException {
		Files.createDirectories(path.getParent());
		Files.writeString(path, JSON.writeValueAsString(root) + "\n");
	}

	@SuppressWarnings("unchecked")
	public static Map<String, Object> readJson(Path path) throws IOException {
		return JSON.readValue(Files.readString(path), Map.class);
	}

	@SuppressWarnings("unchecked")
	public static MemoryDao loadFixture(Map<String, Object> root) {
		Map<String, Object> cfgMap = (Map<String, Object>) root.get("config");
		SaTokenConfig cfg = baseConfig();
		if (cfgMap != null) {
			if (cfgMap.get("tokenName") != null) {
				cfg.setTokenName(String.valueOf(cfgMap.get("tokenName")));
			}
			if (cfgMap.get("timeout") != null) {
				cfg.setTimeout(((Number) cfgMap.get("timeout")).longValue());
			}
			if (cfgMap.get("activeTimeout") != null) {
				cfg.setActiveTimeout(((Number) cfgMap.get("activeTimeout")).longValue());
			}
			if (cfgMap.get("dynamicActiveTimeout") != null) {
				cfg.setDynamicActiveTimeout(Boolean.parseBoolean(String.valueOf(cfgMap.get("dynamicActiveTimeout"))));
			}
			if (cfgMap.get("isConcurrent") != null) {
				cfg.setIsConcurrent(Boolean.parseBoolean(String.valueOf(cfgMap.get("isConcurrent"))));
			}
			if (cfgMap.get("isShare") != null) {
				cfg.setIsShare(Boolean.parseBoolean(String.valueOf(cfgMap.get("isShare"))));
			}
			if (cfgMap.get("jwtSecretKey") != null) {
				cfg.setJwtSecretKey(String.valueOf(cfgMap.get("jwtSecretKey")));
			}
			if (cfgMap.get("sameTokenTimeout") != null) {
				cfg.setSameTokenTimeout(((Number) cfgMap.get("sameTokenTimeout")).longValue());
			}
		}
		MemoryDao dao = reset(cfg);
		if (cfgMap != null) {
			applyJwtMode(String.valueOf(cfgMap.getOrDefault("jwtMode", "none")));
		}
		dao.load((List<Map<String, Object>>) root.get("kv"));
		return dao;
	}

	public static String str(Map<String, Object> m, String key) {
		if (m == null || m.get(key) == null) {
			return null;
		}
		return String.valueOf(m.get(key));
	}
}
