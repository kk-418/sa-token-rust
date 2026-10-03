import cn.dev33.satoken.dao.auto.SaTokenDaoByObjectFollowString;
import cn.dev33.satoken.util.SaFoxUtil;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * String-store memory DAO: object/session follow string (StringRedisTemplate model).
 */
public class MemoryDao implements SaTokenDaoByObjectFollowString {

	static final class Cell {
		String value;
		long expireAt;

		Cell(String value, long expireAt) {
			this.value = value;
			this.expireAt = expireAt;
		}
	}

	private final ConcurrentHashMap<String, Cell> store = new ConcurrentHashMap<>();

	public void clear() {
		store.clear();
	}

	public List<Map<String, Object>> dump() {
		List<Map<String, Object>> rows = new ArrayList<>();
		for (String key : store.keySet()) {
			long ttl = getTimeout(key);
			if (ttl == NOT_VALUE_EXPIRE) {
				continue;
			}
			Cell cell = store.get(key);
			if (cell == null) {
				continue;
			}
			Map<String, Object> row = new LinkedHashMap<>();
			row.put("key", key);
			row.put("value", cell.value);
			row.put("ttl", ttl);
			rows.add(row);
		}
		rows.sort(Comparator.comparing(r -> String.valueOf(r.get("key"))));
		return rows;
	}

	@SuppressWarnings("unchecked")
	public void load(List<Map<String, Object>> rows) {
		clear();
		if (rows == null) {
			return;
		}
		for (Map<String, Object> row : rows) {
			String key = String.valueOf(row.get("key"));
			Object raw = row.get("value");
			String value = raw == null ? null : String.valueOf(raw);
			long ttl = ((Number) row.get("ttl")).longValue();
			set(key, value, ttl);
		}
	}

	private void purge(String key) {
		Cell cell = store.get(key);
		if (cell == null) {
			return;
		}
		if (cell.expireAt != NEVER_EXPIRE && cell.expireAt < System.currentTimeMillis()) {
			store.remove(key);
		}
	}

	@Override
	public String get(String key) {
		purge(key);
		Cell cell = store.get(key);
		return cell == null ? null : cell.value;
	}

	@Override
	public void set(String key, String value, long timeout) {
		if (timeout == 0 || timeout <= NOT_VALUE_EXPIRE) {
			return;
		}
		long expireAt = (timeout == NEVER_EXPIRE) ? NEVER_EXPIRE : (System.currentTimeMillis() + timeout * 1000);
		store.put(key, new Cell(value, expireAt));
	}

	@Override
	public void update(String key, String value) {
		if (getTimeout(key) == NOT_VALUE_EXPIRE) {
			return;
		}
		Cell cell = store.get(key);
		if (cell != null) {
			cell.value = value;
		}
	}

	@Override
	public void delete(String key) {
		store.remove(key);
	}

	@Override
	public long getTimeout(String key) {
		purge(key);
		Cell cell = store.get(key);
		if (cell == null) {
			return NOT_VALUE_EXPIRE;
		}
		if (cell.expireAt == NEVER_EXPIRE) {
			return NEVER_EXPIRE;
		}
		long timeout = (cell.expireAt - System.currentTimeMillis()) / 1000;
		if (timeout < 0) {
			store.remove(key);
			return NOT_VALUE_EXPIRE;
		}
		return timeout;
	}

	@Override
	public void updateTimeout(String key, long timeout) {
		if (timeout == 0 || timeout <= NOT_VALUE_EXPIRE) {
			delete(key);
			return;
		}
		Cell cell = store.get(key);
		if (cell == null) {
			return;
		}
		cell.expireAt = (timeout == NEVER_EXPIRE) ? NEVER_EXPIRE : (System.currentTimeMillis() + timeout * 1000);
	}

	@Override
	public List<String> searchData(String prefix, String keyword, int start, int size, boolean sortType) {
		List<String> keys = new ArrayList<>();
		for (String key : store.keySet()) {
			purge(key);
			if (store.containsKey(key)) {
				keys.add(key);
			}
		}
		return SaFoxUtil.searchList(keys, prefix, keyword, start, size, sortType);
	}

	@Override
	public void init() {
		// no refresh thread: TTL is computed on read/dump
	}

	@Override
	public void destroy() {
	}
}
