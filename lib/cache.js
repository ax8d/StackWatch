/**
 * Cache layer for CVE lookups, backed by chrome.storage.local.
 * Keyed by `${source}:${id}:${version}` so different versions of the
 * same library don't collide. Entries expire after CACHE_TTL_MS so
 * newly published CVEs eventually surface without us re-querying constantly.
 */

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const CACHE_PREFIX = "sw_cache_";

function cacheKey(source, id, version) {
  return `${CACHE_PREFIX}${source}:${id}:${version || "any"}`;
}

export async function getCached(source, id, version) {
  const key = cacheKey(source, id, version);
  const result = await chrome.storage.local.get(key);
  const entry = result[key];
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) return null;
  return entry.data;
}

export async function setCached(source, id, version, data) {
  const key = cacheKey(source, id, version);
  await chrome.storage.local.set({
    [key]: { timestamp: Date.now(), data }
  });
}

/** Periodic cleanup so storage.local doesn't grow unbounded over months of browsing. */
export async function pruneExpired() {
  const all = await chrome.storage.local.get(null);
  const toRemove = [];
  for (const [key, entry] of Object.entries(all)) {
    if (!key.startsWith(CACHE_PREFIX)) continue;
    if (!entry || Date.now() - entry.timestamp > CACHE_TTL_MS) {
      toRemove.push(key);
    }
  }
  if (toRemove.length) await chrome.storage.local.remove(toRemove);
}
