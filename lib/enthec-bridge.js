/**
 * Enthec/WebAppAnalyzer fingerprint bridge (Tier 2).
 *
 * Loads the open-source Wappalyzer-compatible fingerprint database from
 * github.com/enthec/webappanalyzer via jsDelivr CDN and converts each
 * entry's detection patterns into results usable by the existing pipeline.
 *
 * The database covers ~1500+ technologies across analytics, ads, CMS plugins,
 * marketing tools, A/B platforms, UI frameworks, and server-side software
 * that our hand-written SIGNATURES list does not include.
 *
 * Cache strategy: stored in chrome.storage.local keyed "enthec:db" with a
 * 48-hour TTL (longer than CVE cache since the fingerprint DB changes slowly).
 *
 * Pattern format (Wappalyzer spec):
 *   "pattern\\;version:\\1\\;confidence:75"
 *   The part before the first \; is the regex. version: and confidence: are
 *   optional metadata appended with literal \; separators (NOT newlines).
 */

const ENTHEC_TTL_MS = 48 * 60 * 60 * 1000; // 48 hours
const ENTHEC_CACHE_KEY = "sw_cache_enthec:db:v1";

// The letters a-z plus _ (for packages starting with numbers/symbols).
const LETTERS = "abcdefghijklmnopqrstuvwxyz_".split("");
const CDN_BASE =
  "https://cdn.jsdelivr.net/gh/enthec/webappanalyzer@main/src/technologies/";

// ─── Cache helpers (mirror of lib/cache.js but keyed separately) ────────────

async function loadCached() {
  try {
    const result = await chrome.storage.local.get(ENTHEC_CACHE_KEY);
    const entry = result[ENTHEC_CACHE_KEY];
    if (!entry) return null;
    if (Date.now() - entry.timestamp > ENTHEC_TTL_MS) return null;
    return entry.data;
  } catch {
    return null;
  }
}

async function saveCache(data) {
  try {
    await chrome.storage.local.set({
      [ENTHEC_CACHE_KEY]: { timestamp: Date.now(), data }
    });
  } catch {
    // Storage quota exceeded — silently skip caching
  }
}

// ─── Loader ─────────────────────────────────────────────────────────────────

/**
 * Fetches and caches the Enthec technology map.
 * Returns an object of { techName: techObject, ... } merged from all letter files.
 */
export async function loadEnthec() {
  const cached = await loadCached();
  if (cached) return cached;

  const merged = {};
  const results = await Promise.allSettled(
    LETTERS.map(async (letter) => {
      try {
        const res = await fetch(`${CDN_BASE}${letter}.json`);
        if (!res.ok) return;
        const data = await res.json();
        Object.assign(merged, data);
      } catch {
        // Individual letter files failing is not fatal
      }
    })
  );

  void results; // we already handle errors in the map above

  if (Object.keys(merged).length > 0) {
    await saveCache(merged);
  }
  return merged;
}

// ─── Pattern parser ──────────────────────────────────────────────────────────

/**
 * Parse a single Wappalyzer pattern string into { regex, versionTemplate, confidence }.
 * Patterns look like: "jQuery v?\\;version:\\1\\;confidence:50"
 * The \; separator is a literal backslash-semicolon in the JSON string, which
 * JavaScript will deliver as "\\;" after JSON.parse.
 */
function parsePattern(raw) {
  if (!raw || typeof raw !== "string") return null;
  // Split on \; (two chars: backslash + semicolon)
  const parts = raw.split("\\;");
  const regexSrc = parts[0];
  let versionTpl = "";
  let confidence = 100;

  for (let i = 1; i < parts.length; i++) {
    const p = parts[i];
    if (p.startsWith("version:")) versionTpl = p.slice(8);
    else if (p.startsWith("confidence:")) confidence = parseInt(p.slice(11), 10) || 100;
  }

  let regex = null;
  try {
    regex = new RegExp(regexSrc, "i");
  } catch {
    return null; // malformed regex — skip
  }

  return { regex, versionTpl, confidence };
}

/**
 * Extract a version string from a regex match using a Wappalyzer version template.
 * Template format: "\\1" refers to capture group 1, "\\2" to group 2, etc.
 */
function extractVersion(match, versionTpl) {
  if (!versionTpl || !match) return null;
  const ver = versionTpl.replace(/\\(\d+)/g, (_, n) => match[parseInt(n, 10)] || "");
  const cleaned = ver.trim().replace(/^[^0-9]*/, "");
  return cleaned || null;
}

// ─── Matcher ─────────────────────────────────────────────────────────────────

/**
 * Try to match a single Enthec tech entry against collected page signals.
 *
 * signals: {
 *   headers:    { [lowerCaseName]: string }  — response headers
 *   html:       string                        — full outer HTML (truncated)
 *   scriptSrcs: string[]                      — all script/link URLs on page
 *   cookies:    string                        — document.cookie + Set-Cookie blob
 *   metas:      { [name]: string }            — <meta name=...> content values
 * }
 *
 * Returns a detection object or null.
 */
function matchEnthec(techName, tech, signals) {
  const { headers, html, scriptSrcs, cookies, metas } = signals;
  let version = null;
  let matched = false;

  // ── headers ──────────────────────────────────────────────────────────────
  if (tech.headers && !matched) {
    for (const [hName, rawPattern] of Object.entries(tech.headers)) {
      const parsed = parsePattern(rawPattern);
      if (!parsed) continue;
      const val = headers[hName.toLowerCase()];
      if (!val) continue;
      const m = val.match(parsed.regex);
      if (m) {
        matched = true;
        version = version || extractVersion(m, parsed.versionTemplate) || m[1] || null;
        break;
      }
    }
  }

  // ── html body ─────────────────────────────────────────────────────────────
  if (!matched && tech.html) {
    for (const rawPattern of [tech.html].flat()) {
      const parsed = parsePattern(rawPattern);
      if (!parsed) continue;
      const m = html.match(parsed.regex);
      if (m) {
        matched = true;
        version = version || extractVersion(m, parsed.versionTemplate) || m[1] || null;
        break;
      }
    }
  }

  // ── script src URLs ───────────────────────────────────────────────────────
  if (!matched && tech.scriptSrc) {
    for (const rawPattern of [tech.scriptSrc].flat()) {
      const parsed = parsePattern(rawPattern);
      if (!parsed) continue;
      for (const src of scriptSrcs) {
        const m = src.match(parsed.regex);
        if (m) {
          matched = true;
          version = version || extractVersion(m, parsed.versionTemplate) || m[1] || null;
          break;
        }
      }
      if (matched) break;
    }
  }

  // ── cookies ───────────────────────────────────────────────────────────────
  if (!matched && tech.cookies) {
    for (const [cName] of Object.entries(tech.cookies)) {
      if (new RegExp(`\\b${cName}\\b`, "i").test(cookies)) {
        matched = true;
        break;
      }
    }
  }

  // ── meta tags ─────────────────────────────────────────────────────────────
  if (!matched && tech.meta) {
    for (const [metaName, rawPattern] of Object.entries(tech.meta)) {
      const parsed = parsePattern(rawPattern);
      if (!parsed) continue;
      const val = metas[metaName.toLowerCase()];
      if (!val) continue;
      const m = val.match(parsed.regex);
      if (m) {
        matched = true;
        version = version || extractVersion(m, parsed.versionTemplate) || m[1] || null;
        break;
      }
    }
  }

  if (!matched) return null;

  // ── build result ──────────────────────────────────────────────────────────
  // Enthec categories are numeric IDs. We just use a readable string here;
  // the popup renders it as-is.
  const catId = (tech.cats || [])[0];
  const category = catId ? `cat:${catId}` : "Other";

  // Build OSV lookup info if the tech has a website (heuristic: use npm ecosystem
  // with the lowercased tech name — this hits for most JS packages).
  // Genuine server-side packages often have no npm entry, so we skip those.
  const osv = tech.website ? { ecosystem: "npm", name: techName.toLowerCase() } : null;

  return {
    id: `enthec:${techName}`,
    name: techName,
    category,
    version: version || null,
    osv,
    cpe: null,
    source: "enthec"
  };
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Run all Enthec fingerprints against the given page signals.
 * Returns an array of detection result objects (same shape as SIGNATURES results).
 *
 * Already-known IDs (from SIGNATURES) are skipped to avoid double-counting;
 * pass knownIds as a Set of id strings already detected.
 */
export async function runEnthec(signals, knownIds = new Set()) {
  let db;
  try {
    db = await loadEnthec();
  } catch {
    return [];
  }

  const results = [];

  for (const [techName, tech] of Object.entries(db)) {
    // Skip if our hand-written SIGNATURES already detected this tech
    const normalizedName = techName.toLowerCase().replace(/[^a-z0-9]/g, "");
    const alreadyKnown = [...knownIds].some(
      (id) => id.toLowerCase().replace(/[^a-z0-9]/g, "") === normalizedName
    );
    if (alreadyKnown) continue;

    const result = matchEnthec(techName, tech, signals);
    if (result) results.push(result);
  }

  return results;
}
