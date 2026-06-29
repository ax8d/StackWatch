/**
 * Advanced detection — Tiers 3, 4, 5, 6.
 *
 * All functions here are called from the service worker after the basic
 * passive detection pass and are purely additive — they never modify
 * existing detections, only append new ones.
 *
 * Tier 3 — Error page + server probe fingerprinting
 *   Fetches /nonexistent-path (triggering a 404), /nginx-status, /server-status
 *   and reads the response headers + body for server banners. This catches
 *   Nginx / Apache when the CDN strips the Server: header on the main page.
 *
 * Tier 4 — robots.txt / .well-known path mining
 *   CMS structures leave tell-tale Disallow paths in robots.txt (wp-admin,
 *   /administrator/, /sites/default/). Also checks /.well-known/security.txt.
 *
 * Tier 5 — Source map extraction
 *   Reads the first kilobytes of each JS asset looking for a
 *   //# sourceMappingURL= comment, then fetches and parses the .map file.
 *   node_modules paths inside .sources[] reveal the exact npm package name
 *   (and sometimes version) of every bundled dependency — a signal Wappalyzer
 *   cannot produce because it never fetches .map files.
 *
 * Tier 6 — Shodan InternetDB
 *   Free endpoint (no API key): https://internetdb.shodan.io/<ip>
 *   Returns CPE strings and tags for the server. Resolves the page hostname
 *   to an IP first via Cloudflare DNS-over-HTTPS.
 */

import { SIGNATURES } from "./signatures.js";

// ─── Shared utilities ─────────────────────────────────────────────────────────

/** Fetch with a hard timeout. Returns null on any error or timeout. */
async function safeFetch(url, opts = {}, timeoutMs = 6000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    return res;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** True if the IP is RFC-1918 / loopback — skip Shodan for private ranges. */
function isPrivateIp(ip) {
  return (
    /^127\./.test(ip) ||
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === "::1"
  );
}

/** Find a SIGNATURES entry by id (exact) or by matching name/cpe/osv. */
function sigById(id) {
  return SIGNATURES.find((s) => s.id === id) || null;
}

function sigByVendorProduct(vendor, product) {
  return (
    SIGNATURES.find(
      (s) =>
        s.cpe &&
        s.cpe.vendor.toLowerCase() === vendor.toLowerCase() &&
        s.cpe.product.toLowerCase() === product.toLowerCase()
    ) || null
  );
}

// ─── Tier 3 — Error page + server probe ───────────────────────────────────────

const ERROR_PAGE_PATTERNS = [
  { regex: /nginx\/([0-9][0-9.]*)/i,              id: "nginx",      name: "nginx",              category: "Web Server" },
  { regex: /<(?:center|title)>nginx<\/(?:center|title)>/i, id: "nginx", name: "nginx",          category: "Web Server" },
  { regex: /openresty\/([0-9][0-9.]*)/i,          id: "openresty",  name: "OpenResty",          category: "Web Server" },
  { regex: /Apache\/([0-9][0-9.]*)/i,             id: "apache",     name: "Apache HTTP Server", category: "Web Server" },
  { regex: /Microsoft-IIS\/([0-9][0-9.]*)/i,      id: "iis",        name: "Microsoft IIS",      category: "Web Server" },
  { regex: /LiteSpeed(?:\/([0-9][0-9.]*))?/i,     id: "litespeed",  name: "LiteSpeed",          category: "Web Server" },
  { regex: /Tengine(?:\/([0-9][0-9.]*))?/i,       id: "tengine",    name: "Tengine",            category: "Web Server" },
  { regex: /lighttpd\/([0-9][0-9.]*)/i,           id: "lighttpd",   name: "lighttpd",           category: "Web Server" },
  { regex: /Caddy(?:\/([0-9][0-9.]*))?/i,         id: "caddy",      name: "Caddy",              category: "Web Server" },
  { regex: /Werkzeug\/([0-9][0-9.]*)/i,           id: "werkzeug",   name: "Werkzeug",           category: "Web Framework" },
  { regex: /Python\/([0-9][0-9.]*)/i,             id: "python",     name: "Python",             category: "Programming Language" },
  { regex: /PHP\/([0-9][0-9.]*)/i,                id: "php",        name: "PHP",                category: "Programming Language" },
];

const PROBE_PATHS = [
  // 404 probe — nearly every server exposes its identity in the error page
  { path: `/.stackwatch-probe-${Math.random().toString(36).slice(2, 8)}`, type: "404" },
  // Nginx stub status module (common in monitoring setups)
  { path: "/nginx-status",   type: "stub_status" },
  { path: "/nginx_status",   type: "stub_status" },
  // Apache server-status
  { path: "/server-status",  type: "apache_status" },
  // PHP info (will 403 on most hardened servers, but the 403 header still leaks server)
  { path: "/info.php",       type: "php_info" },
];

/**
 * Probes a small set of well-known paths on the origin and scans both
 * response headers and body for server banners.
 *
 * Only runs when no server-type tech has already been detected, to avoid
 * redundant network traffic.
 *
 * @param {string} origin  - e.g. "https://example.com"
 * @param {object[]} existingDetections - already-found items
 * @returns {Promise<object[]>} new detection objects
 */
export async function probeErrorPages(origin, existingDetections) {
  // Skip if we already know the server type
  const serverIds = new Set(["nginx","openresty","apache","iis","litespeed",
    "tengine","lighttpd","caddy","werkzeug","gunicorn","tomcat","kestrel",
    "haproxy","jetty","passenger"]);
  const hasServer = existingDetections.some((d) => serverIds.has(d.id));
  if (hasServer) return [];

  const found = [];

  for (const probe of PROBE_PATHS) {
    const res = await safeFetch(`${origin}${probe.path}`, {
      method: "GET",
      redirect: "follow",
      headers: { Accept: "text/html,*/*" }
    });
    if (!res) continue;

    // 1. Check response headers (CDNs sometimes strip the main-page Server:
    //    header but leave it on error responses)
    const serverHdr = res.headers.get("server") || "";
    const poweredBy  = res.headers.get("x-powered-by") || "";
    const combined   = `${serverHdr} ${poweredBy}`;

    for (const pat of ERROR_PAGE_PATTERNS) {
      const m = combined.match(pat.regex);
      if (m) {
        found.push({
          id: pat.id, name: pat.name, category: pat.category,
          version: m[1] || null,
          cpe: sigById(pat.id)?.cpe || null,
          osv: sigById(pat.id)?.osv || null,
          source: "error_probe_header"
        });
        break;
      }
    }
    if (found.length > 0) break;

    // 2. Check body (only for small/fast responses)
    if (res.status === 404 || res.status === 403 || (res.ok && probe.type !== "404")) {
      let body = "";
      try {
        body = await res.text();
        if (body.length > 12000) body = body.slice(0, 12000);
      } catch { continue; }

      for (const pat of ERROR_PAGE_PATTERNS) {
        const m = body.match(pat.regex);
        if (m) {
          found.push({
            id: pat.id, name: pat.name, category: pat.category,
            version: m[1] || null,
            cpe: sigById(pat.id)?.cpe || null,
            osv: sigById(pat.id)?.osv || null,
            source: "error_probe_body"
          });
          break;
        }
      }
      if (found.length > 0) break;
    }
  }

  return found;
}

// ─── Tier 4 — robots.txt / well-known path mining ────────────────────────────

const ROBOTS_CMS_PATTERNS = [
  { regex: /\/wp-admin|\/wp-content|\/wp-includes/i, id: "wordpress", name: "WordPress",    category: "CMS" },
  { regex: /WordPress\s+([0-9][0-9.]*)/i,            id: "wordpress", name: "WordPress",    category: "CMS", versioned: true },
  { regex: /\/administrator\//i,                      id: "joomla",    name: "Joomla",       category: "CMS" },
  { regex: /\/sites\/default\//i,                     id: "drupal",    name: "Drupal",        category: "CMS" },
  { regex: /Drupal\s+([0-9][0-9.]*)/i,               id: "drupal",    name: "Drupal",        category: "CMS", versioned: true },
  { regex: /\/typo3\//i,                              id: "typo3",     name: "TYPO3",         category: "CMS" },
  { regex: /\/contao\//i,                             id: "contao",    name: "Contao",        category: "CMS" },
  { regex: /\/concrete5\//i,                          id: "concrete5", name: "Concrete CMS",  category: "CMS" },
  { regex: /\/craft\//i,                              id: "craftcms",  name: "Craft CMS",     category: "CMS" },
];

/**
 * Fetches robots.txt and /.well-known/security.txt and extracts CMS / server
 * identifiers from their content.
 *
 * @param {string} origin
 * @param {object[]} existingDetections
 * @returns {Promise<object[]>}
 */
export async function minePublicPaths(origin, existingDetections) {
  const existingIds = new Set(existingDetections.map((d) => d.id));
  const found = [];

  // ── robots.txt ────────────────────────────────────────────────────────────
  const robotsRes = await safeFetch(`${origin}/robots.txt`);
  if (robotsRes && robotsRes.ok) {
    let body = "";
    try { body = await robotsRes.text(); } catch {}

    for (const pat of ROBOTS_CMS_PATTERNS) {
      if (existingIds.has(pat.id)) continue;
      const m = body.match(pat.regex);
      if (m) {
        const version = pat.versioned ? (m[1] || null) : null;
        found.push({
          id: pat.id, name: pat.name, category: pat.category,
          version,
          cpe: sigById(pat.id)?.cpe || null,
          osv: sigById(pat.id)?.osv || null,
          source: "robots_txt"
        });
        existingIds.add(pat.id);
      }
    }
  }

  // ── /.well-known/security.txt ──────────────────────────────────────────────
  const secRes = await safeFetch(`${origin}/.well-known/security.txt`);
  if (secRes && secRes.ok) {
    let body = "";
    try { body = await secRes.text(); } catch {}

    // Some operators list their tech in the security.txt
    for (const pat of ERROR_PAGE_PATTERNS) {
      if (existingIds.has(pat.id)) continue;
      const m = body.match(pat.regex);
      if (m) {
        found.push({
          id: pat.id, name: pat.name, category: pat.category,
          version: m[1] || null,
          cpe: sigById(pat.id)?.cpe || null,
          osv: sigById(pat.id)?.osv || null,
          source: "security_txt"
        });
        existingIds.add(pat.id);
      }
    }
  }

  return found;
}

// ─── Tier 5 — Source map extraction ──────────────────────────────────────────

/** Bundler-signature globals visible in the first ~4 KB of a bundle. */
const BUNDLER_SIGS = [
  { regex: /__webpack_require__|webpackJsonp|__webpack_exports__/,
    id: "webpack",   name: "webpack",  category: "Bundler",
    osv: { ecosystem: "npm", name: "webpack" } },
  { regex: /__vite__global__|import\.meta\.hot/,
    id: "vite",      name: "Vite",     category: "Bundler",
    osv: { ecosystem: "npm", name: "vite" } },
  { regex: /__turbopack_require__|__turbopack_load__/,
    id: "turbopack", name: "Turbopack",category: "Bundler",
    osv: { ecosystem: "npm", name: "@vercel/turbopack" } },
  { regex: /define\(["']require["']|require\.config/,
    id: "requirejs", name: "RequireJS",category: "JS Library",
    osv: { ecosystem: "npm", name: "requirejs" } },
  { regex: /\brollupVersion\b|generated by rollup/i,
    id: "rollup",    name: "Rollup",   category: "Bundler",
    osv: { ecosystem: "npm", name: "rollup" } },
];

/**
 * Reads the first ~4 KB of each JS asset URL:
 *   1. Detects bundler signatures in the bundle header.
 *   2. Extracts //# sourceMappingURL= and fetches the .map file.
 *   3. Parses map.sources[] for node_modules/ package paths and versions.
 *
 * Limits to the first MAX_JS_ASSETS script URLs to keep the scan fast.
 *
 * @param {string[]} assetUrls
 * @param {object[]} existingDetections
 * @returns {Promise<object[]>}
 */
export async function mineSourceMaps(assetUrls, existingDetections) {
  const MAX_JS_ASSETS = 6;
  const HEAD_BYTES    = 5000; // bytes to read for bundler sig + sourceMappingURL

  const existingIds = new Set(existingDetections.map((d) => d.id));
  const foundBundlers = new Set();
  const foundPackages = new Map(); // pkgName → { version, osv, id, name, category }
  const results = [];

  const jsUrls = assetUrls
    .filter((u) => /\.m?js(\?[^#]*)?$/.test(u.split("?")[0]) || /\.js\?/.test(u))
    .slice(0, MAX_JS_ASSETS);

  for (const url of jsUrls) {
    // ── Read head of file ────────────────────────────────────────────────────
    let head = "";
    try {
      const res = await safeFetch(url, {}, 8000);
      if (!res || !res.ok) continue;

      const reader = res.body.getReader();
      const chunks = [];
      let totalRead = 0;
      let done = false;

      while (!done && totalRead < HEAD_BYTES) {
        const { value, done: d } = await reader.read();
        if (value) { chunks.push(value); totalRead += value.length; }
        done = d;
      }
      reader.cancel().catch(() => {});
      head = new TextDecoder().decode(
        chunks.reduce((a, b) => { const c = new Uint8Array(a.length + b.length); c.set(a); c.set(b, a.length); return c; }, new Uint8Array())
      );
    } catch { continue; }

    // ── Bundler detection ─────────────────────────────────────────────────────
    for (const sig of BUNDLER_SIGS) {
      if (!foundBundlers.has(sig.id) && !existingIds.has(sig.id) && sig.regex.test(head)) {
        foundBundlers.add(sig.id);
        results.push({
          id: sig.id, name: sig.name, category: sig.category,
          version: null, osv: sig.osv || null, cpe: null,
          source: "bundle_globals"
        });
      }
    }

    // ── Source map URL ─────────────────────────────────────────────────────────
    // Also check the full tail: some minifiers put the comment at the very end,
    // so we do a quick reversed scan of the last 512 chars we have.
    const mapMatch =
      head.match(/\/\/# sourceMappingURL=([^\s'"]+\.map[^\s'"]*)/i) ||
      head.slice(-512).match(/\/\/# sourceMappingURL=([^\s'"]+\.map[^\s'"]*)/i);

    if (!mapMatch) continue;

    let mapUrl = mapMatch[1].trim();
    if (mapUrl.startsWith("data:")) continue; // inline source maps — skip

    if (!/^https?:\/\//.test(mapUrl)) {
      try { mapUrl = new URL(mapUrl, url).href; }
      catch { continue; }
    }

    // ── Fetch and parse the map ───────────────────────────────────────────────
    let mapData = null;
    try {
      const mapRes = await safeFetch(mapUrl, {}, 15000);
      if (!mapRes || !mapRes.ok) continue;
      mapData = await mapRes.json();
    } catch { continue; }

    const sources = Array.isArray(mapData.sources) ? mapData.sources : [];

    for (const src of sources) {
      if (!src) continue;

      // Match node_modules/pkgname or node_modules/@scope/pkgname
      const nmMatch = src.match(/node_modules\/((?:@[^/]+\/)?[^/]+)\//);
      if (!nmMatch) continue;
      const pkg = nmMatch[1];

      if (foundPackages.has(pkg)) continue; // already processed this package

      // Some bundlers embed the version in the source path:
      //   node_modules/react@18.2.0/index.js   (pnpm style)
      //   webpack://./node_modules/lodash/4.17.21/...
      const versionInPath =
        src.match(new RegExp(`node_modules/${pkg.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&")}@([0-9]+\\.[0-9]+\\.[0-9.]*)`)) ||
        src.match(/\/([0-9]+\.[0-9]+\.[0-9.]+)\//);

      const version = versionInPath ? versionInPath[1] : null;

      // Find matching SIGNATURES entry
      const sig = SIGNATURES.find(
        (s) => s.osv && s.osv.name.toLowerCase() === pkg.toLowerCase()
      );

      foundPackages.set(pkg, {
        id:       sig?.id       || `sourcemap:${pkg}`,
        name:     sig?.name     || pkg,
        category: sig?.category || "npm Package",
        version,
        osv: sig?.osv || { ecosystem: "npm", name: pkg },
        cpe: sig?.cpe || null,
        source: "source_map"
      });
    }
  }

  // Flatten package map into results, skipping already-known ids
  for (const det of foundPackages.values()) {
    if (!existingIds.has(det.id)) {
      results.push(det);
    }
  }

  return results;
}

// ─── Tier 6 — Shodan InternetDB ──────────────────────────────────────────────

const SHODAN_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours (IP intel changes slowly)

async function getCachedShodan(ip) {
  try {
    const key = `sw_cache_shodan:${ip}`;
    const r = await chrome.storage.local.get(key);
    const e = r[key];
    if (!e || Date.now() - e.timestamp > SHODAN_TTL_MS) return null;
    return e.data;
  } catch { return null; }
}

async function setCachedShodan(ip, data) {
  try {
    await chrome.storage.local.set({
      [`sw_cache_shodan:${ip}`]: { timestamp: Date.now(), data }
    });
  } catch {}
}

/**
 * Resolves hostname → IP via Cloudflare DoH, then queries Shodan InternetDB
 * (free, no API key) and maps the returned CPE strings and tags to SIGNATURES.
 *
 * @param {string} hostname  - e.g. "example.com"
 * @param {object[]} existingDetections
 * @returns {Promise<object[]>}
 */
export async function queryShodanInternetDB(hostname, existingDetections) {
  if (!hostname) return [];

  const existingIds = new Set(existingDetections.map((d) => d.id));
  const results = [];

  // ── 1. Resolve hostname to IP ──────────────────────────────────────────────
  let ip = null;
  try {
    const dnsRes = await safeFetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
      { headers: { Accept: "application/dns-json" } },
      5000
    );
    if (dnsRes && dnsRes.ok) {
      const dns = await dnsRes.json();
      ip = (dns.Answer || []).find((a) => a.type === 1)?.data || null;
    }
  } catch {}

  if (!ip || isPrivateIp(ip)) return [];

  // ── 2. Check cache ─────────────────────────────────────────────────────────
  const cached = await getCachedShodan(ip);
  const data = cached || await (async () => {
    const r = await safeFetch(`https://internetdb.shodan.io/${ip}`, {}, 8000);
    if (!r || !r.ok) return null;
    try { return await r.json(); } catch { return null; }
  })();

  if (!data) return [];
  if (!cached) await setCachedShodan(ip, data);

  // ── 3. Map CPE strings to SIGNATURES ──────────────────────────────────────
  for (const cpeStr of data.cpes || []) {
    // cpe:/a:vendor:product:version  or  cpe:2.3:a:vendor:product:version:...
    const m =
      cpeStr.match(/^cpe:\/[aoh]:([^:]+):([^:]+):?([0-9][0-9.]*)?/) ||
      cpeStr.match(/^cpe:2\.3:[aoh]:([^:]+):([^:]+):([^:]*)/);
    if (!m) continue;

    const vendor  = m[1];
    const product = m[2];
    const version = (m[3] && m[3] !== "*" && m[3] !== "-") ? m[3] : null;

    const sig = sigByVendorProduct(vendor, product);
    const id  = sig?.id || `cpe:${vendor}:${product}`;

    if (existingIds.has(id)) {
      // If we have a version and the existing entry doesn't, annotate — but
      // since mergeDetections handles this, we just skip to avoid duplicates.
      continue;
    }
    existingIds.add(id);

    results.push({
      id,
      name:     sig?.name     || `${vendor}/${product}`,
      category: sig?.category || "Detected (Shodan)",
      version,
      cpe:  sig?.cpe  || { vendor, product },
      osv:  sig?.osv  || null,
      source: "shodan_internetdb"
    });
  }

  // ── 4. Map string tags (e.g. "nginx", "apache") ───────────────────────────
  for (const tag of data.tags || []) {
    const tagLower = tag.toLowerCase();
    const sig = SIGNATURES.find(
      (s) => s.id === tagLower || s.name.toLowerCase() === tagLower
    );
    if (!sig || existingIds.has(sig.id)) continue;
    existingIds.add(sig.id);

    results.push({
      id: sig.id, name: sig.name, category: sig.category,
      version: null,
      cpe: sig.cpe || null,
      osv: sig.osv || null,
      source: "shodan_internetdb"
    });
  }

  return results;
}
