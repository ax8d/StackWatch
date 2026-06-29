import { SIGNATURES, buildLookupTarget } from "../lib/signatures.js";
import { extractFromCdnUrl } from "../lib/cdn-detect.js";
import { queryOsvFullList } from "../lib/osv-client.js";
import { queryNvdFullList } from "../lib/nvd-client.js";
import { isOsvVersionAffected, isNvdVersionAffected } from "../lib/version-match.js";
import { getCached, setCached, pruneExpired } from "../lib/cache.js";
import { analyzeHeaders } from "../lib/header-signals.js";
import { computeScore } from "../lib/score.js";
import { dedupeByCveId, groupNearDuplicates } from "../lib/dedupe.js";
import { suggestFixedVersionOsv, suggestFixedVersionNvd } from "../lib/remediation.js";

const CDN_HOST_PATTERN = /jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|googleapis\.com\/ajax|bootstrapcdn\.com|code\.jquery\.com/i;
const STATE_PREFIX = "tabstate_";

// MV3 service workers are ephemeral — Chrome can (and routinely does) kill
// this worker after ~30s idle, wiping any in-memory Map. That was the root
// cause of "cached/already-open tabs show nothing until reload": the
// content script's one-time message had nowhere durable to land. Per-tab
// state now lives in chrome.storage.session, which survives worker
// restarts for the lifetime of the browser session.
async function getTabState(tabId) {
  const key = STATE_PREFIX + tabId;
  const result = await chrome.storage.session.get(key);
  return result[key] || null;
}
async function setTabState(tabId, state) {
  await chrome.storage.session.set({ [STATE_PREFIX + tabId]: state });
}
async function deleteTabState(tabId) {
  await chrome.storage.session.remove(STATE_PREFIX + tabId);
}

// Short-lived in-memory guard against firing executeScript twice for the
// same tab while a rescan is already in flight.
const rescansInFlight = new Set();

chrome.runtime.onInstalled.addListener(async () => {
  const { activeProbingEnabled } = await chrome.storage.local.get("activeProbingEnabled");
  if (activeProbingEnabled === undefined) {
    await chrome.storage.local.set({ activeProbingEnabled: true, nvdApiKey: "" });
  }
  pruneExpired();
});

// Capture response headers (incl. Set-Cookie, via extraHeaders) from the
// page's own navigation request — no extra network calls for this part.
chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (details.type !== "main_frame") return;
    const headers = {};
    const setCookieValues = [];
    for (const h of details.responseHeaders || []) {
      const name = h.name.toLowerCase();
      if (name === "set-cookie") setCookieValues.push(h.value);
      else headers[name] = h.value;
    }
    const state = (await getTabState(details.tabId)) || {};
    state.headers = headers;
    state.rawSetCookie = setCookieValues.join("; ");
    state.url = details.url;
    state.isHttps = details.url.startsWith("https://");
    await setTabState(details.tabId, state);
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["responseHeaders", "extraHeaders"]
);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "STACKWATCH_PASSIVE_RESULTS") {
    handlePassiveResults(msg, sender);
    return;
  }
  if (msg.type === "STACKWATCH_OPEN_POPUP") {
    chrome.action.openPopup?.();
    return;
  }
  if (msg.type === "STACKWATCH_GET_TAB_RESULTS") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) return sendResponse(null);

      let state = await getTabState(tab.id);

      // This is the fix: if we have no state at all for this tab — because
      // it was already open before the extension loaded, was restored from
      // back/forward cache, or the service worker simply got killed and
      // lost everything — actively re-run detection right now instead of
      // waiting for a page load that may never happen again.
      if (!state && !rescansInFlight.has(tab.id)) {
        rescansInFlight.add(tab.id);
        triggerOnDemandScan(tab.id, tab.url).finally(() => rescansInFlight.delete(tab.id));
        state = { status: "detecting" };
        await setTabState(tab.id, state);
      }

      sendResponse(state);
    })();
    return true;
  }
  if (msg.type === "STACKWATCH_RESCAN") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab) {
        await deleteTabState(tab.id);
        chrome.tabs.reload(tab.id);
      }
      sendResponse({ ok: true });
    })();
    return true;
  }
});

/**
 * Re-injects the content script directly into an already-loaded tab and,
 * if we never captured response headers for it, fetches the page ourselves
 * as a best-effort fallback so header-based detection still works. Note:
 * fetch() cannot read Set-Cookie (browsers block it from script for
 * security), so cookie-based fingerprinting only fires on a "real"
 * page-load detection, not this on-demand fallback path.
 */
async function triggerOnDemandScan(tabId, url) {
  const state = (await getTabState(tabId)) || {};

  if (!state.headers && url && /^https?:\/\//.test(url)) {
    try {
      const res = await fetch(url);
      const headers = {};
      res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
      state.headers = headers;
      state.url = url;
      state.isHttps = url.startsWith("https://");
      await setTabState(tabId, state);
    } catch {
      // best-effort only; header-based detection just won't fire if this fails
    }
  }

  try {
    await chrome.scripting.executeScript({ target: { tabId }, files: ["content/detector.js"] });
  } catch {
    // tab may be a chrome:// page or otherwise non-injectable — nothing more to do
  }
}

async function handlePassiveResults(msg, sender) {
  const tabId = sender.tab?.id;
  if (tabId == null) return;

  const state = (await getTabState(tabId)) || {};
  state.url = msg.url;
  state.status = "detecting";
  await setTabState(tabId, state);

  const headers = state.headers || {};
  const headerDetections = detectFromHeaders(headers);
  const cookieBlob = `${msg.cookieString || ""}; ${state.rawSetCookie || ""}`;
  const cookieDetections = detectFromCookies(cookieBlob);
  const { cdnDetections, cdnAssetCount } = detectFromCdnUrls(msg.assetUrls || []);

  let merged = mergeDetections([...msg.detected, ...headerDetections, ...cookieDetections, ...cdnDetections]);

  const { activeProbingEnabled } = await chrome.storage.local.get("activeProbingEnabled");
  if (activeProbingEnabled) {
    await runActiveProbes(merged, msg.url);
    await runCommentSniff(merged);
  }

  state.passiveDetected = merged;
  state.cdnAssetCount = cdnAssetCount;
  state.status = "looking_up_cves";
  await setTabState(tabId, state);
  updateBadge(tabId, null);

  const results = await lookupAllCves(merged);
  const headerSignals = analyzeHeaders(headers, state.isHttps);
  const score = computeScore(results, headerSignals, cdnAssetCount);

  state.results = results;
  state.headerSignals = headerSignals;
  state.score = score;
  state.status = "done";
  await setTabState(tabId, state);

  updateBadge(tabId, results);

  const confirmedCritical = results.flatMap((r) => r.vulnerabilities).filter((v) => v.severity === "critical");
  if (confirmedCritical.length > 0) {
    chrome.tabs.sendMessage(tabId, {
      type: "STACKWATCH_SHOW_BANNER",
      summary: { count: confirmedCritical.length, example: confirmedCritical[0].cveId }
    }).catch(() => {});
  }
}

function detectFromHeaders(headers) {
  const found = [];
  for (const sig of SIGNATURES) {
    const h = sig.detect?.header;
    if (!h) continue;
    let val = headers[h.name];
    let m = val ? val.match(h.regex) : null;

    if (!m && sig.detect?.header2) {
      const h2 = sig.detect.header2;
      const val2 = headers[h2.name];
      m = val2 ? val2.match(h2.regex) : null;
    }

    if (m) {
      found.push({ id: sig.id, name: sig.name, category: sig.category, version: m[1] || null, cpe: sig.cpe || null, osv: sig.osv || null, source: "header" });
    }
  }
  return found;
}

function detectFromCookies(cookieBlob) {
  const found = [];
  if (!cookieBlob) return found;
  for (const sig of SIGNATURES) {
    if (!sig.cookieHint) continue;
    if (sig.cookieHint.regex.test(cookieBlob)) {
      found.push({ id: sig.id, name: sig.name, category: sig.category, version: null, cpe: sig.cpe || null, osv: sig.osv || null, source: "cookie" });
    }
  }
  return found;
}

function detectFromCdnUrls(assetUrls) {
  const found = [];
  const seen = new Set();
  let cdnAssetCount = 0;

  for (const url of assetUrls) {
    if (CDN_HOST_PATTERN.test(url)) cdnAssetCount++;

    const parsed = extractFromCdnUrl(url);
    if (!parsed) continue;
    if (seen.has(parsed.name)) continue;
    seen.add(parsed.name);

    const matchingSig = SIGNATURES.find((s) => s.osv && s.osv.name.toLowerCase() === parsed.name.toLowerCase());

    if (matchingSig) {
      found.push({ id: matchingSig.id, name: matchingSig.name, category: matchingSig.category, version: parsed.version, osv: matchingSig.osv, source: "cdn", cdn: parsed.cdn });
    } else {
      found.push({
        id: `cdn:${parsed.name}`,
        name: parsed.name,
        category: "Auto-detected (CDN)",
        version: parsed.version,
        osv: { ecosystem: parsed.ecosystem, name: parsed.name },
        source: "cdn",
        cdn: parsed.cdn,
        inferred: true
      });
    }
  }

  return { cdnDetections: found, cdnAssetCount };
}

function mergeDetections(all) {
  const map = new Map();
  for (const d of all) {
    const existing = map.get(d.id);
    if (!existing) {
      map.set(d.id, d);
    } else if (!existing.version && d.version) {
      map.set(d.id, { ...existing, ...d, version: d.version });
    }
  }
  return Array.from(map.values());
}

async function runActiveProbes(detections, pageUrl) {
  let origin;
  try { origin = new URL(pageUrl).origin; } catch { return; }

  for (const d of detections) {
    const sig = SIGNATURES.find((s) => s.id === d.id);
    if (!sig?.activeProbes) continue;

    for (const probe of sig.activeProbes) {
      try {
        const res = await fetch(origin + probe.path, { method: "GET", redirect: "manual" });
        if (probe.versionRegex && res.status === 200) {
          const text = await res.text();
          const m = text.match(probe.versionRegex);
          if (m && !d.version) d.version = m[1];
        }
      } catch {
        // best-effort; network errors/CORS are expected and silently skipped
      }
    }
  }
}

async function runCommentSniff(detections) {
  for (const d of detections) {
    if (d.version || !d.assetUrl) continue;
    const sig = SIGNATURES.find((s) => s.id === d.id);
    if (!sig?.commentSniff) continue;

    try {
      const res = await fetch(d.assetUrl);
      if (!res.ok) continue;
      const text = await res.text();
      const m = text.slice(0, 2000).match(sig.commentSniff);
      if (m) d.version = m[1];
    } catch {
      // cross-origin/network errors are expected and silently skipped
    }
  }
}

async function lookupAllCves(detections) {
  const { nvdApiKey } = await chrome.storage.local.get("nvdApiKey");
  const results = [];

  for (const d of detections) {
    const sig = SIGNATURES.find((s) => s.id === d.id);
    const target = buildLookupTarget(sig || { id: d.id, name: d.name, category: d.category, osv: d.osv, cpe: d.cpe }, d.version);
    target.inferred = !!d.inferred;
    target.cdn = d.cdn || null;

    let fullList = [];

    if (target.osv) {
      const cached = await getCached("osv", target.osv.name, null);
      fullList = cached ? dedupeByCveId(cached) : await fetchAndCacheOsv(target.osv);
    } else if (target.cpe) {
      const cacheId = `${target.cpe.vendor}:${target.cpe.product}`;
      const cached = await getCached("nvd", cacheId, null);
      fullList = cached ? dedupeByCveId(cached) : await fetchAndCacheNvd(target.cpe, nvdApiKey);
    }

    const { confirmed, unconfirmed } = partitionByVersion(fullList, target);
    confirmed.sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));
    unconfirmed.sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));

    for (const v of confirmed) {
      v.fixedVersion = target.osv ? suggestFixedVersionOsv(v) : target.cpe ? suggestFixedVersionNvd(v, target.cpe.vendor, target.cpe.product) : null;
    }

    results.push({
      ...target,
      vulnerabilities: confirmed,
      vulnerabilityGroups: groupNearDuplicates(confirmed),
      unconfirmedVulnerabilities: unconfirmed.slice(0, 20),
      totalKnownForProduct: fullList.length,
      worstSeverity: confirmed[0]?.severity || "none"
    });
  }

  return results;
}

async function fetchAndCacheOsv(osv) {
  const list = dedupeByCveId(await queryOsvFullList(osv));
  await setCached("osv", osv.name, null, list);
  return list;
}

async function fetchAndCacheNvd(cpe, apiKey) {
  const list = dedupeByCveId(await queryNvdFullList(cpe, apiKey));
  await setCached("nvd", `${cpe.vendor}:${cpe.product}`, null, list);
  return list;
}

function partitionByVersion(fullList, target) {
  const confirmed = [];
  const unconfirmed = [];

  for (const vuln of fullList) {
    let matched;
    if (target.osv) {
      matched = isOsvVersionAffected(target.version, vuln);
    } else if (target.cpe) {
      matched = isNvdVersionAffected(target.version, vuln, target.cpe.vendor, target.cpe.product);
    } else {
      matched = null;
    }

    if (matched === true) confirmed.push(vuln);
    else if (matched === null) unconfirmed.push({ ...vuln, unconfirmedReason: target.version ? "no_range_data" : "no_version_detected" });
  }

  return { confirmed, unconfirmed };
}

/**
 * Badge now reflects ONLY actual confirmed vulnerable components — not the
 * 0-100 risk score (which also factors in missing headers, unknown
 * versions, etc., and was showing up as a misleadingly large badge number
 * even when there were zero real vulnerabilities). No confirmed findings =
 * no badge at all.
 */
function updateBadge(tabId, results) {
  if (!results) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  let critical = 0, high = 0, medium = 0, low = 0;
  for (const r of results) {
    const groupCount = (r.vulnerabilityGroups || []).length;
    if (groupCount === 0) continue;
    if (r.worstSeverity === "critical") critical += groupCount;
    else if (r.worstSeverity === "high") high += groupCount;
    else if (r.worstSeverity === "medium") medium += groupCount;
    else if (r.worstSeverity === "low") low += groupCount;
  }

  const total = critical + high + medium + low;
  if (total === 0) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  let color = "#3EE6A5";
  if (critical > 0) color = "#FF5C7E";
  else if (high > 0) color = "#FF8A4C";
  else if (medium > 0) color = "#FFC857";
  else if (low > 0) color = "#5EC8FF";

  chrome.action.setBadgeText({ tabId, text: String(total) });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

chrome.tabs.onRemoved.addListener((tabId) => deleteTabState(tabId));
