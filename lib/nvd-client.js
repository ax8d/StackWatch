/**
 * NVD (National Vulnerability Database) client.
 * Docs: https://nvd.nist.gov/developers/vulnerabilities
 *
 * Free; an API key (signup at https://nvd.nist.gov/developers/request-an-api-key)
 * raises the rate limit from 5 req/30s to 50 req/30s.
 *
 * Like osv-client.js, we deliberately query with a WILDCARD version (i.e.
 * "give us every CVE ever filed against this product") rather than asking
 * NVD to filter server-side. We cache that full list per-product and then
 * apply our own range matching (lib/version-match.js) against the specific
 * detected version. This is what actually fixes "shows CVEs unrelated to
 * the version in use" — we never show a CVE as a confirmed finding unless
 * our own check confirms the version falls in an affected range.
 */

const NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

export async function queryNvdFullList({ vendor, product }, apiKey) {
  if (!vendor || !product) return [];

  const cpeMatchString = `cpe:2.3:*:${vendor}:${product}:*:*:*:*:*:*:*:*`;
  const params = new URLSearchParams({ virtualMatchString: cpeMatchString, resultsPerPage: "100" });

  const headers = {};
  if (apiKey) headers["apiKey"] = apiKey;

  try {
    const res = await fetch(`${NVD_BASE_URL}?${params.toString()}`, { headers });

    if (res.status === 403 || res.status === 429) {
      console.warn("[StackWatch] NVD rate limited or unauthorized — add an API key in settings for higher limits.");
      return [];
    }
    if (!res.ok) {
      console.warn(`[StackWatch] NVD query failed: ${res.status}`);
      return [];
    }

    const data = await res.json();
    return (data.vulnerabilities || []).map(normalizeNvdVuln);
  } catch (err) {
    console.warn("[StackWatch] NVD query error:", err);
    return [];
  }
}

function normalizeNvdVuln(entry) {
  const cve = entry.cve || {};
  const descs = cve.descriptions || [];
  const summary = (descs.find((d) => d.lang === "en") || descs[0] || {}).value || "No summary available.";

  const metrics = cve.metrics || {};
  let cvssScore = null, cvssVector = null, severity = "unknown";
  const chosen = metrics.cvssMetricV31?.[0]?.cvssData || metrics.cvssMetricV30?.[0]?.cvssData || metrics.cvssMetricV2?.[0]?.cvssData;
  if (chosen) {
    cvssScore = chosen.baseScore;
    cvssVector = chosen.vectorString;
    severity = (chosen.baseSeverity || "").toLowerCase() || fallbackSeverity(cvssScore);
  }

  return {
    cveId: cve.id,
    osvId: null,
    summary: summary.slice(0, 300),
    published: cve.published || null,
    modified: cve.lastModified || null,
    cvssScore,
    cvssVector,
    severity,
    references: (cve.references || []).slice(0, 6).map((r) => ({ url: r.url, label: (r.tags || [])[0] || "Reference" })),
    rawConfigurations: cve.configurations || [], // kept for local version-range matching
    source: "nvd"
  };
}

function fallbackSeverity(score) {
  if (score == null) return "unknown";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}
