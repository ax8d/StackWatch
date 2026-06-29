/**
 * OSV.dev client — free, no API key required.
 * Docs: https://google.github.io/osv.dev/api/
 *
 * IMPORTANT: we deliberately query by package only (no version param), even
 * when we know the detected version. This means:
 *  1. The result is cacheable per-package, not per-version, so it's reused
 *     across every site/version we ever see using that package.
 *  2. We keep `affected` ranges so version-match.js can apply our own
 *     filtering — we don't trust a single upstream filter step blindly.
 */

import { parseCvssVector, scoreToSeverity } from "./cvss.js";

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";

export async function queryOsvFullList({ ecosystem, name }) {
  if (!ecosystem || !name) return [];

  try {
    const res = await fetch(OSV_QUERY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package: { name, ecosystem } })
    });

    if (!res.ok) {
      console.warn(`[StackWatch] OSV query failed: ${res.status}`);
      return [];
    }

    const data = await res.json();
    return (data.vulns || []).map(normalizeOsvVuln);
  } catch (err) {
    console.warn("[StackWatch] OSV query error:", err);
    return [];
  }
}

function normalizeOsvVuln(v) {
  const cveId = (v.aliases || []).find((a) => a.startsWith("CVE-")) || v.id;

  let cvssScore = null, cvssVector = null, severity = "unknown";
  if (Array.isArray(v.severity)) {
    const cvss = v.severity.find((s) => s.type && s.type.startsWith("CVSS"));
    if (cvss) {
      const parsed = parseCvssVector(cvss.score);
      cvssScore = parsed.score;
      cvssVector = cvss.score;
      severity = parsed.severity;
    }
  }
  // Some OSV records (mainly GHSA-sourced) put a coarse severity word directly
  // in `database_specific.severity` when no CVSS vector is present at all.
  if (severity === "unknown" && v.database_specific?.severity) {
    severity = String(v.database_specific.severity).toLowerCase();
  }

  return {
    cveId,
    osvId: v.id,
    summary: v.summary || (v.details ? v.details.slice(0, 200) : "No summary available."),
    published: v.published || null,
    modified: v.modified || null,
    cvssScore,
    cvssVector,
    severity,
    references: (v.references || []).slice(0, 6).map((r) => ({ url: r.url, label: formatOsvRefType(r.type) })),
    rawAffected: v.affected || [], // kept for local version-range matching
    source: "osv"
  };
}

function formatOsvRefType(type) {
  const map = {
    ADVISORY: "Advisory",
    FIX: "Fix / Patch",
    REPORT: "Report",
    WEB: "Reference",
    PACKAGE: "Package",
    EVIDENCE: "Evidence",
    ARTICLE: "Article"
  };
  return map[type] || "Reference";
}

export { scoreToSeverity };
