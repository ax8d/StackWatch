/**
 * Two distinct problems were getting conflated as "duplicate CVEs":
 *
 * 1. The SAME CVE ID appearing twice — a real bug. OSV sometimes returns
 *    more than one advisory record (e.g. a GHSA-sourced record and an
 *    ecosystem-specific PYSEC/RUSTSEC record) that both carry the same CVE
 *    alias. dedupeByCveId() fixes this by merging records that share a
 *    CVE/OSV id, keeping whichever has the most complete data.
 *
 * 2. DIFFERENT CVE IDs describing what reads like the same issue — often
 *    NOT a bug. It's common for a vulnerability fix to be incomplete, with
 *    a follow-up CVE filed for the bypass (e.g. several real Werkzeug
 *    `safe_join()` CVEs exist for exactly this reason). These are
 *    genuinely separate advisories and shouldn't be silently merged — but
 *    flat-listing 3 near-identical-looking entries reads as noise.
 *    groupNearDuplicates() clusters them under one expandable card instead,
 *    without hiding that they're distinct CVEs.
 */

export function dedupeByCveId(vulns) {
  const map = new Map();
  for (const v of vulns) {
    const key = v.cveId || v.osvId;
    if (!key) continue;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, v);
      continue;
    }
    // Prefer the record with a real CVSS score; merge reference lists either way.
    const better = existing.cvssScore == null && v.cvssScore != null ? v : existing;
    const mergedRefs = dedupeRefs([...(existing.references || []), ...(v.references || [])]);
    map.set(key, { ...better, references: mergedRefs });
  }
  return Array.from(map.values());
}

function dedupeRefs(refs) {
  const seen = new Set();
  const out = [];
  for (const r of refs) {
    const url = typeof r === "string" ? r : r.url;
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push(r);
  }
  return out;
}

/** Normalizes a summary into a word set for similarity comparison. */
function normalizeWords(summary) {
  if (!summary) return new Set();
  const words = summary
    .toLowerCase()
    .replace(/cve-\d{4}-\d+/g, "")
    .replace(/[0-9]+(\.[0-9]+)*/g, "")
    .replace(/[^a-z\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 2);
  return new Set(words);
}

function jaccard(a, b) {
  if (a.size === 0 || b.size === 0) return 0;
  let intersection = 0;
  for (const w of a) if (b.has(w)) intersection++;
  const union = a.size + b.size - intersection;
  return intersection / union;
}

const SIMILARITY_THRESHOLD = 0.5;

/**
 * Groups vulns whose summary text is substantially similar (Jaccard
 * similarity over significant words, not just identical wording) into
 * { primary, related: [] } clusters. `primary` is the highest-score
 * member, so the visible headline is the most serious one in the cluster.
 * Greedy clustering against each cluster's first member — fine for the
 * small (<100) finding lists this runs on.
 */
export function groupNearDuplicates(vulns) {
  const withWords = vulns.map((v) => ({ v, words: normalizeWords(v.summary) }));
  const clusters = [];

  for (const item of withWords) {
    let placed = false;
    for (const cluster of clusters) {
      if (jaccard(item.words, cluster[0].words) >= SIMILARITY_THRESHOLD) {
        cluster.push(item);
        placed = true;
        break;
      }
    }
    if (!placed) clusters.push([item]);
  }

  return clusters.map((cluster) => {
    const members = cluster.map((c) => c.v).sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));
    return { primary: members[0], related: members.slice(1) };
  });
}
