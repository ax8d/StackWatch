/**
 * This module is the fix for the core correctness bug: previously, when a
 * library's version wasn't in a URL we could parse, we'd ask OSV/NVD for
 * "everything ever reported for this product" and show it as if it applied.
 *
 * Now: we fetch the FULL vulnerability list for a product once (cached per
 * product, not per version — cheaper and more reusable), and filter it
 * ourselves against the *specific detected version* using the same range
 * semantics OSV and NVD define in their own schemas. A CVE is only shown as
 * a confirmed finding if the detected version actually falls inside an
 * affected range.
 */

import { compareVersions } from "./version-compare.js";

/**
 * OSV "affected" ranges look like:
 *   ranges: [{ type: "SEMVER"|"ECOSYSTEM", events: [{introduced:"0"}, {fixed:"1.2.5"}, ...] }]
 *   versions: ["1.2.3", "1.2.4"]   (sometimes given as an explicit list instead of ranges)
 *
 * Build a list of [start, end) intervals from the events, where an interval
 * with end === null is open-ended (still affected up to and including latest).
 */
function buildIntervalsFromEvents(events) {
  const intervals = [];
  let start = "0";
  let haveOpenStart = true;

  for (const ev of events || []) {
    if ("introduced" in ev) {
      start = ev.introduced;
      haveOpenStart = true;
    } else if ("fixed" in ev) {
      intervals.push({ start, end: ev.fixed, endInclusive: false });
      haveOpenStart = false;
    } else if ("last_affected" in ev) {
      intervals.push({ start, end: ev.last_affected, endInclusive: true });
      haveOpenStart = false;
    } else if ("limit" in ev) {
      intervals.push({ start, end: ev.limit, endInclusive: false });
      haveOpenStart = false;
    }
  }
  if (haveOpenStart) {
    intervals.push({ start, end: null, endInclusive: false });
  }
  return intervals;
}

function versionInIntervals(version, intervals) {
  for (const iv of intervals) {
    const startOk = iv.start === "0" || iv.start == null || compareVersions(version, iv.start) >= 0;
    if (!startOk) continue;
    if (iv.end == null) return true;
    const cmp = compareVersions(version, iv.end);
    if (iv.endInclusive ? cmp <= 0 : cmp < 0) return true;
  }
  return false;
}

/**
 * Check whether `version` is affected by a normalized OSV vuln record.
 * `vuln.rawAffected` is the raw `affected` array as returned by the OSV API
 * (kept around specifically so we can do this check).
 */
export function isOsvVersionAffected(version, vuln) {
  if (!version) return null; // caller should treat null as "can't confirm"
  const affectedEntries = vuln.rawAffected || [];
  if (affectedEntries.length === 0) return null; // no structured data to check against

  for (const entry of affectedEntries) {
    if (Array.isArray(entry.versions) && entry.versions.length > 0) {
      if (entry.versions.includes(version)) return true;
      continue;
    }
    for (const range of entry.ranges || []) {
      const intervals = buildIntervalsFromEvents(range.events);
      if (versionInIntervals(version, intervals)) return true;
    }
  }
  return false;
}

/**
 * Check whether `version` is affected by a normalized NVD CVE record, using
 * the CVE's own `configurations` (cpeMatch entries with version range fields
 * or an exact version baked into the CPE 2.3 criteria string).
 */
export function isNvdVersionAffected(version, vuln, vendor, product) {
  if (!version) return null;
  const configs = vuln.rawConfigurations || [];
  if (configs.length === 0) return null;

  for (const node of configs.flatMap((c) => c.nodes || [])) {
    for (const match of node.cpeMatch || []) {
      if (match.vulnerable === false) continue;
      const parts = (match.criteria || "").split(":");
      // cpe:2.3:a:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
      const mVendor = parts[3];
      const mProduct = parts[4];
      const mVersion = parts[5];
      if (mVendor !== vendor || mProduct !== product) continue;

      if (mVersion && mVersion !== "*" && mVersion !== "-") {
        if (compareVersions(version, mVersion) === 0) return true;
        continue;
      }

      let ok = true;
      if (match.versionStartIncluding && compareVersions(version, match.versionStartIncluding) < 0) ok = false;
      if (match.versionStartExcluding && compareVersions(version, match.versionStartExcluding) <= 0) ok = false;
      if (match.versionEndIncluding && compareVersions(version, match.versionEndIncluding) > 0) ok = false;
      if (match.versionEndExcluding && compareVersions(version, match.versionEndExcluding) >= 0) ok = false;
      if (ok) return true;
    }
  }
  return false;
}
