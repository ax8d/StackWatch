/**
 * Extracts "what version fixes this" from the same range data version-match.js
 * uses to confirm a finding. This is the constructive analog of "how to
 * exploit it" — concrete, defensive, and derived entirely from data we
 * already have, not authored advice.
 */

export function suggestFixedVersionOsv(vuln) {
  for (const entry of vuln.rawAffected || []) {
    for (const range of entry.ranges || []) {
      for (const ev of range.events || []) {
        if ("fixed" in ev) return ev.fixed;
      }
    }
  }
  return null;
}

export function suggestFixedVersionNvd(vuln, vendor, product) {
  for (const node of (vuln.rawConfigurations || []).flatMap((c) => c.nodes || [])) {
    for (const match of node.cpeMatch || []) {
      const parts = (match.criteria || "").split(":");
      if (parts[3] !== vendor || parts[4] !== product) continue;
      if (match.versionEndExcluding) return match.versionEndExcluding;
      if (match.versionEndIncluding) return `${match.versionEndIncluding} (patch within this version)`;
    }
  }
  return null;
}
