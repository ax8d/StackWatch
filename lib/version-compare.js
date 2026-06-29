/**
 * Minimal version comparator for dotted version strings like "1.2.3", "2.1",
 * "5.1.3-beta.1". Not a full semver implementation (no build-metadata rules,
 * no semver-exact precedence edge cases) but handles the overwhelming
 * majority of real-world version strings we'll see from CDNs, headers, and
 * vulnerability database range fields.
 */

function parseVersion(v) {
  const str = String(v).trim();
  const [main, pre] = str.split("-");
  const parts = main.split(".").map((p) => {
    const n = parseInt(p, 10);
    return isNaN(n) ? 0 : n;
  });
  return { parts, pre: pre || null };
}

/** Returns -1 if a < b, 0 if equal, 1 if a > b. */
export function compareVersions(a, b) {
  if (a === b) return 0;
  if (a === "0" || a === 0) return b === "0" ? 0 : -1;

  const pa = parseVersion(a);
  const pb = parseVersion(b);
  const len = Math.max(pa.parts.length, pb.parts.length);

  for (let i = 0; i < len; i++) {
    const x = pa.parts[i] || 0;
    const y = pb.parts[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }

  // Numeric parts equal — a prerelease is considered lower than the plain release.
  if (pa.pre && !pb.pre) return -1;
  if (!pa.pre && pb.pre) return 1;
  if (pa.pre && pb.pre) return pa.pre < pb.pre ? -1 : pa.pre > pb.pre ? 1 : 0;
  return 0;
}

export function versionLt(a, b) { return compareVersions(a, b) < 0; }
export function versionLte(a, b) { return compareVersions(a, b) <= 0; }
export function versionGt(a, b) { return compareVersions(a, b) > 0; }
export function versionGte(a, b) { return compareVersions(a, b) >= 0; }
export function versionEq(a, b) { return compareVersions(a, b) === 0; }
