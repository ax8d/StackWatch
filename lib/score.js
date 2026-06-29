/**
 * Computes the 0-100 risk score and its category breakdown, shown as the
 * gauge + rubric bars in the popup. Categories are specific to a tech/CVE
 * scanner (not copied from any other tool's rubric) but follow the same
 * "weighted bars summing to a total" pattern.
 */

const WEIGHTS = {
  vulnerableComponents: 40,
  unconfirmedExposure: 20,
  securityHeaders: 20,
  supplyChainSurface: 10,
  techStackBreadth: 10
};

export function computeScore(results, headerSignals, cdnAssetCount) {
  let critical = 0, high = 0, medium = 0, low = 0;
  let unconfirmedComponents = 0;

  for (const r of results) {
    for (const v of r.vulnerabilities || []) {
      if (v.severity === "critical") critical++;
      else if (v.severity === "high") high++;
      else if (v.severity === "medium") medium++;
      else if (v.severity === "low") low++;
    }
    if ((r.unconfirmedVulnerabilities || []).length > 0) unconfirmedComponents++;
  }

  const missingHeaders = (headerSignals || []).filter((h) => h.status === "missing").length;

  const vulnerableComponentsScore = Math.min(
    WEIGHTS.vulnerableComponents,
    critical * 14 + high * 7 + medium * 3 + low * 1
  );
  const unconfirmedExposureScore = Math.min(WEIGHTS.unconfirmedExposure, unconfirmedComponents * 5);
  const securityHeadersScore = Math.min(WEIGHTS.securityHeaders, missingHeaders * 4);
  const supplyChainSurfaceScore = Math.min(WEIGHTS.supplyChainSurface, cdnAssetCount || 0);
  const techStackBreadthScore = Math.min(WEIGHTS.techStackBreadth, results.length);

  const total = Math.round(
    vulnerableComponentsScore +
    unconfirmedExposureScore +
    securityHeadersScore +
    supplyChainSurfaceScore +
    techStackBreadthScore
  );

  return {
    total,
    tier: scoreTier(total),
    categories: [
      { key: "vulnerableComponents", label: "Vulnerable Components", value: vulnerableComponentsScore, max: WEIGHTS.vulnerableComponents },
      { key: "unconfirmedExposure", label: "Unconfirmed Components", value: unconfirmedExposureScore, max: WEIGHTS.unconfirmedExposure },
      { key: "securityHeaders", label: "Security Headers", value: securityHeadersScore, max: WEIGHTS.securityHeaders },
      { key: "supplyChainSurface", label: "Supply Chain Surface", value: supplyChainSurfaceScore, max: WEIGHTS.supplyChainSurface },
      { key: "techStackBreadth", label: "Tech Stack Breadth", value: techStackBreadthScore, max: WEIGHTS.techStackBreadth }
    ],
    counts: { critical, high, medium, low, unconfirmedComponents, missingHeaders }
  };
}

function scoreTier(total) {
  if (total <= 15) return { label: "MINIMAL EXPOSURE", colorVar: "--safe" };
  if (total <= 35) return { label: "LOW EXPOSURE", colorVar: "--low" };
  if (total <= 55) return { label: "MODERATE EXPOSURE", colorVar: "--medium" };
  if (total <= 75) return { label: "ELEVATED EXPOSURE", colorVar: "--high" };
  return { label: "CRITICAL EXPOSURE", colorVar: "--critical" };
}
