/**
 * CVSS v3.1 base score calculator.
 *
 * OSV.dev frequently gives a CVSS *vector string* (e.g. "CVSS:3.1/AV:N/AC:L/...")
 * rather than a precomputed numeric score. Previously we just gave up and showed
 * "N/A · UNKNOWN" for every such entry — which is misleading since the data to
 * compute a real score is right there. This implements the official FIRST.org
 * CVSS v3.1 base-score formula so we can show a real number + severity bucket.
 *
 * Spec: https://www.first.org/cvss/v3.1/specification-document (section 7.4)
 * Also handles v3.0 vectors using the same formula (the v3.0/v3.1 difference is
 * a minor PR weighting change under Scope:Changed — negligible for our purposes).
 */

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 },
  I: { H: 0.56, L: 0.22, N: 0 },
  A: { H: 0.56, L: 0.22, N: 0 },
  // PR depends on Scope — handled specially below
};

const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };

function roundUp(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/**
 * Parse a CVSS vector string into a { score, severity, vector } object.
 * Returns null score (with severity "unknown") if the vector is missing,
 * malformed, or not a v3.x vector we know how to compute.
 */
export function parseCvssVector(vector) {
  if (!vector || typeof vector !== "string") return { score: null, severity: "unknown", vector: null };

  // Vector might be plain "CVSS:3.1/AV:N/..." or have a numeric score prefix in some feeds.
  const bareNumber = parseFloat(vector);
  if (!isNaN(bareNumber) && /^[0-9.]+$/.test(vector.trim())) {
    return { score: bareNumber, severity: scoreToSeverity(bareNumber), vector };
  }

  if (!vector.startsWith("CVSS:3")) {
    return { score: null, severity: "unknown", vector };
  }

  const metrics = {};
  for (const part of vector.split("/")) {
    const [key, val] = part.split(":");
    if (key && val) metrics[key] = val;
  }

  const { AV, AC, PR, UI, S, C, I, A } = metrics;
  if (!AV || !AC || !PR || !UI || !S || !C || !I || !A) {
    return { score: null, severity: "unknown", vector };
  }

  try {
    const avW = WEIGHTS.AV[AV];
    const acW = WEIGHTS.AC[AC];
    const uiW = WEIGHTS.UI[UI];
    const cW = WEIGHTS.C[C];
    const iW = WEIGHTS.I[I];
    const aW = WEIGHTS.A[A];
    const scopeChanged = S === "C";
    const prW = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[PR];

    if ([avW, acW, uiW, cW, iW, aW, prW].some((v) => v === undefined)) {
      return { score: null, severity: "unknown", vector };
    }

    const iscBase = 1 - (1 - cW) * (1 - iW) * (1 - aW);
    const isc = scopeChanged
      ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
      : 6.42 * iscBase;

    const exploitability = 8.22 * avW * acW * prW * uiW;

    let base;
    if (isc <= 0) {
      base = 0;
    } else {
      base = scopeChanged
        ? roundUp(Math.min(1.08 * (isc + exploitability), 10))
        : roundUp(Math.min(isc + exploitability, 10));
    }

    return { score: base, severity: scoreToSeverity(base), vector };
  } catch {
    return { score: null, severity: "unknown", vector };
  }
}

export function scoreToSeverity(score) {
  if (score == null) return "unknown";
  if (score === 0) return "none";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}
