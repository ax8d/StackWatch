/**
 * Analyzes response headers for common security-hygiene signals. This is
 * independent of the CVE matching pipeline — it's about server *configuration*
 * rather than known vulnerable *software versions*, but both feed the same
 * risk score and give the popup's "Headers" tab real content (in the same
 * spirit as a findings/signals list, with its own severity tags).
 */

export function analyzeHeaders(headers, isHttps) {
  const signals = [];
  const h = headers || {};

  const csp = h["content-security-policy"];
  signals.push(
    csp
      ? { id: "csp", severity: "info", status: "present", title: "Content-Security-Policy present", detail: truncate(csp, 140) }
      : { id: "csp", severity: "medium", status: "missing", title: "Missing Content-Security-Policy", detail: "No CSP header — increases impact of any XSS found on this site." }
  );

  const hsts = h["strict-transport-security"];
  if (isHttps) {
    signals.push(
      hsts
        ? { id: "hsts", severity: "info", status: "present", title: "Strict-Transport-Security present", detail: truncate(hsts, 140) }
        : { id: "hsts", severity: "medium", status: "missing", title: "Missing Strict-Transport-Security", detail: "HTTPS site with no HSTS — vulnerable to protocol-downgrade / SSL-stripping attacks on first visit." }
    );
  }

  const xfo = h["x-frame-options"];
  const cspHasFrameAncestors = csp && /frame-ancestors/i.test(csp);
  signals.push(
    xfo || cspHasFrameAncestors
      ? { id: "xfo", severity: "info", status: "present", title: "Clickjacking protection present", detail: xfo ? `X-Frame-Options: ${xfo}` : "CSP frame-ancestors directive present" }
      : { id: "xfo", severity: "low", status: "missing", title: "Missing clickjacking protection", detail: "No X-Frame-Options or CSP frame-ancestors — page can be framed by other sites." }
  );

  const xcto = h["x-content-type-options"];
  signals.push(
    xcto
      ? { id: "xcto", severity: "info", status: "present", title: "X-Content-Type-Options present", detail: xcto }
      : { id: "xcto", severity: "low", status: "missing", title: "Missing X-Content-Type-Options", detail: "Browsers may MIME-sniff responses, enabling some content-injection attacks." }
  );

  const acao = h["access-control-allow-origin"];
  if (acao) {
    signals.push(
      acao.trim() === "*"
        ? { id: "cors", severity: "high", status: "present", title: "CORS Access-Control-Allow-Origin: *", detail: "Cross-origin reads possible from any site — verify no sensitive data is returned here." }
        : { id: "cors", severity: "info", status: "present", title: "CORS restricted", detail: `Access-Control-Allow-Origin: ${truncate(acao, 80)}` }
    );
  }

  const rp = h["referrer-policy"];
  signals.push(
    rp
      ? { id: "referrer", severity: "info", status: "present", title: "Referrer-Policy present", detail: rp }
      : { id: "referrer", severity: "low", status: "missing", title: "Missing Referrer-Policy", detail: "Full URLs (possibly with sensitive query params) may leak to third parties via the Referer header." }
  );

  return signals;
}

function truncate(str, n) {
  if (!str) return "";
  return str.length > n ? str.slice(0, n) + "…" : str;
}
