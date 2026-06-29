import { getTechIconUrl, getCategoryGlyphSvg } from "../lib/tech-icons.js";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
let currentState = null;
let activeSeverities = new Set(SEVERITY_ORDER);
let activeTab = "overview";

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  document.getElementById("sw-hostname").textContent = safeHostname(tab.url);

  document.getElementById("sw-options-btn").addEventListener("click", () => chrome.runtime.openOptionsPage());
  document.getElementById("sw-rescan-btn").addEventListener("click", onRescan);
  document.getElementById("sw-export-btn").addEventListener("click", onExport);
  document.getElementById("sw-copy-btn").addEventListener("click", onCopySummary);

  document.querySelectorAll(".sw-tab").forEach((btn) => btn.addEventListener("click", () => switchTab(btn.dataset.tab)));
  document.querySelectorAll(".sw-pill").forEach((btn) => btn.addEventListener("click", () => togglePill(btn)));

  setLiveStatus("scanning", "scanning…");
  poll();
}

function safeHostname(url) {
  try { return new URL(url).hostname; } catch { return url || "—"; }
}

let pollCount = 0;
function poll() {
  chrome.runtime.sendMessage({ type: "STACKWATCH_GET_TAB_RESULTS" }, (state) => {
    pollCount++;
    if (!state) {
      setStatus("No data yet — try reloading the page.");
      if (pollCount < 15) setTimeout(poll, 400);
      return;
    }
    if (!state.status || state.status === "detecting") {
      setStatus("Detecting technologies…");
      if (pollCount < 30) setTimeout(poll, 400);
      return;
    }
    if (state.status === "looking_up_cves") {
      setStatus(`Checking ${state.passiveDetected?.length || 0} component(s) against CVE databases…`);
      if (pollCount < 50) setTimeout(poll, 500);
      return;
    }
    if (state.status === "done") {
      hideStatus();
      currentState = state;
      renderAll();
      setLiveStatus("done", "done");
    }
  });
}

function setStatus(text) {
  const el = document.getElementById("sw-status");
  el.classList.remove("hidden");
  el.textContent = text;
}
function hideStatus() { document.getElementById("sw-status").classList.add("hidden"); }

function setLiveStatus(mode, text) {
  document.getElementById("sw-live-dot").className = `sw-live-dot ${mode}`;
  document.getElementById("sw-live-text").textContent = text;
}

function onRescan() {
  setLiveStatus("scanning", "rescanning…");
  for (const id of ["panel-overview", "panel-stack", "panel-vulns", "panel-headers"]) {
    document.getElementById(id).innerHTML = "";
  }
  setStatus("Rescanning…");
  pollCount = 0;
  chrome.runtime.sendMessage({ type: "STACKWATCH_RESCAN" }, () => setTimeout(poll, 800));
}

/* ---------------- Tabs & severity pills ---------------- */

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll(".sw-tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".sw-tabpanel").forEach((p) => p.classList.toggle("hidden", p.id !== `panel-${tab}`));
  document.getElementById("sw-pills").classList.toggle("hidden", tab !== "vulns" && tab !== "headers");
  document.getElementById("sw-content").scrollTop = 0;
}

function togglePill(btn) {
  const sev = btn.dataset.sev;
  if (activeSeverities.has(sev)) { activeSeverities.delete(sev); btn.classList.remove("active"); }
  else { activeSeverities.add(sev); btn.classList.add("active"); }
  if (currentState) {
    renderVulnerabilities(currentState.results || []);
    renderHeaders(currentState.headerSignals || []);
  }
}

function classifySeverity(sev) {
  return SEVERITY_ORDER.includes(sev) ? sev : "info";
}

/* ---------------- Icon rendering ---------------- */

/** Builds a small icon chip: tries the real brand icon first, falls back to a clean line glyph on load error. */
function buildIconChip(id, category, sizeClass) {
  const wrap = document.createElement("span");
  wrap.className = sizeClass;
  const url = getTechIconUrl(id);

  if (url) {
    const img = document.createElement("img");
    img.src = url;
    img.alt = "";
    img.loading = "lazy";
    img.onerror = () => { wrap.innerHTML = getCategoryGlyphSvg(category, "#93908C", 16); };
    wrap.appendChild(img);
  } else {
    wrap.innerHTML = getCategoryGlyphSvg(category, "#93908C", 16);
  }
  return wrap;
}

/* ---------------- Top-level render ---------------- */

function renderAll() {
  renderHero(currentState.score);
  renderCategories(currentState.score.categories);
  renderOverview(currentState);
  renderStack(currentState.results || []);
  renderVulnerabilities(currentState.results || []);
  renderHeaders(currentState.headerSignals || []);
  switchTab(activeTab);
}

function renderHero(score) {
  document.getElementById("sw-score-number").textContent = score.total;
  document.getElementById("sw-score-tier").textContent = score.tier.label;
  renderStackCore(currentState.results || []);
}

function renderStackCore(results) {
  const container = document.getElementById("sw-stackcore");
  container.innerHTML = "";

  if (results.length === 0) {
    container.innerHTML = `<div class="sw-core-segment sw-sev-safe"><span class="sw-core-label">none</span></div>`;
    return;
  }

  const priority = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...results].sort((a, b) => (priority[a.worstSeverity] ?? 4) - (priority[b.worstSeverity] ?? 4));
  const shown = sorted.slice(0, 9);
  const remainder = sorted.length - shown.length;

  for (const r of shown) {
    const seg = document.createElement("div");
    let sevClass = "sw-sev-safe";
    if (["critical", "high", "medium", "low"].includes(r.worstSeverity)) sevClass = `sw-sev-${r.worstSeverity}`;
    else if ((r.unconfirmedVulnerabilities || []).length > 0) sevClass = "sw-sev-unconfirmed";
    seg.className = `sw-core-segment ${sevClass}`;
    seg.title = `${r.name} (${r.category})${r.version ? " · v" + r.version : " · version unknown"}`;
    seg.innerHTML = `<span class="sw-core-label">${escapeHtml(r.name)}</span>`;
    seg.addEventListener("click", () => jumpToComponent(r.id));
    container.appendChild(seg);
  }
  if (remainder > 0) {
    const more = document.createElement("div");
    more.className = "sw-core-segment sw-core-more";
    more.textContent = `+${remainder}`;
    more.title = `${remainder} more in the Stack tab`;
    more.addEventListener("click", () => switchTab("stack"));
    container.appendChild(more);
  }
}

function jumpToComponent(id) {
  switchTab("vulns");
  requestAnimationFrame(() => {
    const card = document.getElementById(`comp-card-${cssEscape(id)}`);
    if (card) { card.classList.add("expanded"); card.scrollIntoView({ block: "start" }); }
  });
}

function renderCategories(categories) {
  const colorMap = {
    vulnerableComponents: "var(--critical)",
    unconfirmedExposure: "var(--medium)",
    securityHeaders: "var(--low)",
    supplyChainSurface: "var(--brand)",
    techStackBreadth: "var(--bar-neutral)"
  };
  const container = document.getElementById("sw-categories");
  container.innerHTML = categories.map((c) => `
    <div class="sw-cat-row">
      <div class="sw-cat-label">${escapeHtml(c.label)}</div>
      <div class="sw-cat-track"><div class="sw-cat-fill" style="width:${(c.value / c.max) * 100}%; background:${colorMap[c.key] || "var(--brand)"}"></div></div>
      <div class="sw-cat-frac">${Math.round(c.value)}/${c.max}</div>
    </div>
  `).join("");
}

/* ---------------- Overview tab ---------------- */

function renderOverview(state) {
  const { results, score } = state;
  const groupCount = results.reduce((sum, r) => sum + (r.vulnerabilityGroups || []).length, 0);
  const rawCveCount = results.reduce((sum, r) => sum + (r.vulnerabilities || []).length, 0);
  const unconfirmedCount = score.counts.unconfirmedComponents;
  const missingHeaders = score.counts.missingHeaders;

  let narrative;
  if (groupCount === 0) {
    narrative = `No confirmed vulnerabilities for the versions detected on this page (${results.length} component(s) checked).`;
  } else {
    const cveNote = rawCveCount > groupCount ? ` (${rawCveCount} CVE entries, grouped)` : "";
    narrative = `<strong>${groupCount} confirmed security issue${groupCount === 1 ? "" : "s"}</strong> matched to the exact versions detected on this page${cveNote}.`;
  }
  if (unconfirmedCount > 0) narrative += ` ${unconfirmedCount} component(s) have an undetected version — see the Vulnerabilities tab.`;
  if (missingHeaders > 0) narrative += ` ${missingHeaders} recommended security header(s) missing — see Headers.`;

  const panel = document.getElementById("panel-overview");
  panel.innerHTML = `<div class="sw-overview-line">${narrative}</div>`;

  const topGroups = results
    .flatMap((r) => (r.vulnerabilityGroups || []).map((g) => ({ ...g, componentName: r.name })))
    .sort((a, b) => (b.primary.cvssScore || 0) - (a.primary.cvssScore || 0))
    .slice(0, 3);

  for (const g of topGroups) panel.appendChild(buildFindingGroupItem(g, g.componentName));
}

/* ---------------- Stack tab ---------------- */

function renderStack(results) {
  const panel = document.getElementById("panel-stack");
  panel.innerHTML = "";

  if (results.length === 0) {
    panel.innerHTML = `<div class="sw-empty-state">No technologies detected on this page.</div>`;
    return;
  }

  const groups = new Map();
  for (const r of results) {
    if (!groups.has(r.category)) groups.set(r.category, []);
    groups.get(r.category).push(r);
  }

  const wrap = document.createElement("div");
  wrap.className = "sw-stack-columns";

  for (const [category, items] of groups) {
    const group = document.createElement("div");
    group.className = "sw-stack-group";
    group.innerHTML = `<div class="sw-stack-group-title">${escapeHtml(category)}</div>`;
    for (const r of items) {
      const row = document.createElement("div");
      row.className = "sw-stack-item";
      const versionClass = r.version ? "" : "unknown";
      const versionLabel = r.version ? "v" + escapeHtml(r.version) : "unknown";
      row.appendChild(buildIconChip(r.id, r.category, "sw-stack-icon"));
      const nameSpan = document.createElement("span");
      nameSpan.className = "sw-stack-name";
      nameSpan.textContent = r.name;
      const verSpan = document.createElement("span");
      verSpan.className = `sw-stack-version ${versionClass}`;
      verSpan.textContent = versionLabel;
      row.appendChild(nameSpan);
      row.appendChild(verSpan);
      row.addEventListener("click", () => jumpToComponent(r.id));
      group.appendChild(row);
    }
    wrap.appendChild(group);
  }
  panel.appendChild(wrap);
}

/* ---------------- Vulnerabilities tab ---------------- */

function renderVulnerabilities(results) {
  const panel = document.getElementById("panel-vulns");
  panel.innerHTML = "";

  const withFindings = results.filter((r) => (r.vulnerabilityGroups || []).length > 0 || (r.unconfirmedVulnerabilities || []).length > 0);

  if (withFindings.length === 0) {
    panel.innerHTML = `<div class="sw-empty-state">No vulnerabilities to report for this page.</div>`;
    return;
  }

  const sorted = [...withFindings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.worstSeverity] ?? 4) - (order[b.worstSeverity] ?? 4);
  });

  for (const r of sorted) {
    const bucket = classifySeverity(r.worstSeverity === "none" ? "info" : r.worstSeverity);
    const card = buildComponentVulnCard(r);
    card.dataset.sevBucket = bucket;
    card.style.display = activeSeverities.has(bucket) ? "" : "none";
    panel.appendChild(card);
  }
}

function buildComponentVulnCard(r) {
  const card = document.createElement("div");
  card.className = "sw-card";
  card.id = `comp-card-${cssEscape(r.id)}`;

  const groupCount = (r.vulnerabilityGroups || []).length;
  const versionLabel = r.version ? `v${escapeHtml(r.version)}` : "version unknown";

  const row = document.createElement("div");
  row.className = "sw-card-row";
  row.appendChild(buildIconChip(r.id, r.category, "sw-tech-icon"));

  const info = document.createElement("div");
  info.className = "sw-card-info";
  info.innerHTML = `
    <div class="sw-card-name">${escapeHtml(r.name)}${r.inferred ? '<span class="sw-badge-inferred" title="Auto-detected via CDN URL">auto</span>' : ""}</div>
    <div class="sw-card-meta">${escapeHtml(r.category)} · ${versionLabel}</div>
  `;
  row.appendChild(info);

  const count = document.createElement("span");
  count.className = "sw-card-count";
  count.textContent = `${groupCount} confirmed`;
  row.appendChild(count);

  const chevron = document.createElement("span");
  chevron.className = "sw-chevron";
  chevron.textContent = "▶";
  row.appendChild(chevron);

  row.addEventListener("click", () => card.classList.toggle("expanded"));
  card.appendChild(row);

  const detail = document.createElement("div");
  detail.className = "sw-card-detail";

  if (groupCount === 0) {
    detail.innerHTML = `<div class="sw-no-findings">No confirmed vulnerabilities for ${r.version ? "this version" : "any version — see below"}.</div>`;
  } else {
    for (const g of r.vulnerabilityGroups) detail.appendChild(buildFindingGroupItem(g));
  }

  const unconfirmed = r.unconfirmedVulnerabilities || [];
  if (unconfirmed.length > 0) {
    const box = document.createElement("div");
    box.className = "sw-unconfirmed-box";
    const reason = unconfirmed[0].unconfirmedReason;
    const explain = reason === "no_version_detected"
      ? `StackWatch couldn't confirm which version of ${escapeHtml(r.name)} this site is running, so these ${unconfirmed.length} CVE(s) — found for <em>some</em> version of this product — aren't shown as confirmed.`
      : `${unconfirmed.length} CVE(s) exist for ${escapeHtml(r.name)}, but the database didn't provide structured version-range data to confirm whether v${escapeHtml(r.version || "")} is affected.`;
    box.innerHTML = `<p>${explain}</p><button class="sw-reveal-btn">Show unconfirmed CVEs</button>`;
    const revealBtn = box.querySelector(".sw-reveal-btn");
    const list = document.createElement("div");
    list.className = "sw-unconfirmed-list";
    for (const g of groupNearDuplicatesClient(unconfirmed)) list.appendChild(buildFindingGroupItem(g));
    box.appendChild(list);
    revealBtn.addEventListener("click", () => {
      list.classList.toggle("revealed");
      revealBtn.textContent = list.classList.contains("revealed") ? "Hide unconfirmed CVEs" : "Show unconfirmed CVEs";
    });
    detail.appendChild(box);
  }

  card.appendChild(detail);
  return card;
}

function groupNearDuplicatesClient(vulns) {
  function words(s) {
    return new Set((s || "").toLowerCase().replace(/[^a-z\s]/g, " ").split(/\s+/).filter((w) => w.length > 2));
  }
  function jaccard(a, b) {
    if (a.size === 0 || b.size === 0) return 0;
    let inter = 0;
    for (const w of a) if (b.has(w)) inter++;
    return inter / (a.size + b.size - inter);
  }
  const items = vulns.map((v) => ({ v, w: words(v.summary) }));
  const clusters = [];
  for (const item of items) {
    let placed = false;
    for (const c of clusters) {
      if (jaccard(item.w, c[0].w) >= 0.5) { c.push(item); placed = true; break; }
    }
    if (!placed) clusters.push([item]);
  }
  return clusters.map((c) => {
    const members = c.map((x) => x.v).sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));
    return { primary: members[0], related: members.slice(1) };
  });
}

function buildFindingGroupItem(group, componentName) {
  const { primary, related } = group;
  const item = document.createElement("div");
  item.className = "sw-finding-item";

  const scoreLabel = primary.cvssScore != null ? primary.cvssScore.toFixed(1) : "N/A";
  const sevClass = ["critical", "high", "medium", "low"].includes(primary.severity) ? primary.severity : "unknown";
  const published = formatDate(primary.published);
  const modified = formatDate(primary.modified);

  item.innerHTML = `
    <div class="sw-finding-head">
      <a class="sw-finding-id" href="${cveUrl(primary.cveId)}" target="_blank" rel="noopener noreferrer">${escapeHtml(primary.cveId || primary.osvId || "Unknown ID")}</a>
      <span class="sw-finding-score ${sevClass}">${scoreLabel} · ${sevClass[0].toUpperCase() + sevClass.slice(1)}</span>
    </div>
    <div class="sw-finding-summary">${componentName ? `<strong>${escapeHtml(componentName)}</strong> — ` : ""}${escapeHtml(truncate(primary.summary, 150))}</div>
    <div class="sw-finding-dates">${published ? "Published " + published : ""}${modified ? " · Updated " + modified : ""}</div>
  `;

  if (primary.fixedVersion) {
    const fix = document.createElement("div");
    fix.className = "sw-fix-line";
    fix.textContent = `Fix available — upgrade to v${primary.fixedVersion}+`;
    item.appendChild(fix);
  }

  if (primary.references && primary.references.length > 0) {
    const refs = document.createElement("div");
    refs.className = "sw-refs-line";
    for (const ref of primary.references.slice(0, 4)) {
      const a = document.createElement("a");
      a.className = "sw-ref-link";
      a.href = ref.url;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      a.textContent = ref.label || "Reference";
      refs.appendChild(a);
    }
    item.appendChild(refs);
  }

  if (related && related.length > 0) {
    const toggle = document.createElement("button");
    toggle.className = "sw-related-toggle";
    toggle.textContent = `+${related.length} related advisor${related.length === 1 ? "y" : "ies"}`;
    const list = document.createElement("div");
    list.className = "sw-related-list";
    for (const r of related) list.appendChild(buildFindingGroupItem({ primary: r, related: [] }));
    toggle.addEventListener("click", () => {
      list.classList.toggle("revealed");
      toggle.textContent = list.classList.contains("revealed") ? "Hide related" : `+${related.length} related advisor${related.length === 1 ? "y" : "ies"}`;
    });
    item.appendChild(toggle);
    item.appendChild(list);
  }

  return item;
}

/* ---------------- Headers tab ---------------- */

function renderHeaders(signals) {
  const panel = document.getElementById("panel-headers");
  panel.innerHTML = "";

  if (!signals || signals.length === 0) {
    panel.innerHTML = `<div class="sw-empty-state">No header data captured yet.</div>`;
    return;
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...signals].sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

  for (const s of sorted) {
    const bucket = classifySeverity(s.severity);
    const card = document.createElement("div");
    card.className = "sw-card";
    card.style.display = activeSeverities.has(bucket) ? "" : "none";
    card.innerHTML = `
      <div class="sw-card-row" style="cursor:default;">
        <span class="sw-dot ${bucket === "info" ? "info" : bucket}"></span>
        <div class="sw-card-info">
          <div class="sw-card-name">${escapeHtml(s.title)}</div>
          <div class="sw-card-meta" style="font-size:11px;">${escapeHtml(s.detail)}</div>
        </div>
      </div>
    `;
    panel.appendChild(card);
  }
}

/* ---------------- Export / Copy ---------------- */

function onExport() {
  if (!currentState) return;
  const report = {
    url: currentState.url,
    generatedAt: new Date().toISOString(),
    riskScore: currentState.score.total,
    riskTier: currentState.score.tier.label,
    components: (currentState.results || []).map((r) => ({
      name: r.name,
      category: r.category,
      version: r.version,
      confirmedVulnerabilities: (r.vulnerabilities || []).map((v) => ({ id: v.cveId, severity: v.severity, cvssScore: v.cvssScore, summary: v.summary, fixedVersion: v.fixedVersion || null })),
      unconfirmedVulnerabilityCount: (r.unconfirmedVulnerabilities || []).length
    })),
    securityHeaders: currentState.headerSignals || []
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `stackwatch-${safeHostname(currentState.url)}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function onCopySummary() {
  if (!currentState) return;
  const confirmed = (currentState.results || []).flatMap((r) => (r.vulnerabilities || []).map((v) => `- [${v.severity.toUpperCase()}] ${v.cveId} — ${r.name} v${r.version || "?"}${v.fixedVersion ? ` (fix: v${v.fixedVersion}+)` : ""}`));
  const unknownVersions = (currentState.results || []).filter((r) => !r.version).map((r) => r.name);
  const missingHeaders = (currentState.headerSignals || []).filter((h) => h.status === "missing").map((h) => h.title);

  const lines = [
    `StackWatch scan — ${currentState.url}`,
    `Risk score: ${currentState.score.total}/100 (${currentState.score.tier.label})`,
    "",
    confirmed.length ? "Confirmed vulnerabilities:" : "No confirmed vulnerabilities for detected versions.",
    ...confirmed,
    "",
    unknownVersions.length ? `Components with undetected version (CVEs unconfirmed): ${unknownVersions.join(", ")}` : "",
    missingHeaders.length ? `Missing security headers: ${missingHeaders.join(", ")}` : ""
  ].filter(Boolean);

  navigator.clipboard.writeText(lines.join("\n")).then(() => {
    const btn = document.getElementById("sw-copy-btn");
    const original = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = original), 1500);
  });
}

/* ---------------- Helpers ---------------- */

function cveUrl(cveId) {
  if (cveId && cveId.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${cveId}`;
  return `https://osv.dev/vulnerability/${cveId}`;
}
function formatDate(iso) { if (!iso) return null; try { return new Date(iso).toISOString().slice(0, 10); } catch { return null; } }
function truncate(str, n) { if (!str) return ""; return str.length > n ? str.slice(0, n) + "…" : str; }
function escapeHtml(str) {
  if (str == null) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function cssEscape(str) { return String(str).replace(/[^a-zA-Z0-9_-]/g, "_"); }

init();
