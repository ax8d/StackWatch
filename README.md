<div align="center">

<img src="assets/banner.svg" width="100%" alt="StackWatch banner"/>

<br/>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=2800&pause=900&color=FF8A00&center=true&vCenter=true&width=720&lines=Detects+frameworks%2C+libraries+%26+CDNs+on+any+site...;Matches+exact+versions+against+real+CVEs...;OSV.dev+%2B+NVD+%E2%80%94+deduped%2C+scored%2C+actionable...;Wappalyzer-style+UI%2C+real+brand+icons%2C+zero+noise." alt="Typing SVG"/>

<br/><br/>

[![Manifest](https://img.shields.io/badge/MANIFEST-V3-FF8A00?style=for-the-badge&logo=googlechrome&logoColor=white&labelColor=1a1a1a)](#)
[![Signatures](https://img.shields.io/badge/SIGNATURES-75-FF9A3D?style=for-the-badge&labelColor=1a1a1a)](#)
[![CVE Sources](https://img.shields.io/badge/CVE_SOURCES-OSV.dev%20%7C%20NVD-FF5E00?style=for-the-badge&labelColor=1a1a1a)](#)
[![License](https://img.shields.io/badge/LICENSE-MIT-FFB347?style=for-the-badge&labelColor=1a1a1a)](#)

</div>

<img src="assets/divider.svg" width="100%"/>

## 🟧 What is StackWatch?

**StackWatch** is a Chrome extension (Manifest V3) that fingerprints the frontend and backend technologies running on any site — Wappalyzer-style, grouped by category, with real brand icons — and cross-checks the **exact detected version** of each against known CVEs via **OSV.dev** and **NVD**. Results are deduplicated, scored, and shipped with remediation guidance.

No guessing. No flat lists of "this site uses React." A version, a CVE, a fix.

<img src="assets/divider.svg" width="100%"/>

## ✨ Features

<table>
<tr>
<td width="33%" valign="top">

### 🔍 Detection
- Script / HTML / meta / global-variable regex
- **DOM & CSS-selector matching** (new)
- Stylesheet content scan (`--tw-*` vars, etc.)
- Header & cookie fingerprinting
- CDN-URL inference
- Active probing (optional)

</td>
<td width="33%" valign="top">

### 🛡️ Vulnerability Intel
- OSV.dev + NVD lookups, cached per product
- Local version-range matching
- CVE dedup + near-duplicate grouping
- CVSS v3.1 scoring from vector strings
- Remediation: suggested fixed version

</td>
<td width="33%" valign="top">

### 🎨 Experience
- Real brand icons (Simple Icons CDN)
- Clean glass-card popup UI
- Badge shows **confirmed vuln count only**
- Headers tab (CSP / HSTS / CORS analysis)
- Survives MV3 service-worker restarts

</td>
</tr>
</table>

<img src="assets/divider.svg" width="100%"/>

## 🆕 What's New in v2.0

<details>
<summary><b>🩹 Fixed — cached / already-open tabs showing nothing</b></summary>
<br/>

**Root cause:** MV3 service workers are ephemeral. Chrome kills them after ~30s idle, wiping the in-memory `Map` that held per-tab results. Tabs already open before the extension loaded — or restored from back/forward cache — never re-trigger the content script, so the popup found no state and told you to reload.

**Fix:**
- Per-tab state now lives in `chrome.storage.session`, surviving worker restarts for the whole browser session.
- When the popup opens and finds *no* state for the current tab, the service worker **actively re-injects** `content/detector.js` via `chrome.scripting.executeScript` — the same trick Wappalyzer uses.
- If no response headers were captured either, a one-off background `fetch()` of the page kicks in as a fallback, so header-based detection (`Server`, `X-Powered-By`, CDN headers) still works.

> [!IMPORTANT]
> `fetch()` can't read `Set-Cookie` for security reasons — cookie-based fingerprinting only fires from a real page-load detection, not this on-demand path. Documented, not hidden.

</details>

<details>
<summary><b>🧩 New detection method — DOM/CSS-selector matching</b></summary>
<br/>

Researched Wappalyzer's own technology schema. The big gap: **checking whether a CSS selector matches anything on the page** — one of its most-used signal types, and something StackWatch didn't do at all before (it only checked script URLs, globals, meta tags, and raw HTML regex).

Added it, plus a stylesheet-content scan for frameworks like **Tailwind** that compile away any fixed class namespace but still leave distinctive `--tw-*` CSS custom properties behind.

**Unlocks:** Video.js, Lucide, Material / Bootstrap / Feather icon libraries, Tailwind CSS, Framer Motion (best-effort), Priority Hints, Next.js (now also via `next-head-count`, not just `__NEXT_DATA__`), Nuxt, Gatsby, Astro, Svelte/SvelteKit.

**Signature count: 36 → 75.**

> [!NOTE]
> Wappalyzer can sometimes show an exact Next.js patch version. The precise client-side mechanism for that isn't reliable in production builds, so StackWatch detects Next.js reliably but won't always surface that exact patch number — said so rather than faking it.

</details>

<details>
<summary><b>🖼️ Real component icons</b></summary>
<br/>

Pixel-art badges are gone. Icons now come from the **Simple Icons CDN** (`cdn.simpleicons.org/<slug>`) — actual brand logos. Coverage isn't 1:1 for 75+ signatures, so every icon has an `onerror` fallback to a clean line-icon glyph per category instead of a broken image.

> [!NOTE]
> Requires internet access to load. Offline, you'll see the line-icon fallback throughout — intentional graceful degradation, not a bug.

</details>

<details>
<summary><b>🔇 Badge noise fixed</b></summary>
<br/>

The toolbar badge used to show the 0–100 risk score even with zero actual vulnerabilities — missing security headers alone could push that number up and make a clean site look like a pile of problems.

The badge now shows **only the count of confirmed vulnerable components**, and shows nothing at all when that count is zero.

</details>

<details>
<summary><b>🎨 New theme</b></summary>
<br/>

Full pivot away from the pixel/terminal look: white/soft-gray background, indigo brand accent, rounded-2xl cards with soft shadows, pill badges and buttons, a subtle gradient blob behind the header mark. Monospace is now reserved for actual data (CVE IDs, versions, hostname) rather than the whole UI.

> [!NOTE]
> The three Dribbble references couldn't be loaded directly (JS-rendered shot pages, nothing exposed to `fetch`), so this was built from the genre they're clearly part of — clean light fintech/AI-SaaS — rather than a pixel-accurate copy of any one of them.

</details>

<details>
<summary><b>🐛 CVE dedup bug — fixed</b></summary>
<br/>

A dedup step had been dropped in an earlier revision, so the same CVE could appear more than once when OSV returns overlapping advisory records for it.

- Re-added: `lib/dedupe.js`
- Added: near-duplicate advisory grouping (different CVE IDs, same underlying issue — common with incomplete-fix follow-ups), collapsing into one expandable card instead of flat-listing as repeats.

</details>

<img src="assets/divider.svg" width="100%"/>

## 🚀 Install

```bash
1. Open chrome://extensions
2. Enable Developer mode (top-right toggle)
3. Click "Load unpacked"
4. Select this project folder
```

Then open the popup's **⚙ Settings**:
- Add an NVD API key (click **Show** to verify what you typed)
- Toggle **active probing** on/off

<img src="assets/divider.svg" width="100%"/>

## 🏗️ Architecture

```
content/detector.js       passive detection: script/html/meta/global regex,
                           DOM-selector existence, stylesheet content scan.
                           Re-injectable on demand.

background/service-worker.js
  ├─ chrome.storage.session-backed per-tab state (survives worker restarts)
  ├─ on-demand rescan via chrome.scripting.executeScript
  ├─ header/cookie/CDN-URL detection, active probing, comment sniffing
  ├─ CVE lookup (cached per-product), local version-range matching,
  │  dedup + remediation + scoring
  └─ badge: confirmed-vulnerability count only

lib/
  ├─ signatures.js        75 signatures, incl. dom/cssVarScan methods
  ├─ tech-icons.js         Simple Icons CDN mapping + line-icon fallback
  ├─ dedupe.js              dedupeByCveId() + groupNearDuplicates()
  ├─ remediation.js         suggestFixedVersionOsv/Nvd()
  ├─ version-match.js      local version-range matching (confirmed vs unconfirmed)
  ├─ cvss.js                CVSS v3.1 score calculator from a vector string
  ├─ osv-client.js          full per-product vuln list, cached
  ├─ nvd-client.js          full per-product vuln list, cached
  ├─ header-signals.js     CSP / HSTS / CORS / etc. analysis
  ├─ score.js               risk score + rubric-bar breakdown
  └─ cache.js                chrome.storage.local cache

popup/
  ├─ Overview
  ├─ Stack            (Wappalyzer-style grid, real icons)
  ├─ Vulnerabilities  (grouped CVEs + fix guidance)
  └─ Headers
```

<img src="assets/divider.svg" width="100%"/>

## ⚠️ Known Limitations

> [!WARNING]
> **Cookie fingerprinting on re-injected tabs.** On-demand rescans (the cached-tab fix) can't see `Set-Cookie` — cookie-fingerprinted frameworks (Django, Laravel, Rails, etc.) only resolve from a real page-load detection.

> [!WARNING]
> **Near-duplicate advisory grouping is heuristic** (word-overlap, not exact) — it can occasionally under- or over-cluster. Nothing is hidden, only grouped for display.

> [!NOTE]
> NVD pagination caps at 100 results/product. CDN-inferred packages are a best-effort name guess. A "vulnerable version" doesn't mean "exploitable in practice" — treat confirmed findings as **needs review**, not a verdict.

> [!NOTE]
> Icon coverage is best-effort for less-common packages; unmapped or failed icons fall back to a category glyph rather than breaking.

> [!CAUTION]
> No exploitation walkthroughs, by design. See the in-app **References** (NVD/OSV's own labeled links) and the **Fix-available** line instead.

<img src="assets/divider.svg" width="100%"/>

<div align="center">

### Made with 🟧 and a healthy distrust of `package.json`

<sub>Detection &nbsp;•&nbsp; Versioning &nbsp;•&nbsp; CVEs &nbsp;•&nbsp; Remediation — no guessing in between.</sub>

</div>
