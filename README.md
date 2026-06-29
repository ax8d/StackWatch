# StackWatch — Tech & Vulnerability Scanner

A Chrome extension (Manifest V3) that detects frontend/backend technologies
on a site (Wappalyzer-style, grouped by category, with real brand icons)
and checks them against known CVEs via OSV.dev and NVD — matched to the
specific version detected, deduplicated, with remediation guidance.

## What changed in v2.0

### 1. Fixed: cached/already-open tabs showing nothing

**Root cause**: MV3 service workers are ephemeral — Chrome kills this one
after ~30s of inactivity, wiping whatever was in the in-memory `Map` that
held per-tab results. A tab that was already open before the extension
loaded (or one Chrome restored from back/forward cache) never re-triggers
the content script, so there was nothing to repopulate that Map. Result:
the popup found no state and told you to reload.

**Fix**: per-tab state now lives in `chrome.storage.session`, which
survives worker restarts for the life of the browser session. On top of
that, when the popup opens and finds *no* state at all for the current
tab, `background/service-worker.js` now actively re-injects
`content/detector.js` via `chrome.scripting.executeScript` right then —
the same thing Wappalyzer does to show results instantly on a tab you
didn't just navigate to. If no response headers were ever captured either,
it also does a one-off background `fetch()` of the page as a fallback so
header-based detection (Server, X-Powered-By, CDN headers) still works.
The one gap: `fetch()` cannot read `Set-Cookie` for security reasons, so
cookie-based fingerprinting only fires from a real page-load detection,
not this on-demand path — documented, not hidden.

### 2. Detection breadth — added the method we were missing entirely

Researched what Wappalyzer's own technology schema actually uses. The big
gap: **DOM/CSS-selector detection** — checking whether a CSS selector
matches anything on the page — which is one of Wappalyzer's most-used
signal types and something this extension didn't do at all before (it only
checked script URLs, globals, meta tags, and raw HTML regex). Added it,
plus a stylesheet-content scan for things like Tailwind that compile away
any fixed class namespace but still leave distinctive `--tw-*` CSS custom
properties behind.

New signatures this unlocks, matching your screenshot's gap directly:
Video.js, Lucide, Material/Bootstrap/Feather icon libraries, Tailwind CSS,
Framer Motion (best-effort), Priority Hints, Next.js (now also via its
`next-head-count` meta tag, not just `__NEXT_DATA__`), Nuxt, Gatsby, Astro,
Svelte/SvelteKit. Signature count: 36 → 75.

One honesty note: Wappalyzer showed an exact Next.js patch version
(15.5.15) in your screenshot. I couldn't confirm the precise mechanism it
uses for that — Next.js doesn't reliably expose its own semver client-side
in production builds — so StackWatch detects Next.js reliably but won't
always surface that exact patch number. Said so rather than faking it.

### 3. Real component icons

Pixel-art badges are gone. Icons now come from the Simple Icons CDN
(`cdn.simpleicons.org/<slug>`) — actual brand logos, the same kind of
source Wappalyzer-style tools use. Coverage isn't 1:1 for 75+ signatures
(some slugs in `lib/tech-icons.js` are best-effort), so every icon has an
`onerror` fallback to a small clean line-icon glyph per category rather
than a broken image. Requires internet access to load; offline, you'll see
the line-icon fallback throughout (intentional graceful degradation, not a
bug).

### 4. Badge noise fixed

The toolbar badge was showing the 0-100 risk score as its number even when
there were zero actual vulnerabilities — missing security headers alone
could push that number up and make it look like a pile of problems. The
badge now shows only the count of confirmed vulnerable components, and
shows nothing at all when that count is zero.

### 5. New theme

Full pivot away from the pixel/terminal look: white/soft-gray background,
indigo brand accent, rounded-2xl cards with soft shadows, pill badges and
buttons, a subtle gradient blob behind the header mark. Monospace is now
reserved for actual data (CVE IDs, versions, hostname) rather than the
whole UI. I couldn't load the three Dribbble references directly (their
shot pages are JS-rendered with nothing exposed to fetch), so this is built
from the genre they're clearly part of — clean light fintech/AI-SaaS —
rather than a pixel-accurate copy of any one of them.

### Also: CVE dedup bug

Separately from the design ask — a dedup step had been dropped in an
earlier revision, so the same CVE could show up more than once when OSV
returns overlapping advisory records for it. Re-added (`lib/dedupe.js`),
plus near-duplicate advisory grouping (different CVE IDs, same underlying
issue — common with incomplete-fix follow-ups) so those collapse into one
expandable card instead of flat-listing as repeats.

## Install

`chrome://extensions` → enable Developer mode → Load unpacked → select this
folder. Settings (⚙ in the popup): add an NVD key (click Show to verify
what you typed) and toggle active probing.

## Architecture

```
content/detector.js     passive detection: script/html/meta/global regex,
                         DOM-selector existence, stylesheet content scan.
                         Re-injectable on demand (see fix #1 above).

background/service-worker.js
  - chrome.storage.session-backed per-tab state (survives worker restarts)
  - on-demand rescan via chrome.scripting.executeScript
  - header/cookie/CDN-URL detection, active probing, comment sniffing
  - CVE lookup (cached per-product), local version-range matching,
    dedup + remediation + scoring
  - badge: confirmed-vulnerability count only

lib/
  signatures.js        75 signatures, now including dom/cssVarScan methods
  tech-icons.js          Simple Icons CDN mapping + line-icon fallback (new)
  dedupe.js               dedupeByCveId() + groupNearDuplicates()
  remediation.js          suggestFixedVersionOsv/Nvd()
  version-match.js      local version-range matching (confirmed vs unconfirmed)
  cvss.js                CVSS v3.1 score calculator from a vector string
  osv-client.js / nvd-client.js   full per-product vuln lists, cached
  header-signals.js     CSP/HSTS/CORS/etc. analysis
  score.js               risk score + rubric-bar breakdown
  cache.js                chrome.storage.local cache

popup/   Overview / Stack (Wappalyzer-style grid, real icons) /
         Vulnerabilities (grouped CVEs + fix guidance) / Headers
```

## Known limitations

- Icon coverage is best-effort for less-common packages; unmapped or failed
  icons fall back to a category glyph rather than breaking.
- On-demand rescans (the fix for cached tabs) can't see `Set-Cookie` —
  cookie-fingerprinted frameworks (Django, Laravel, Rails, etc.) only
  resolve from a real page-load detection.
- Near-duplicate advisory grouping is a similarity heuristic (word-overlap,
  not exact), so it can occasionally under- or over-cluster; nothing is
  hidden, only grouped for display.
- NVD pagination caps at 100 results/product; CDN-inferred packages are a
  best-effort name guess; a "vulnerable version" doesn't mean "exploitable
  in practice" — treat confirmed findings as "needs review."
- No exploitation walkthroughs by design — see the in-app References
  (NVD/OSV's own labeled links) and the Fix-available line instead.
