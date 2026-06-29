/**
 * Content script: runs in every page (and can be re-injected on demand by
 * the background worker via chrome.scripting.executeScript when a tab has
 * no recorded state yet — e.g. it was open before the extension loaded, or
 * the service worker was restarted and lost its in-memory state).
 *
 * Performs PASSIVE detection (HTML, meta tags, script src, window globals,
 * DOM selectors, stylesheet content) and collects raw signal (script/link
 * URLs, document.cookie) for the background worker to do CDN-URL parsing,
 * Set-Cookie fingerprinting, and CVE lookups.
 *
 * Manifest V3 content scripts loaded via content_scripts[].js cannot use
 * `import` (only background.service_worker supports "type": "module"), so
 * this is a kept-in-sync-by-hand duplicate of lib/signatures.js's `detect`
 * blocks. To minimize drift, the field names here are IDENTICAL to
 * lib/signatures.js (script/global/html/htmlAttr/meta/dom/cssVarScan) so
 * syncing a new signature is a direct copy of its `detect` object, not a
 * field-name translation.
 */

(function () {
  const SIGS = [
    { id: "jquery", name: "jQuery", category: "JS Library", detect: { script: /jquery(?:-|\.)([0-9]+\.[0-9]+\.[0-9]+)/i, global: "jQuery.fn.jquery" } },
    { id: "jquery-ui", name: "jQuery UI", category: "JS Library", detect: { script: /jquery-ui[.-]([0-9]+\.[0-9]+\.[0-9]+)/i, global: "jQuery.ui.version" } },
    { id: "react", name: "React", category: "JS Framework", detect: { global: "React.version", html: /data-reactroot|react-dom/i } },
    { id: "vue", name: "Vue.js", category: "JS Framework", detect: { global: "Vue.version", script: /vue(?:\.runtime)?[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "angular", name: "Angular", category: "JS Framework", detect: { global: "ng.version.full", htmlAttr: /ng-version="([0-9.]+)"/i } },
    { id: "angularjs", name: "AngularJS (1.x)", category: "JS Framework", detect: { global: "angular.version.full", script: /angular[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "lodash", name: "Lodash", category: "JS Library", detect: { global: "_.VERSION", script: /lodash[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "underscore", name: "Underscore.js", category: "JS Library", detect: { global: "_.VERSION", script: /underscore[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "bootstrap", name: "Bootstrap", category: "CSS Framework", detect: { script: /bootstrap[.-]([0-9]+\.[0-9]+\.[0-9]+)/i, html: /bootstrap(?:\.min)?\.css/i } },
    { id: "moment", name: "Moment.js", category: "JS Library", detect: { global: "moment.version", script: /moment[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "axios", name: "Axios", category: "JS Library", detect: { script: /axios[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "d3", name: "D3.js", category: "JS Library", detect: { global: "d3.version", script: /d3[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "three", name: "Three.js", category: "JS Library", detect: { global: "THREE.REVISION", script: /three[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "chartjs", name: "Chart.js", category: "JS Library", detect: { global: "Chart.version", script: /chart[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "alpinejs", name: "Alpine.js", category: "JS Framework", detect: { global: "Alpine.version", script: /alpinejs?[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "nextjs", name: "Next.js", category: "JS Framework", detect: { global: "next.version", html: /__NEXT_DATA__/i, dom: { selector: "meta[name='next-head-count']" } } },
    { id: "gsap", name: "GSAP", category: "JS Library", detect: { global: "gsap.version", script: /gsap[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "popper", name: "Popper.js", category: "JS Library", detect: { script: /popper[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "swiper", name: "Swiper", category: "JS Library", detect: { script: /swiper[.-]([0-9]+\.[0-9]+\.[0-9]+)/i, global: "Swiper.version" } },
    { id: "fontawesome", name: "Font Awesome", category: "Icon Library", detect: { script: /font-?awesome[.-]([0-9]+\.[0-9]+\.[0-9]+)/i, html: /font-awesome|fontawesome/i, dom: { selector: "svg[data-fa-i2svg], i[class*='fa-']" } } },
    { id: "videojs", name: "Video.js", category: "Video Player", detect: { global: "videojs.VERSION", dom: { selector: ".video-js" }, script: /video[.-]js[.-]?([0-9]+\.[0-9]+\.[0-9]+)?/i } },
    { id: "lucide", name: "Lucide", category: "Icon Library", detect: { dom: { selector: "svg.lucide" }, script: /lucide[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "materialicons", name: "Material Icons", category: "Icon Library", detect: { dom: { selector: ".material-icons, .material-symbols-outlined, .material-symbols-rounded" } } },
    { id: "bootstrapicons", name: "Bootstrap Icons", category: "Icon Library", detect: { dom: { selector: "[class*='bi-']" }, script: /bootstrap-icons[.-]([0-9]+\.[0-9]+\.[0-9]+)/i } },
    { id: "feathericons", name: "Feather Icons", category: "Icon Library", detect: { dom: { selector: "[data-feather]" } } },
    { id: "framermotion", name: "Framer Motion", category: "JS Library", detect: { global: "Motion.version", script: /framer-motion/i } },
    { id: "tailwindcss", name: "Tailwind CSS", category: "CSS Framework", detect: { cssVarScan: /--tw-[a-z-]+/ } },
    { id: "prioritihints", name: "Priority Hints", category: "Performance", detect: { dom: { selector: "[fetchpriority]" } } },
    { id: "nuxt", name: "Nuxt", category: "Static Site Generator", detect: { global: "__NUXT__", dom: { selector: "#__nuxt, #__layer" } } },
    { id: "gatsby", name: "Gatsby", category: "Static Site Generator", detect: { dom: { selector: "#___gatsby" }, html: /gatsby-/i } },
    { id: "astro", name: "Astro", category: "Static Site Generator", detect: { dom: { selector: "astro-island" }, html: /astro-island/i } },
    { id: "svelte", name: "Svelte / SvelteKit", category: "JS Framework", detect: { dom: { selector: "[class*='svelte-']" } } },
    { id: "wordpress", name: "WordPress", category: "CMS", detect: { meta: { name: "generator", regex: /WordPress\s*([0-9.]+)?/i }, html: /wp-content|wp-includes/i } },
    { id: "drupal", name: "Drupal", category: "CMS", detect: { meta: { name: "generator", regex: /Drupal\s*([0-9.]+)?/i } } },
    { id: "joomla", name: "Joomla", category: "CMS", detect: { meta: { name: "generator", regex: /Joomla!?\s*([0-9.]+)?/i } } },
    { id: "ghost", name: "Ghost", category: "CMS", detect: { meta: { name: "generator", regex: /Ghost\s*([0-9.]+)?/i } } },
    { id: "magento", name: "Magento", category: "CMS", detect: { html: /Mage\.Cookies|\/static\/version/i } },
    { id: "webflow", name: "Webflow", category: "Website Builder", detect: { meta: { name: "generator", regex: /Webflow/i } } }
  ];

  // Files we'll ask the background worker to fetch and sniff for a leading
  // version comment when we found the tech but not its version.
  const COMMENT_SNIFF_CANDIDATES = ["jquery", "bootstrap", "fontawesome"];

  function readGlobal(path) {
    try {
      let obj = window;
      for (const p of path.split(".")) {
        if (obj == null) return null;
        obj = obj[p];
      }
      return typeof obj === "string" || typeof obj === "number" ? String(obj) : null;
    } catch {
      return null;
    }
  }

  /** Scans accessible (same-origin) stylesheets' rule text for a regex match. */
  function scanStylesheets(regex) {
    for (const sheet of Array.from(document.styleSheets)) {
      try {
        const rules = sheet.cssRules;
        if (!rules) continue;
        for (const rule of Array.from(rules)) {
          if (regex.test(rule.cssText)) return true;
        }
      } catch {
        // cross-origin stylesheet — cssRules throws, skip it
      }
    }
    // Also check inline <style> tags, which are always same-origin readable
    for (const styleTag of Array.from(document.querySelectorAll("style"))) {
      if (regex.test(styleTag.textContent || "")) return true;
    }
    return false;
  }

  function detectPassive() {
    const html = document.documentElement ? document.documentElement.outerHTML : "";
    const scriptSrcs = Array.from(document.scripts || []).map((s) => s.src).filter(Boolean);
    const linkHrefs = Array.from(document.querySelectorAll("link[href]")).map((l) => l.href).filter(Boolean);
    const allAssetUrls = [...scriptSrcs, ...linkHrefs];
    const metas = Array.from(document.querySelectorAll("meta[name]"));
    const found = [];

    for (const sig of SIGS) {
      const d = sig.detect || {};
      let version = null;
      let matched = false;
      let assetUrl = null;

      if (d.global) {
        const v = readGlobal(d.global);
        if (v) { matched = true; version = v; }
      }

      if (d.script) {
        for (const src of allAssetUrls) {
          const m = src.match(d.script);
          if (m) { matched = true; version = version || m[1] || null; assetUrl = src; break; }
        }
      }

      if (!matched && d.meta) {
        const tag = metas.find((m) => m.getAttribute("name")?.toLowerCase() === d.meta.name);
        if (tag) {
          const content = tag.getAttribute("content") || "";
          const m = content.match(d.meta.regex);
          if (m) { matched = true; version = m[1] || version; }
        }
      }

      if (!matched && d.htmlAttr) {
        const m = html.match(d.htmlAttr);
        if (m) { matched = true; version = m[1] || version; }
      }

      if (!matched && d.dom) {
        try {
          if (document.querySelector(d.dom.selector)) matched = true;
        } catch {
          // malformed selector — skip rather than throw and abort detection
        }
      }

      if (!matched && d.cssVarScan) {
        if (scanStylesheets(d.cssVarScan)) matched = true;
      }

      if (!matched && d.html && d.html.test(html)) {
        matched = true;
        if (sig.id === "bootstrap") assetUrl = allAssetUrls.find((u) => /bootstrap/i.test(u)) || null;
        if (sig.id === "fontawesome") assetUrl = allAssetUrls.find((u) => /font-?awesome/i.test(u)) || null;
      }

      if (matched) {
        found.push({
          id: sig.id,
          name: sig.name,
          category: sig.category,
          version: version || null,
          assetUrl: COMMENT_SNIFF_CANDIDATES.includes(sig.id) && !version ? assetUrl : null
        });
      }
    }

    return { detected: found, allAssetUrls };
  }

  const { detected, allAssetUrls } = detectPassive();

  chrome.runtime.sendMessage({
    type: "STACKWATCH_PASSIVE_RESULTS",
    url: location.href,
    detected,
    assetUrls: allAssetUrls,
    cookieString: document.cookie || ""
  });

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "STACKWATCH_SHOW_BANNER") {
      showBanner(msg.summary);
    }
  });

  function showBanner(summary) {
    if (document.getElementById("stackwatch-banner")) return;
    const bar = document.createElement("div");
    bar.id = "stackwatch-banner";
    bar.innerHTML = `
      <div class="sw-banner-inner">
        <span class="sw-banner-icon">⚠</span>
        <span class="sw-banner-text">
          <strong>StackWatch</strong> — this site is running ${summary.count} component(s) with a confirmed critical vulnerability
          (e.g. ${summary.example}). This is a browser-extension notice, not a message from this website.
        </span>
        <button class="sw-banner-action" id="sw-banner-details">Details</button>
        <button class="sw-banner-close" id="sw-banner-close" aria-label="Dismiss">&times;</button>
      </div>
    `;
    document.documentElement.appendChild(bar);
    document.getElementById("sw-banner-close").addEventListener("click", () => bar.remove());
    document.getElementById("sw-banner-details").addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "STACKWATCH_OPEN_POPUP" });
    });
  }
})();
