/**
 * Real brand icons instead of generated pixel art. Simple Icons
 * (simpleicons.org) hosts exactly this use case — "show the logo of a
 * detected technology" — via a free public CDN, no bundling needed:
 *   https://cdn.simpleicons.org/<slug>
 *
 * Coverage is necessarily incomplete (3000+ brands exist, our signature
 * list doesn't map 1:1 to a slug for all of them, and some slugs below are
 * best-effort rather than independently verified). Every <img> using this
 * gets onerror handling in popup.js to fall back to the category glyph
 * below, so a wrong/missing slug degrades gracefully instead of showing a
 * broken image.
 */

const SLUG_MAP = {
  jquery: "jquery", "jquery-ui": "jquery", react: "react", vue: "vuedotjs",
  angular: "angular", angularjs: "angularjs", lodash: "lodash", underscore: "underscoredotjs",
  bootstrap: "bootstrap", moment: "javascript", axios: "axios", d3: "d3dotjs",
  three: "threedotjs", chartjs: "chartdotjs", alpinejs: "alpinedotjs", nextjs: "nextdotjs",
  gsap: "greensock", popper: "popper", swiper: "swiper", fontawesome: "fontawesome",
  videojs: "videodotjs", lucide: "lucide", bootstrapicons: "bootstrap", framermotion: "framer",
  tailwindcss: "tailwindcss", nuxt: "nuxtdotjs", gatsby: "gatsby", astro: "astro",
  svelte: "svelte", wordpress: "wordpress", drupal: "drupal", joomla: "joomla",
  ghost: "ghost", magento: "magento", apache: "apache", nginx: "nginx", php: "php",
  iis: "microsoft", aspnet: "dotnet", express: "express", openssl: "openssl",
  werkzeug: "python", python: "python", gunicorn: "gunicorn", django: "django",
  rails: "rubyonrails", laravel: "laravel", tomcat: "apachetomcat", caddy: "caddy",
  haproxy: "haproxy", kestrel: "dotnet", varnish: "varnish", cloudflare: "cloudflare",
  cloudfront: "amazonaws", fastly: "fastly", akamai: "akamai", vercel: "vercel",
  netlify: "netlify", aws: "amazonaws", heroku: "heroku", "cloudflare-waf": "cloudflare",
  sucuri: "sucuri", shopify: "shopify", wix: "wix", squarespace: "squarespace",
  webflow: "webflow"
};

/** Returns a Simple Icons CDN URL for a signature id, or null if unmapped. */
export function getTechIconUrl(id) {
  const baseId = id.startsWith("cdn:") ? id.slice(4) : id;
  const slug = SLUG_MAP[baseId] || SLUG_MAP[baseId.toLowerCase()];
  if (slug) return `https://cdn.simpleicons.org/${slug}`;

  // CDN-auto-detected packages: try the raw package name as a slug guess —
  // works surprisingly often (most npm package names match their simple-icons
  // slug directly), and onerror fallback covers the misses.
  if (id.startsWith("cdn:")) {
    const guess = baseId.replace(/[^a-z0-9]/gi, "").toLowerCase();
    return `https://cdn.simpleicons.org/${guess}`;
  }
  return null;
}

/** Clean line-icon SVG fallback per category, used when no brand icon is available or the image fails to load. */
const CATEGORY_GLYPHS = {
  "Web Server": `<path d="M4 4h16v6H4zM4 14h16v6H4z"/><circle cx="7" cy="7" r=".5"/><circle cx="7" cy="17" r=".5"/>`,
  "Reverse Proxy": `<path d="M4 4h16v6H4zM4 14h16v6H4z"/><circle cx="7" cy="7" r=".5"/><circle cx="7" cy="17" r=".5"/>`,
  "Programming Language": `<polyline points="9 18 4 12 9 6"/><polyline points="15 6 20 12 15 18"/>`,
  "Web Framework": `<circle cx="12" cy="12" r="8"/><path d="M12 4a8 8 0 0 1 0 16 8 8 0 0 1 0-16"/>`,
  "JS Framework": `<circle cx="12" cy="12" r="8"/><path d="M12 4a8 8 0 0 1 0 16 8 8 0 0 1 0-16"/>`,
  "JS Library": `<rect x="5" y="5" width="14" height="14" rx="2"/>`,
  "CSS Framework": `<path d="M5 4h14l-1.2 15L12 21l-5.8-2L5 4z"/>`,
  "UI Framework": `<rect x="5" y="5" width="14" height="14" rx="2"/>`,
  "Icon Library": `<circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/>`,
  "Video Player": `<rect x="3" y="5" width="18" height="14" rx="2"/><polygon points="10 9 16 12 10 15"/>`,
  "Performance": `<polyline points="3 17 9 11 13 15 21 6"/>`,
  "Static Site Generator": `<path d="M4 4h16v16H4z"/><path d="M4 9h16"/>`,
  "Crypto Library": `<rect x="6" y="11" width="12" height="9" rx="1"/><path d="M9 11V7a3 3 0 0 1 6 0v4"/>`,
  "CMS": `<path d="M4 4h16v16H4z"/><path d="M8 9h8M8 13h8M8 17h4"/>`,
  "CDN": `<path d="M6 17a4 4 0 0 1 0-8 5 5 0 0 1 9.6-1.8A4.5 4.5 0 0 1 18 17H6z"/>`,
  "PaaS": `<path d="M6 17a4 4 0 0 1 0-8 5 5 0 0 1 9.6-1.8A4.5 4.5 0 0 1 18 17H6z"/>`,
  "Security/WAF": `<path d="M12 3l7 4v5c0 5-3 7.5-7 9-4-1.5-7-4-7-9V7l7-4z"/>`,
  "Website Builder": `<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M4 9h16"/>`,
  "E-commerce": `<path d="M4 7h16l-1.5 10h-13z"/><path d="M8 7V5a4 4 0 0 1 8 0v2"/>`,
  "Auto-detected (CDN)": `<rect x="5" y="5" width="14" height="14" rx="2"/>`
};

const DEFAULT_GLYPH = `<rect x="5" y="5" width="14" height="14" rx="2"/>`;

/** Returns a self-contained <svg> string for a category's fallback glyph. */
export function getCategoryGlyphSvg(category, color = "currentColor", size = 18) {
  const path = CATEGORY_GLYPHS[category] || DEFAULT_GLYPH;
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg">${path}</svg>`;
}
