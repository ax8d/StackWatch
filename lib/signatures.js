/**
 * Technology signature database.
 *
 * Each entry describes how to detect a technology passively, and how to map
 * a detected version to a lookup key for vulnerability databases:
 *  - osv: { ecosystem, name }   -> used to query OSV.dev
 *  - cpe: { vendor, product }  -> used to query NVD (CPE match)
 *
 * Detection methods under `detect`:
 *  - script / html / meta / global / header / header2: as before
 *  - dom: { selector } — CSS selector existence check (Wappalyzer's most
 *    heavily-used method; this is what we were missing entirely before —
 *    a lot of modern frontend libraries mark their presence via a DOM
 *    class/attribute rather than a global variable or script URL)
 *  - cssVarScan: regex tested against accessible stylesheet rule text —
 *    needed for things like Tailwind, which compiles away any fixed
 *    namespace but still emits distinctive `--tw-*` custom properties
 *
 * `commentSniff` gives a regex to run against the *content* of a same
 * technology's asset file (CSS/JS) when no version was found via filename
 * or CDN URL.
 */

export const SIGNATURES = [
  // ---------------- JS Frameworks / Libraries ----------------
  {
    id: "jquery", name: "jQuery", category: "JS Library",
    osv: { ecosystem: "npm", name: "jquery" },
    detect: { script: /jquery(?:-|\.)([0-9]+\.[0-9]+\.[0-9]+)/i, global: "jQuery.fn.jquery" },
    commentSniff: /jQuery\s+JavaScript\s+Library\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i
  },
  {
    id: "jquery-ui", name: "jQuery UI", category: "JS Library",
    osv: { ecosystem: "npm", name: "jquery-ui" },
    detect: { script: /jquery-ui[.-]([0-9]+\.[0-9]+\.[0-9]+)/i, global: "jQuery.ui.version" }
  },
  {
    id: "react", name: "React", category: "JS Framework",
    osv: { ecosystem: "npm", name: "react" },
    detect: { global: "React.version", html: /data-reactroot|react-dom/i }
  },
  {
    id: "vue", name: "Vue.js", category: "JS Framework",
    osv: { ecosystem: "npm", name: "vue" },
    detect: { global: "Vue.version", script: /vue(?:\.runtime)?[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "angular", name: "Angular", category: "JS Framework",
    osv: { ecosystem: "npm", name: "@angular/core" },
    detect: { global: "ng.version.full", html: /ng-version="([0-9.]+)"/i }
  },
  {
    id: "angularjs", name: "AngularJS (1.x)", category: "JS Framework",
    osv: { ecosystem: "npm", name: "angular" },
    detect: { global: "angular.version.full", script: /angular[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "lodash", name: "Lodash", category: "JS Library",
    osv: { ecosystem: "npm", name: "lodash" },
    detect: { global: "_.VERSION", script: /lodash[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "underscore", name: "Underscore.js", category: "JS Library",
    osv: { ecosystem: "npm", name: "underscore" },
    detect: { global: "_.VERSION", script: /underscore[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "bootstrap", name: "Bootstrap", category: "CSS Framework",
    osv: { ecosystem: "npm", name: "bootstrap" },
    detect: { script: /bootstrap[.-]([0-9]+\.[0-9]+\.[0-9]+)/i, html: /bootstrap(?:\.min)?\.css/i },
    commentSniff: /Bootstrap\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i
  },
  {
    id: "moment", name: "Moment.js", category: "JS Library",
    osv: { ecosystem: "npm", name: "moment" },
    detect: { global: "moment.version", script: /moment[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "axios", name: "Axios", category: "JS Library",
    osv: { ecosystem: "npm", name: "axios" },
    detect: { script: /axios[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "d3", name: "D3.js", category: "JS Library",
    osv: { ecosystem: "npm", name: "d3" },
    detect: { global: "d3.version", script: /d3[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "three", name: "Three.js", category: "JS Library",
    osv: { ecosystem: "npm", name: "three" },
    detect: { global: "THREE.REVISION", script: /three[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "chartjs", name: "Chart.js", category: "JS Library",
    osv: { ecosystem: "npm", name: "chart.js" },
    detect: { global: "Chart.version", script: /chart[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "alpinejs", name: "Alpine.js", category: "JS Framework",
    osv: { ecosystem: "npm", name: "alpinejs" },
    detect: { global: "Alpine.version", script: /alpinejs?[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "nextjs", name: "Next.js", category: "JS Framework",
    osv: { ecosystem: "npm", name: "next" },
    detect: { global: "next.version", html: /__NEXT_DATA__/i, dom: { selector: "meta[name='next-head-count']" } }
  },
  {
    id: "gsap", name: "GSAP", category: "JS Library",
    osv: { ecosystem: "npm", name: "gsap" },
    detect: { global: "gsap.version", script: /gsap[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "popper", name: "Popper.js", category: "JS Library",
    osv: { ecosystem: "npm", name: "@popperjs/core" },
    detect: { script: /popper[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "swiper", name: "Swiper", category: "JS Library",
    osv: { ecosystem: "npm", name: "swiper" },
    detect: { script: /swiper[.-]([0-9]+\.[0-9]+\.[0-9]+)/i, global: "Swiper.version" }
  },
  {
    id: "fontawesome", name: "Font Awesome", category: "Icon Library",
    osv: { ecosystem: "npm", name: "font-awesome" },
    detect: { script: /font-?awesome[.-]([0-9]+\.[0-9]+\.[0-9]+)/i, html: /font-awesome|fontawesome/i, dom: { selector: "svg[data-fa-i2svg], i[class*='fa-']" } },
    commentSniff: /Font Awesome\s+(?:Free|Pro)?\s*v?([0-9]+\.[0-9]+\.[0-9]+)/i
  },
  {
    id: "videojs", name: "Video.js", category: "Video Player",
    osv: { ecosystem: "npm", name: "video.js" },
    detect: { global: "videojs.VERSION", dom: { selector: ".video-js" }, script: /video[.-]js[.-]?([0-9]+\.[0-9]+\.[0-9]+)?/i }
  },
  {
    id: "lucide", name: "Lucide", category: "Icon Library",
    osv: { ecosystem: "npm", name: "lucide" },
    detect: { dom: { selector: "svg.lucide" }, script: /lucide[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "materialicons", name: "Material Icons", category: "Icon Library",
    detect: { dom: { selector: ".material-icons, .material-symbols-outlined, .material-symbols-rounded" } }
  },
  {
    id: "bootstrapicons", name: "Bootstrap Icons", category: "Icon Library",
    osv: { ecosystem: "npm", name: "bootstrap-icons" },
    detect: { dom: { selector: "[class*='bi-']" }, script: /bootstrap-icons[.-]([0-9]+\.[0-9]+\.[0-9]+)/i }
  },
  {
    id: "feathericons", name: "Feather Icons", category: "Icon Library",
    detect: { dom: { selector: "[data-feather]" } }
  },
  {
    id: "framermotion", name: "Framer Motion", category: "JS Library",
    osv: { ecosystem: "npm", name: "framer-motion" },
    detect: { global: "Motion.version", script: /framer-motion/i }
  },
  {
    id: "tailwindcss", name: "Tailwind CSS", category: "CSS Framework",
    osv: { ecosystem: "npm", name: "tailwindcss" },
    detect: { cssVarScan: /--tw-[a-z-]+/ }
  },
  {
    id: "prioritihints", name: "Priority Hints", category: "Performance",
    detect: { dom: { selector: "[fetchpriority]" } }
  },
  {
    id: "nuxt", name: "Nuxt", category: "Static Site Generator",
    osv: { ecosystem: "npm", name: "nuxt" },
    detect: { global: "__NUXT__", dom: { selector: "#__nuxt, #__layer" } }
  },
  {
    id: "gatsby", name: "Gatsby", category: "Static Site Generator",
    osv: { ecosystem: "npm", name: "gatsby" },
    detect: { dom: { selector: "#___gatsby" }, html: /gatsby-/i }
  },
  {
    id: "astro", name: "Astro", category: "Static Site Generator",
    osv: { ecosystem: "npm", name: "astro" },
    detect: { dom: { selector: "astro-island" }, html: /astro-island/i }
  },
  {
    id: "svelte", name: "Svelte / SvelteKit", category: "JS Framework",
    osv: { ecosystem: "npm", name: "svelte" },
    detect: { dom: { selector: "[class*='svelte-']" } }
  },

  // ---------------- CMS ----------------
  {
    id: "wordpress", name: "WordPress", category: "CMS",
    cpe: { vendor: "wordpress", product: "wordpress" },
    detect: { meta: { name: "generator", regex: /WordPress\s*([0-9.]+)?/i }, html: /wp-content|wp-includes/i },
    activeProbes: [
      { path: "/wp-login.php", confirms: true },
      { path: "/readme.html", versionRegex: /Version\s+([0-9.]+)/i }
    ]
  },
  {
    id: "drupal", name: "Drupal", category: "CMS",
    cpe: { vendor: "drupal", product: "drupal" },
    detect: { meta: { name: "generator", regex: /Drupal\s*([0-9.]+)?/i }, header: { name: "x-generator", regex: /Drupal\s*([0-9.]+)?/i } },
    activeProbes: [{ path: "/CHANGELOG.txt", versionRegex: /Drupal\s+([0-9.]+)/i }]
  },
  {
    id: "joomla", name: "Joomla", category: "CMS",
    cpe: { vendor: "joomla", product: "joomla" },
    detect: { meta: { name: "generator", regex: /Joomla!?\s*([0-9.]+)?/i } }
  },
  {
    id: "ghost", name: "Ghost", category: "CMS",
    osv: { ecosystem: "npm", name: "ghost" },
    detect: { meta: { name: "generator", regex: /Ghost\s*([0-9.]+)?/i } }
  },
  {
    id: "magento", name: "Magento", category: "CMS",
    cpe: { vendor: "adobe", product: "commerce" },
    detect: { html: /Mage\.Cookies|\/static\/version/i },
    cookieHint: { regex: /\bmage-cache-sessid\b/, label: "Magento (cache session cookie)" }
  },

  // ---------------- Server / Backend ----------------
  {
    id: "apache", name: "Apache HTTP Server", category: "Web Server",
    cpe: { vendor: "apache", product: "http_server" },
    detect: { header: { name: "server", regex: /Apache\/?([0-9.]+)?/i } }
  },
  {
    id: "nginx", name: "nginx", category: "Web Server",
    cpe: { vendor: "f5", product: "nginx" },
    detect: { header: { name: "server", regex: /nginx\/?([0-9.]+)?/i } }
  },
  {
    id: "php", name: "PHP", category: "Programming Language",
    cpe: { vendor: "php", product: "php" },
    detect: { header: { name: "x-powered-by", regex: /PHP\/?([0-9.]+)?/i } },
    cookieHint: { regex: /\bPHPSESSID\b/, label: "PHP (session cookie)" }
  },
  {
    id: "iis", name: "Microsoft IIS", category: "Web Server",
    cpe: { vendor: "microsoft", product: "internet_information_services" },
    detect: { header: { name: "server", regex: /Microsoft-IIS\/?([0-9.]+)?/i } }
  },
  {
    id: "aspnet", name: "ASP.NET", category: "Web Framework",
    cpe: { vendor: "microsoft", product: "asp.net" },
    detect: { header: { name: "x-powered-by", regex: /ASP\.NET/i } },
    cookieHint: { regex: /\bASP\.NET_SessionId\b/, label: "ASP.NET (session cookie)" }
  },
  {
    id: "express", name: "Express.js", category: "Web Framework",
    osv: { ecosystem: "npm", name: "express" },
    detect: { header: { name: "x-powered-by", regex: /Express/i } },
    cookieHint: { regex: /\bconnect\.sid\b/, label: "Express (session cookie)" }
  },
  {
    id: "openssl", name: "OpenSSL", category: "Crypto Library",
    cpe: { vendor: "openssl", product: "openssl" },
    detect: { header: { name: "server", regex: /OpenSSL\/([0-9.a-z]+)/i } }
  },
  {
    id: "werkzeug", name: "Werkzeug (Flask dev server)", category: "Web Framework",
    osv: { ecosystem: "PyPI", name: "werkzeug" },
    detect: { header: { name: "server", regex: /Werkzeug\/([0-9.]+)/i } }
  },
  {
    id: "python", name: "Python", category: "Programming Language",
    cpe: { vendor: "python", product: "python" },
    detect: { header: { name: "server", regex: /Python\/([0-9.]+)/i } }
  },
  {
    id: "gunicorn", name: "Gunicorn", category: "Web Server",
    osv: { ecosystem: "PyPI", name: "gunicorn" },
    detect: { header: { name: "server", regex: /gunicorn\/([0-9.]+)/i } }
  },
  {
    id: "django", name: "Django", category: "Web Framework",
    osv: { ecosystem: "PyPI", name: "django" },
    cookieHint: { regex: /\bcsrftoken\b/, label: "Django (csrftoken cookie)" }
  },
  {
    id: "rails", name: "Ruby on Rails", category: "Web Framework",
    osv: { ecosystem: "RubyGems", name: "rails" },
    cookieHint: { regex: /_session(?:_id)?=/, label: "Rails (session cookie)" }
  },
  {
    id: "laravel", name: "Laravel", category: "Web Framework",
    osv: { ecosystem: "Packagist", name: "laravel/framework" },
    cookieHint: { regex: /\blaravel_session\b/, label: "Laravel (session cookie)" }
  },
  {
    id: "tomcat", name: "Apache Tomcat", category: "Web Server",
    cpe: { vendor: "apache", product: "tomcat" },
    detect: { header: { name: "server", regex: /Apache-Coyote\/?([0-9.]+)?/i } },
    cookieHint: { regex: /\bJSESSIONID\b/, label: "Java/Tomcat (session cookie)" }
  },
  {
    id: "litespeed", name: "LiteSpeed Web Server", category: "Web Server",
    cpe: { vendor: "litespeedtech", product: "litespeed_web_server" },
    detect: { header: { name: "server", regex: /LiteSpeed/i } }
  },
  {
    id: "caddy", name: "Caddy", category: "Web Server",
    cpe: { vendor: "caddyserver", product: "caddy" },
    detect: { header: { name: "server", regex: /Caddy/i } }
  },
  {
    id: "haproxy", name: "HAProxy", category: "Web Server",
    cpe: { vendor: "haproxy", product: "haproxy" },
    detect: { header: { name: "server", regex: /HAProxy/i } }
  },
  {
    id: "jetty", name: "Eclipse Jetty", category: "Web Server",
    cpe: { vendor: "eclipse", product: "jetty" },
    detect: { header: { name: "server", regex: /Jetty\(?([0-9.]+)?\)?/i } }
  },
  {
    id: "kestrel", name: "Kestrel (.NET)", category: "Web Server",
    osv: { ecosystem: "NuGet", name: "Microsoft.AspNetCore.Server.Kestrel.Core" },
    detect: { header: { name: "server", regex: /Kestrel/i } }
  },
  {
    id: "passenger", name: "Phusion Passenger", category: "Web Server",
    cpe: { vendor: "phusion", product: "passenger" },
    detect: { header: { name: "x-powered-by", regex: /Phusion Passenger\/?([0-9.]+)?/i } }
  },

  // ---------------- Reverse proxies ----------------
  {
    id: "varnish", name: "Varnish Cache", category: "Reverse Proxy",
    cpe: { vendor: "varnish-cache", product: "varnish_cache_server" },
    detect: { header: { name: "via", regex: /varnish/i } }
  },
  {
    id: "squid", name: "Squid", category: "Reverse Proxy",
    cpe: { vendor: "squid-cache", product: "squid" },
    detect: { header: { name: "via", regex: /squid\/?([0-9.]+)?/i } }
  },

  // ---------------- CDN / PaaS ----------------
  {
    id: "cloudflare", name: "Cloudflare", category: "CDN",
    detect: { header: { name: "server", regex: /cloudflare/i } }
  },
  {
    id: "cloudfront", name: "Amazon CloudFront", category: "CDN",
    detect: { header: { name: "x-amz-cf-id", regex: /(?:.+)/ }, header2: { name: "via", regex: /CloudFront/i } }
  },
  {
    id: "fastly", name: "Fastly", category: "CDN",
    detect: { header: { name: "x-served-by", regex: /cache-[a-z0-9-]+/i } }
  },
  {
    id: "akamai", name: "Akamai", category: "CDN",
    detect: { header: { name: "x-akamai-transformed", regex: /(?:.+)/ } }
  },
  {
    id: "vercel", name: "Vercel", category: "PaaS",
    detect: { header: { name: "x-vercel-id", regex: /(?:.+)/ } }
  },
  {
    id: "netlify", name: "Netlify", category: "PaaS",
    detect: { header: { name: "x-nf-request-id", regex: /(?:.+)/ } }
  },
  {
    id: "aws", name: "Amazon Web Services", category: "PaaS",
    detect: { header: { name: "x-amzn-requestid", regex: /(?:.+)/ } }
  },
  {
    id: "heroku", name: "Heroku", category: "PaaS",
    detect: { header: { name: "via", regex: /heroku/i } }
  },

  // ---------------- Security / WAF ----------------
  {
    id: "cloudflare-waf", name: "Cloudflare (WAF/Bot Management)", category: "Security/WAF",
    detect: { header: { name: "cf-ray", regex: /(?:.+)/ } }
  },
  {
    id: "sucuri", name: "Sucuri WAF", category: "Security/WAF",
    detect: { header: { name: "x-sucuri-id", regex: /(?:.+)/ } }
  },
  {
    id: "incapsula", name: "Imperva Incapsula", category: "Security/WAF",
    detect: { header: { name: "x-iinfo", regex: /(?:.+)/ } }
  },
  {
    id: "aws-waf", name: "AWS WAF", category: "Security/WAF",
    detect: { header: { name: "x-amzn-waf-action", regex: /(?:.+)/ } }
  },

  // ---------------- Website builders / hosted e-commerce ----------------
  {
    id: "shopify", name: "Shopify", category: "E-commerce",
    detect: { header: { name: "x-shopify-stage", regex: /(?:.+)/ } },
    cookieHint: { regex: /_shopify_s=/, label: "Shopify (session cookie)" }
  },
  {
    id: "wix", name: "Wix", category: "Website Builder",
    cookieHint: { regex: /\b_wixCIDX\b/, label: "Wix (visitor cookie)" }
  },
  {
    id: "squarespace", name: "Squarespace", category: "Website Builder",
    cookieHint: { regex: /\bSS_MID\b/, label: "Squarespace (session cookie)" }
  },
  {
    id: "webflow", name: "Webflow", category: "Website Builder",
    detect: { meta: { name: "generator", regex: /Webflow/i } }
  }
];

export function buildLookupTarget(sig, version) {
  return {
    id: sig.id,
    name: sig.name,
    category: sig.category,
    version: version || null,
    osv: sig.osv || null,
    cpe: sig.cpe || null
  };
}
