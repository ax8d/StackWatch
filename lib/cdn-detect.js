/**
 * CDN URLs are the single most reliable version signal available to a
 * passive scanner: jsDelivr, cdnjs, unpkg, and Google's hosted libraries all
 * bake the exact package name + version into the URL path. Parsing these
 * directly lets us detect *any* package hosted on these CDNs — far beyond
 * the hand-written signature list — without doing anything risky.
 */

const CDN_PATTERNS = [
  {
    cdn: "jsDelivr",
    regex: /cdn\.jsdelivr\.net\/npm\/((?:@[^/@]+\/)?[^/@]+)@([0-9][^/]*?)(?:\/|$)/i,
    ecosystem: "npm"
  },
  {
    cdn: "cdnjs (Cloudflare)",
    regex: /cdnjs\.cloudflare\.com\/ajax\/libs\/([^/]+)\/([0-9][^/]*?)\//i,
    ecosystem: "npm"
  },
  {
    cdn: "unpkg",
    regex: /unpkg\.com\/((?:@[^/@]+\/)?[^/@]+)@([0-9][^/]*?)(?:\/|$)/i,
    ecosystem: "npm"
  },
  {
    cdn: "Google Hosted Libraries",
    regex: /ajax\.googleapis\.com\/ajax\/libs\/([^/]+)\/([0-9][^/]*?)\//i,
    ecosystem: "npm"
  },
  {
    cdn: "jQuery CDN",
    regex: /code\.jquery\.com\/(jquery(?:-ui|\.migrate)?)-([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i,
    ecosystem: "npm",
    nameOverride: "jquery"
  },
  {
    cdn: "BootstrapCDN",
    regex: /bootstrapcdn\.com\/bootstrap\/([0-9.]+)\//i,
    ecosystem: "npm",
    nameOverride: "bootstrap",
    versionOnlyGroup: 1
  }
];

/**
 * Returns { name, version, ecosystem, cdn } or null.
 */
export function extractFromCdnUrl(url) {
  if (!url) return null;

  for (const pattern of CDN_PATTERNS) {
    const m = url.match(pattern.regex);
    if (!m) continue;

    if (pattern.versionOnlyGroup) {
      return {
        name: pattern.nameOverride,
        version: m[pattern.versionOnlyGroup],
        ecosystem: pattern.ecosystem,
        cdn: pattern.cdn
      };
    }

    const rawName = pattern.nameOverride || m[1];
    return {
      name: normalizePackageName(rawName),
      version: m[2],
      ecosystem: pattern.ecosystem,
      cdn: pattern.cdn
    };
  }

  return genericFallback(url);
}

/**
 * Conservative fallback for CDN-style URLs that don't match a known host:
 * looks for a `name@version` or `name-version` or `name/version/` path
 * segment shape. Requires the name to look like a real package name to
 * avoid matching arbitrary numbers in unrelated paths (cache-busting query
 * strings, build hashes, etc.).
 */
function genericFallback(url) {
  let path;
  try {
    path = new URL(url).pathname;
  } catch {
    path = url;
  }

  const atMatch = path.match(/([a-zA-Z][a-zA-Z0-9_.-]{2,40})@([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-.][0-9a-zA-Z]+)?)/);
  if (atMatch) {
    return { name: normalizePackageName(atMatch[1]), version: atMatch[2], ecosystem: "npm", cdn: "generic", inferred: true };
  }

  const slashMatch = path.match(/\/([a-zA-Z][a-zA-Z0-9_.-]{2,40})\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)\//);
  if (slashMatch) {
    return { name: normalizePackageName(slashMatch[1]), version: slashMatch[2], ecosystem: "npm", cdn: "generic", inferred: true };
  }

  return null;
}

function normalizePackageName(name) {
  return name.replace(/\.min$|\.js$|\.css$/i, "").toLowerCase();
}
