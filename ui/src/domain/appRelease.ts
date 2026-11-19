const RELEASE_REPOSITORY = "Xauryan/certimate-dns";

export const APP_REPO_URL = `https://github.com/${RELEASE_REPOSITORY}`;
export const APP_DOWNLOAD_URL = `${APP_REPO_URL}/releases`;
export const APP_DOCUMENT_URL = `${APP_REPO_URL}/blob/main/docs/dns-development.zh-CN.md`;

const RELEASES_API_URL = `https://api.github.com/repos/${RELEASE_REPOSITORY}/releases?per_page=100`;
export const RELEASE_CACHE_KEY = "certimate-dns-ui-newver";

const parseVersion = (tag: unknown) => {
  if (typeof tag !== "string") return null;

  const match = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$/.exec(tag);
  if (!match) return null;

  const [major, minor, patch] = match.slice(1, 4).map(Number);
  if (![major, minor, patch].every(Number.isSafeInteger)) return null;

  return { tag, major, minor, patch, stable: !match[4] };
};

type Version = NonNullable<ReturnType<typeof parseVersion>>;

const compareVersions = (a: Version, b: Version) => a.major - b.major || a.minor - b.minor || a.patch - b.patch || Number(a.stable) - Number(b.stable);

const getReleaseUrl = (version: Version) => `${APP_DOWNLOAD_URL}/tag/${version.tag}`;

export const readCachedUpdate = (currentTag: string, storage: Pick<Storage, "getItem">) => {
  const current = parseVersion(currentTag);
  const cached = parseVersion(storage.getItem(RELEASE_CACHE_KEY));
  return current && cached?.stable && compareVersions(cached, current) > 0 ? getReleaseUrl(cached) : null;
};

export const fetchUpdate = async (currentTag: string, storage: Pick<Storage, "setItem" | "removeItem">) => {
  const response = await fetch(RELEASES_API_URL, { redirect: "error" });
  if (!response.ok) throw new Error(`Failed to check Certimate DNS releases (HTTP ${response.status})`);

  const releases: unknown = await response.json();
  if (!Array.isArray(releases)) throw new Error("Invalid Certimate DNS release list");

  const current = parseVersion(currentTag);
  let latest: Version | null = null;
  for (const release of releases) {
    if (!current || release?.draft !== false || release?.prerelease !== false) continue;

    const candidate = parseVersion(release.tag_name);
    if (candidate?.stable && compareVersions(candidate, latest ?? current) > 0) latest = candidate;
  }

  if (!latest) {
    storage.removeItem(RELEASE_CACHE_KEY);
    return null;
  }

  storage.setItem(RELEASE_CACHE_KEY, latest.tag);
  return getReleaseUrl(latest);
};
