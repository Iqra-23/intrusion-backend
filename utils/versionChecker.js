/**
 * Compares current and latest version (semantic versioning)
 * Returns true if outdated
 */
export const isOutdatedVersion = (current, latest) => {
  try {
    const cur = current.split(".").map(Number);
    const lat = latest.split(".").map(Number);
    for (let i = 0; i < 3; i++) {
      if (cur[i] < lat[i]) return true;
      if (cur[i] > lat[i]) return false;
    }
    return false;
  } catch {
    return false;
  }
};

/**
 * Example function for demonstration
 * @returns {Object[]} array of version reports
 */
export const checkPluginVersions = (plugins = []) => {
  return plugins.map((p) => ({
    name: p.name,
    current: p.version,
    latest: p.latest,
    outdated: isOutdatedVersion(p.version, p.latest)
  }));
};
