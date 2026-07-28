/**
 * RouterOS version comparison — client-side twin of backend versions.py.
 * Runs the same logic in the browser so remote (tenant) devices — for which
 * the local backend has no data — also get accurate upgrade badges.
 */

const VER_RE = /^(\d+)\.(\d+)(?:\.(\d+))?(?:rc(\d+))?(?:beta(\d+))?/

export interface ParsedVersion {
  major: number
  minor: number
  patch: number
  stableMarker: number  // 999 for stable, positive for rc, negative for beta
}

export function parseVersion(s: string | undefined | null): ParsedVersion | null {
  if (!s) return null
  const m = VER_RE.exec(s.trim())
  if (!m) return null
  const major = parseInt(m[1], 10)
  const minor = parseInt(m[2], 10)
  const patch = parseInt(m[3] ?? '0', 10)
  const rc = parseInt(m[4] ?? '0', 10)
  const beta = parseInt(m[5] ?? '0', 10)
  const stableMarker = (rc === 0 && beta === 0) ? 999 : (rc || -beta)
  return { major, minor, patch, stableMarker }
}

/**
 * Strip channel suffix from a raw ros_version string.
 * "7.15.2 (stable)" → "7.15.2"
 * "6.49.18"         → "6.49.18"
 */
export function cleanVersion(s: string | undefined | null): string {
  if (!s) return ''
  const m = VER_RE.exec(s.trim())
  return m ? m[0] : s
}

function cmpTuple(a: ParsedVersion, b: ParsedVersion): number {
  if (a.major !== b.major) return a.major - b.major
  if (a.minor !== b.minor) return a.minor - b.minor
  if (a.patch !== b.patch) return a.patch - b.patch
  return a.stableMarker - b.stableMarker
}

export type UpgradeStatus =
  | { status: 'up_to_date'; current: string; target: string }
  | { status: 'outdated'; current: string; target: string }
  | null

/**
 * Given installed version and a map of channel → latest, pick the appropriate
 * upgrade target. Stays on the same major track (v6 → LATEST.6, v7 → LATEST.7).
 * Only stable channels ("6" and "7") are considered — never proposes rc/fix.
 */
export function pickUpgradeTarget(
  installed: string | undefined | null,
  latest: Record<string, { version: string }> | undefined | null,
): UpgradeStatus {
  const iv = parseVersion(installed)
  if (!iv || !latest) return null

  const channel = iv.major === 6 ? '6' : iv.major === 7 ? '7' : null
  if (!channel) return null

  const candidate = latest[channel]
  if (!candidate) return null

  const cv = parseVersion(candidate.version)
  if (!cv) return null

  const cmp = cmpTuple(iv, cv)
  const target = candidate.version
  const current = cleanVersion(installed)
  if (cmp >= 0) return { status: 'up_to_date', current, target }
  return { status: 'outdated', current, target }
}
