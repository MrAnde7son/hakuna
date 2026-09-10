/**
 * Client-side detection of scan targets the VM scanner probably can't reach.
 *
 * The VM scanner dispatches from wherever it is deployed, so a cloud-hosted
 * scanner cannot reach RFC1918 space — a `192.168.1.0/24` expands to 254 jobs
 * that all fail preflight. The backend is authoritative (see
 * services/target_expander.py); this mirror exists only so the scan panel can
 * warn before dispatch, because the panel unmounts on submit and would never
 * show a warning returned on the response.
 *
 * Scope is IPv4 plus the handful of IPv6 literals worth catching. Hostnames
 * are never flagged: classifying them needs DNS, and the lab compose reaches
 * its targets by Docker hostname.
 */

// [network, prefix] pairs that are not routable from the public internet.
const NON_ROUTABLE_V4 = [
  ['10.0.0.0', 8],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['100.64.0.0', 10],  // CGNAT — equally unreachable
  ['0.0.0.0', 8],
]

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

function toInt(ip) {
  const m = ip.match(IPV4_RE)
  if (!m) return null
  const octets = m.slice(1).map(Number)
  if (octets.some(o => o > 255)) return null
  return ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
}

/** Strip a target token down to its host portion (URL, host:port, or bare). */
export function extractHost(token) {
  const t = (token || '').trim()
  if (!t) return ''
  if (t.includes('://')) {
    try {
      return new URL(t).hostname.replace(/^\[|\]$/g, '')
    } catch {
      return ''
    }
  }
  if (t.startsWith('[')) {
    const close = t.indexOf(']')
    if (close !== -1) return t.slice(1, close)
  }
  const hostPort = t.match(/^((?:\d{1,3}\.){3}\d{1,3}):\d+$/)
  if (hostPort) return hostPort[1]
  return t
}

/** True when `token` is a literal IP/CIDR outside globally routable space. */
export function isUnroutableTarget(token) {
  const host = extractHost(token)
  if (!host) return false

  // IPv6 literals we can classify cheaply: loopback and unique-local (fc00::/7).
  if (host.includes(':')) {
    const lower = host.toLowerCase()
    if (lower === '::1') return true
    return /^f[cd][0-9a-f]{2}:/.test(lower)
  }

  const [addr, prefixRaw] = host.split('/')
  const value = toInt(addr)
  if (value === null) return false  // hostname, or malformed — leave it alone

  if (prefixRaw !== undefined) {
    const prefix = Number(prefixRaw)
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false
  }

  return NON_ROUTABLE_V4.some(([net, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
    return (value & mask) >>> 0 === (toInt(net) & mask) >>> 0
  })
}

/** Return the unroutable subset of `targets`, order-preserving and deduped. */
export function findUnroutableTargets(targets) {
  const seen = new Set()
  const flagged = []
  for (const raw of targets || []) {
    const token = (raw || '').trim()
    if (!token || seen.has(token)) continue
    if (isUnroutableTarget(token)) {
      seen.add(token)
      flagged.push(token)
    }
  }
  return flagged
}
