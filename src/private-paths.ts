// Setup serves this Worker directly, without the CLI's public-listener proxy.
// Refuse runtime internals and checkout files before any application dispatch.
const privateSegment = /^(?:cdn-cgi|\.rer|\.seed|\.wrangler|\.git|\.dev\.vars.*|\.env.*|.*\.rer(?:\.(?:[\w-]+\.)?partial)?)$/i

export function isPrivatePath(request: Request): boolean {
  let path = new URL(request.url).pathname
  // Bound decoding work and refuse ambiguous, malformed or deeper encodings.
  for (let round = 0; path.includes('%'); round++) {
    if (round === 8) return true
    try { path = decodeURIComponent(path) } catch { return true }
  }
  const segments = path.replace(/[\\?#]/g, '/').split('/').map(segment => segment.trim())
  if (segments.some(segment => privateSegment.test(segment))) return true
  const served: string[] = []
  for (const segment of segments) {
    if (segment === '..') served.pop()
    else if (segment && segment !== '.') served.push(segment)
  }
  // Match the checkout export directory, including Vite filesystem requests,
  // while allowing application routes such as /api/apps/exports.
  return /^exports$/i.test(served[0] ?? '') ||
    Boolean(served[0]?.startsWith('@') && served.some(segment => /^exports$/i.test(segment)))
}
