import { fontHead } from './font-head'

// Native auth documents bypass the route renderer. Append after their own
// styles so the shared body font also applies, preserving the auth module's
// hashed styles, private headers and form/Origin behavior.
export function fontDocumentResponse(response: Response | null): Response | null {
  if (!response?.headers.get('content-type')?.startsWith('text/html')) return response
  const headers = new Headers(response.headers)
  const policy = headers.get('content-security-policy')
  if (policy) {
    const directives = policy.split(';').map(value => value.trim()).filter(Boolean)
    for (const name of ['style-src', 'font-src']) {
      const index = directives.findIndex(value => value.split(/\s+/)[0] === name)
      if (index < 0) directives.push(`${name} 'self'`)
      else if (!directives[index].split(/\s+/).includes("'self'")) directives[index] += " 'self'"
    }
    headers.set('content-security-policy', directives.join('; '))
  }
  return new HTMLRewriter().on('head', {
    element(element) { element.append(fontHead, { html: true }) },
  }).transform(new Response(response.body, { status: response.status, statusText: response.statusText, headers }))
}
