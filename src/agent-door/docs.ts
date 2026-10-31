import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { DocsArticle } from '../site/docs/DocsArticle'
import siteStyles from '../site/shell/site.css?inline'
import docsStyles from '../site/docs/docs.css?inline'

// The installation uses the run site's existing docs renderer and styles.
// This static public document never opens an Auth session or reads a store.
export function agentDocsResponse(request: Request): Response | null {
  if (new URL(request.url).pathname !== '/docs/agents') return null
  const headers = {
    'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin',
    'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'",
  }
  if (!['GET', 'HEAD'].includes(request.method)) return new Response(null, { status: 405, headers: { ...headers, allow: 'GET, HEAD' } })
  const body = renderToStaticMarkup(createElement(DocsArticle, { slug: 'agents' }))
    .replace(/href="(\/docs(?:\/[^"#]*)?)"/g, (attribute, path: string) => path === '/docs/agents' ? attribute : `href="https://run-auth.com${path}"`)
  return new Response(request.method === 'HEAD' ? null : `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>Agent guide · Auth docs</title><link rel="icon" href="/brand/mark.svg"><link rel="stylesheet" href="/fonts/fonts.css"><link rel="stylesheet" href="/rer-theme.css"><style>${siteStyles}\n${docsStyles}</style></head><body>${body}</body></html>`, { headers })
}
