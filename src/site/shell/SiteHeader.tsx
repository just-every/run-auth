import { run } from '../run'

/** The run site's header: the mark and Auth at left, Docs and Source at right. */
export function SiteHeader() {
  return (
    <header className="site-header">
      <a className="site-brand" href="/"><img src="/brand/mark.svg" alt="" width="32" height="32" /><span>Auth</span></a>
      <nav aria-label="Site"><a href="/docs">Docs</a><a href={run.repository}>Source</a></nav>
    </header>
  )
}
