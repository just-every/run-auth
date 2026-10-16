import { footer } from '../landing/copy'
import { run } from '../run'

/** One line: the lockup and the product's line, then Docs, Source and the licence. */
export function SiteFooter() {
  return (
    <footer className="site-footer">
      <p className="site-footer-brand"><img src="/brand/mark.svg" alt="" width="24" height="24" /><strong>Auth</strong><span>{footer.line}</span></p>
      <nav aria-label="Footer"><a href="/docs">Docs</a><a href={run.repository}>Source</a><a href={`${run.repository}/blob/main/LICENSE`}>MIT licensed</a></nav>
    </footer>
  )
}
