import { pages, sections } from 'virtual:auth-docs'
import { SiteFrame } from '../shell/SiteFrame'
import './docs.css'

/** /docs/<slug>: the guide, with every guide listed beside it and the page's sections above it on a phone. */
export function DocsArticle({ slug }: { slug: string }) {
  const index = pages.findIndex(page => page.slug === slug)
  const page = pages[index]
  if (!page) throw new Error(`No docs page ${slug}`)
  const next = pages[index + 1]
  let example = 0
  const html = page.html.replace(/<pre\b([^>]*)>/g, (_match, attributes: string) => `<pre${attributes} tabindex="0" role="region" aria-label="Code example ${++example}">`)
  return (
    <SiteFrame className="docs">
      <div className="docs-layout">
        <nav className="docs-nav" aria-label="Docs">
          <a className="docs-home" href="/docs">All docs</a>
          {sections.map(section => (
            <div key={section.title}><p>{section.title}</p><ul>{section.pages.map(item => <li key={item.slug}><a href={`/docs/${item.slug}`} aria-current={item.slug === slug ? 'page' : undefined}>{item.title}</a></li>)}</ul></div>
          ))}
        </nav>
        <article className="docs-article">
          <h1>{page.title}</h1>
          <p className="docs-summary">{page.summary}</p>
          {page.toc.length > 2 ? <nav className="docs-toc" aria-label="On this page"><p>On this page</p><ul>{page.toc.map(item => <li key={item.id}><a href={`#${item.id}`}>{item.text}</a></li>)}</ul></nav> : null}
          <div className="docs-prose" dangerouslySetInnerHTML={{ __html: html }} />
          {next ? <a className="docs-next" href={`/docs/${next.slug}`}><span>Next</span><strong>{next.title}</strong></a> : null}
        </article>
      </div>
      <script src="/auth-assets/docs-code.js" defer />
    </SiteFrame>
  )
}
