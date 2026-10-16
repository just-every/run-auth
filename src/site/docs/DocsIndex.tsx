import { sections } from 'virtual:auth-docs'
import { SiteFrame } from '../shell/SiteFrame'
import './docs.css'

/** /docs: every guide by section, each a card with its one-line summary. */
export const DocsIndex = () => (
  <SiteFrame className="docs">
    <div className="docs-intro">
      <p className="eyebrow">Docs</p>
      <h1>Run Auth, sign in with a touch.</h1>
      <p className="feature-body">Owner guides for running Auth on your own computer, inviting your team, linking apps and keeping a backup.</p>
    </div>
    {sections.map(section => (
      <section className="docs-section" key={section.title} aria-labelledby={`docs-${section.title}`}>
        <h2 id={`docs-${section.title}`}>{section.title}</h2>
        <ul className="docs-cards">
          {section.pages.map(page => <li key={page.slug}><a href={`/docs/${page.slug}`}><strong>{page.title}</strong><span>{page.summary}</span></a></li>)}
        </ul>
      </section>
    ))}
  </SiteFrame>
)
