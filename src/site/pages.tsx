import type { ReactElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { pages as docsPages } from 'virtual:auth-docs'
import { contractPageHtml } from '../base/contract-page'
import { runPageHtml, siteNotFoundHtml, type SiteBuild, type SiteContext } from '../base/run-site'
import { identity } from '../identity'
import { DocsArticle } from './docs/DocsArticle'
import { DocsIndex } from './docs/DocsIndex'
import { pageTitle } from './landing/copy'
import { Landing } from './landing/Landing'
import { ContractPage } from './shell/contract-page'
import { run } from './run'

/** The run site (run-auth.com), built by `rer build --site`: the approved homepage, the Run page, the contract, the docs and a 404. */
export function sitePages({ styles, contract }: SiteContext): SiteBuild {
  const document = (title: string, description: string, body: ReactElement) => '<!doctype html>' + renderToStaticMarkup(
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="color-scheme" content="light dark" />
        <title>{title}</title>
        <meta name="description" content={description} />
        <link rel="icon" href={identity.mark} type="image/svg+xml" />
        <link rel="stylesheet" href={identity.fonts} />
        <link rel="stylesheet" href={identity.theme} />
        {styles.map(href => <link key={href} rel="stylesheet" href={href} />)}
      </head>
      <body><ContractPage.Provider value={Boolean(contract)}>{body}</ContractPage.Provider></body>
    </html>,
  )
  return {
    pages: [
      { path: '/', html: document(pageTitle, identity.tagline, <Landing />) },
      { path: '/run', html: runPageHtml(identity, run, contract) },
      ...(contract ? [{ path: '/contract', html: contractPageHtml(identity, run, contract) }] : []),
      { path: '/docs', html: document('Docs · Auth', 'Owner guides for Auth: get started, people, apps, move-in, backup and restore.', <DocsIndex />) },
      ...docsPages.map(page => ({ path: `/docs/${page.slug}`, html: document(`${page.title} · Auth docs`, page.summary, <DocsArticle slug={page.slug} />) })),
      { path: '/404', html: siteNotFoundHtml(identity, run, contract) },
    ],
    assets: ['rer-theme.css', 'fonts', 'brand'],
  }
}
