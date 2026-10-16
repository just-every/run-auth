import { readFileSync } from 'node:fs'
import { dirname, join, normalize, relative, resolve } from 'node:path'
import { renderMarkdown } from './render.mjs'

// `virtual:auth-docs`: the on-site docs, rendered from docs/site.json and the
// Markdown it names (guides in docs/, and the repository's own MOVE-IN.md,
// LINKING.md and AUTH-COMMANDS.md) when the run site builds. A link to another
// listed page becomes /docs/<slug>; a link to any other repository file goes to
// it on GitHub; a link to a missing file or heading fails the build.

export const docsModuleId = 'virtual:auth-docs'
const resolvedId = `\0${docsModuleId}`

export function buildDocs(root) {
  const docs = join(root, 'docs')
  const site = JSON.parse(readFileSync(join(docs, 'site.json'), 'utf8'))
  const repository = (JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))).repository
  const listed = site.sections.flatMap(section => section.pages)
  const bySource = new Map(listed.map(page => [normalize(resolve(docs, page.file)), page.slug]))
  const problems = [], anchors = []
  const pages = listed.map(page => {
    const file = resolve(docs, page.file)
    if (relative(root, file).startsWith('..')) throw new Error(`docs/site.json: ${page.file} is outside the repository`)
    const link = href => {
      if (/^(https?:|mailto:)/.test(href)) return href
      const [path, hash] = href.split('#')
      if (!path) { if (hash) anchors.push({ page: page.slug, slug: page.slug, id: hash }); return href }
      if (path.startsWith('/docs')) {
        const slug = path.replace(/^\/docs\/?/, '')
        if (slug && !listed.some(item => item.slug === slug)) problems.push(`${page.file}: link to missing page ${href}`)
        if (slug && hash) anchors.push({ page: page.slug, slug, id: hash })
        return href
      }
      if (path.startsWith('/')) { problems.push(`${page.file}: site path ${href} is not a docs page`); return href }
      const target = normalize(resolve(dirname(file), path))
      const slug = bySource.get(target)
      if (slug) { if (hash) anchors.push({ page: page.slug, slug, id: hash }); return `/docs/${slug}${hash ? `#${hash}` : ''}` }
      try { readFileSync(target) } catch { problems.push(`${page.file}: link to missing file ${href}`) }
      return `${repository}/blob/main/${relative(root, target).split('\\').join('/')}${hash ? `#${hash}` : ''}`
    }
    const rendered = renderMarkdown(readFileSync(file, 'utf8'), link)
    return { slug: page.slug, title: page.title, summary: page.summary, html: rendered.html, toc: rendered.toc, ids: rendered.ids, file }
  })
  for (const anchor of anchors) if (!pages.find(page => page.slug === anchor.slug)?.ids.includes(anchor.id)) problems.push(`/docs/${anchor.page}: link to missing heading /docs/${anchor.slug}#${anchor.id}`)
  if (problems.length) throw new Error(`The docs have broken links:\n${problems.join('\n')}`)
  return {
    sections: site.sections.map(section => ({ title: section.title, pages: section.pages.map(({ slug, title, summary }) => ({ slug, title, summary })) })),
    pages: pages.map(({ slug, title, summary, html, toc }) => ({ slug, title, summary, html, toc })),
    files: [join(docs, 'site.json'), ...pages.map(page => page.file)],
  }
}

export function docsSite() {
  let root = process.cwd()
  return {
    name: 'auth:docs',
    configResolved(config) { root = config.root },
    resolveId(id) { return id === docsModuleId ? resolvedId : undefined },
    load(id) {
      if (id !== resolvedId) return
      const built = buildDocs(root)
      for (const file of built.files) this.addWatchFile(file)
      return `export const sections = ${JSON.stringify(built.sections)};\nexport const pages = ${JSON.stringify(built.pages)};\n`
    },
  }
}
