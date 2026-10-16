import { Marked } from 'marked'

// One Markdown page to static HTML at build time. Raw HTML in the Markdown is
// shown as text. Headings get GitHub-style ids and the page's h2s become its
// contents. A leading level-1 heading is dropped: the title comes from
// docs/site.json. `link` rewrites every link (another rendered page, a file in
// the repository, or an outside address) and reports the ones that go nowhere.

const escapeHtml = value => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
const plain = value => value.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/\s+/g, ' ').trim()

export function slugger() {
  const seen = new Map()
  return text => {
    const base = text.toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, '').trim().replace(/\s/g, '-') || 'section'
    const count = seen.get(base) ?? 0
    seen.set(base, count + 1)
    return count ? `${base}-${count}` : base
  }
}

export function renderMarkdown(markdown, link) {
  const slug = slugger()
  const toc = [], ids = []
  const source = markdown.replace(/^\s*# [^\n]*\n/, '')
  const marked = new Marked({
    gfm: true,
    renderer: {
      heading({ tokens, depth }) {
        const inner = this.parser.parseInline(tokens)
        const id = slug(plain(inner))
        ids.push(id)
        if (depth === 2) toc.push({ id, text: plain(inner) })
        const level = Math.min(Math.max(depth, 2), 4)
        return `<h${level} id="${id}">${inner}</h${level}>\n`
      },
      code({ text, lang }) {
        const shell = /^(sh|bash|shell|console)$/.test((lang ?? '').trim())
        return `<pre class="docs-code${shell ? ' docs-shell' : ''}"><code>${escapeHtml(text.replace(/\n$/, ''))}</code></pre>\n`
      },
      html({ text }) { return escapeHtml(text) },
      link({ href, title, tokens }) {
        const titled = title ? ` title="${escapeHtml(title)}"` : ''
        return `<a href="${escapeHtml(link(href))}"${titled}>${this.parser.parseInline(tokens)}</a>`
      },
      image() { throw new Error('the docs publish text only, without images') },
    },
  })
  const html = marked.parse(source, { async: false })
    .replace(/<table>/g, '<div class="docs-table" role="region" tabindex="0" aria-label="Table"><table>')
    .replace(/<\/table>/g, '</table></div>')
  return { html, toc, ids }
}
