// The docs module scripts/site-docs/plugin.mjs builds from docs/site.json at `rer build --site`.
declare module 'virtual:auth-docs' {
  export interface DocsHeading { id: string; text: string }
  export interface DocsPage { slug: string; title: string; summary: string; html: string; toc: DocsHeading[] }
  export const sections: { title: string; pages: { slug: string; title: string; summary: string }[] }[]
  export const pages: DocsPage[]
}
