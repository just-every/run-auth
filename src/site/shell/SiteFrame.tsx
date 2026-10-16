import type { ReactNode } from 'react'
import { SiteFooter } from './SiteFooter'
import { SiteHeader } from './SiteHeader'
import './site.css'

/** Header, page and footer, shared by the homepage and the docs. */
export const SiteFrame = ({ children, className }: { children: ReactNode; className?: string }) => (
  <div className={`site${className ? ` ${className}` : ''}`}><SiteHeader /><main>{children}</main><SiteFooter /></div>
)
