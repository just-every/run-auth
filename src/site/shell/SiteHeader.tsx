import { useContext } from 'react'
import { run } from '../run'
import { ContractPage } from './contract-page'

/** The run site's header: the mark and Auth at left, Docs, Contract (when the build renders /contract) and Source at right. */
export function SiteHeader() {
  const contract = useContext(ContractPage)
  return (
    <header className="site-header">
      <a className="site-brand" href="/"><img src="/brand/mark.svg" alt="" width="32" height="32" /><span>Auth</span></a>
      <nav aria-label="Site"><a href="/docs">Docs</a>{contract ? <a href="/contract">Contract</a> : null}<a href={run.repository}>Source</a></nav>
    </header>
  )
}
