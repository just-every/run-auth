import { Icon } from './icons'

/** The primary action and the docs link, used by the hero and the closing band. */
export const RunActions = () => (
  <div className="run-actions">
    <a className="run-button" href="/run">Run Auth<Icon name="arrow" /></a>
    <a className="docs-link" href="/docs">Read the docs</a>
  </div>
)
