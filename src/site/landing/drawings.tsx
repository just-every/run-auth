import type { JSX } from 'react'
import { run } from '../run'
import { Icon } from './icons'

// The small product drawing beside each section: real labels from Auth's own
// screens (UI-REFERENCE), as HTML text on a white card.

const Passkeys = () => (
  <div className="draw-card">
    <p className="draw-title">Registered passkeys</p>
    <div className="draw-rows">
      <div className="draw-row"><span className="draw-avatar"><Icon name="user" /></span><strong className="draw-text">Passkey 1</strong><span className="draw-meta">Added Oct 2</span><span className="draw-meta">Last used Oct 16</span></div>
      <div className="draw-row"><span className="draw-avatar"><Icon name="user" /></span><strong className="draw-text">Passkey 2</strong><span className="draw-meta">Added Oct 9</span><span className="draw-meta">Not used yet</span></div>
    </div>
    <span className="draw-button">Register a passkey</span>
  </div>
)

const Apps = () => (
  <div className="draw-card">
    <div className="draw-rows">
      <div className="draw-row"><span className="draw-avatar"><Icon name="doc" /></span><span className="draw-text"><strong>wiki.example.com</strong><span className="draw-pill quiet">Approved here</span></span><span className="draw-pill">Active</span></div>
      <div className="draw-row"><span className="draw-avatar"><Icon name="chart" /></span><span className="draw-text"><strong>crm.example.com</strong><span className="draw-pill quiet">Created with a link token</span></span><span className="draw-pill">Active</span></div>
    </div>
  </div>
)

const people = [['PS', 'Priya Shah', 'Owner', 'Active'], ['MR', 'Marcus Reed', 'Administrator', 'Active'], ['SL', 'Sam Lee', 'Member', 'Invited']] as const
const People = () => (
  <div className="draw-card">
    <div className="draw-rows plain">
      {people.map(([initials, name, role, status]) => (
        <div className="draw-row" key={name}><span className="draw-initials">{initials}</span><strong className="draw-text">{name}</strong><span className="draw-pill quiet">{role}</span><span className={`draw-pill${status === 'Invited' ? ' invited' : ''}`}>{status}</span></div>
      ))}
    </div>
    <span className="draw-chip">example.com</span>
  </div>
)

const MoveIn = () => (
  <div className="draw-card">
    <p className="draw-title">Stage an export</p>
    <div className="draw-rows"><div className="draw-row"><span className="draw-avatar"><Icon name="file" /></span><strong className="draw-text">users.csv</strong></div></div>
    <span className="draw-button">Admit selected</span>
  </div>
)

const Licence = () => (
  <div className="draw-card licence"><span className="draw-avatar large"><Icon name="file" /></span><strong>MIT License</strong></div>
)

const commands = [
  `git clone ${run.repository}.git`,
  `cd ${run.folder}`,
  'node scripts/rer.mjs install',
  'node scripts/rer.mjs setup --owner-email you@example.com',
  'node scripts/rer.mjs dev',
]
const Terminal = () => (
  <pre className="draw-terminal" aria-label="Start Auth on your computer"><code>{commands.map(line => <span key={line}><span className="prompt" aria-hidden="true">$ </span>{line}{'\n'}</span>)}</code></pre>
)

export const drawings: Record<string, () => JSX.Element> = { passkeys: Passkeys, apps: Apps, people: People, 'move-in': MoveIn, free: Licence, ownership: Terminal }
