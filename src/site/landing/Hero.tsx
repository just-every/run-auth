import type { ReactNode } from 'react'
import { hero } from './copy'
import { Icon } from './icons'
import { RunActions } from './RunActions'

const Step = ({ n, title, children }: { n: number; title: string; children: ReactNode }) => (
  <li className="hero-card"><p className="hero-card-title"><span className="numeral" aria-hidden="true">{n}</span>{title}</p>{children}</li>
)

/** The fold: the headline and actions at left, the open door, and the 1-2-3 story over it. */
export function Hero() {
  return (
    <section className="hero" id="top">
      <div className="hero-copy">
        <h1>{hero.title[0]}<br />{hero.title[1]}</h1>
        <p className="hero-sub">{hero.sub}</p>
        <p className="alternative">100% free, open source alternative to <strong>{hero.alternativeTo[0]}</strong>, <strong>{hero.alternativeTo[1]}</strong> and <strong>{hero.alternativeTo[2]}</strong></p>
        <RunActions />
      </div>
      <figure className="hero-art" aria-label={hero.figure}>
        <img className="hero-door" src="/brand/door.webp" alt="" width="620" height="910" />
        <ol className="hero-cards">
          <Step n={1} title="Invite">
            <div className="draw-rows"><div className="draw-row"><span className="draw-avatar"><Icon name="user" /></span><span className="draw-text"><strong>Priya Shah</strong><span>priya@example.com</span></span><span className="draw-pill invited">Invited</span></div></div>
          </Step>
          <Step n={2} title="Touch">
            <span className="draw-button">Continue with a passkey</span>
          </Step>
          <Step n={3} title="Signed in">
            <div className="draw-rows">
              <div className="draw-row"><span className="draw-avatar"><Icon name="doc" /></span><span className="draw-text">wiki.example.com</span><span className="draw-pill">Active</span></div>
              <div className="draw-row"><span className="draw-avatar"><Icon name="chart" /></span><span className="draw-text">crm.example.com</span><span className="draw-pill">Active</span></div>
            </div>
          </Step>
        </ol>
      </figure>
    </section>
  )
}
