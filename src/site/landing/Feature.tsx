import type { Feature as FeatureCopy } from './copy'
import { drawings } from './drawings'

/** One section: eyebrow, heading and a line or two beside its drawing; the side alternates at 1440. */
export function Feature({ feature }: { feature: FeatureCopy }) {
  const Drawing = drawings[feature.id]
  return (
    <section className={`feature copy-${feature.side}`} id={feature.id} aria-labelledby={`${feature.id}-title`}>
      <div className="feature-copy">
        <p className="eyebrow">{feature.eyebrow}</p>
        <h2 id={`${feature.id}-title`}>{feature.title}</h2>
        <p className="feature-body">{feature.body}</p>
      </div>
      <div className="feature-drawing">{Drawing ? <Drawing /> : null}</div>
    </section>
  )
}
